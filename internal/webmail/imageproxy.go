package webmail

// The image proxy.
//
// Remote images in mail are fetched by this server and served from the
// webmail's own origin, the way large webmail services do it. The sender
// sees the server's address instead of the reader's IP and browser, browser
// tracker blockers have nothing to block, and the message frame's policy
// can allow images from 'self' alone.
//
// A proxy that fetches URLs is easy to abuse, so every request has to pass
// all of these:
//
//   - Signed URLs. The sanitiser rewrites each image address in a message
//     the user opened to /mail/image?u=<address>&s=<signature>, with an HMAC
//     keyed from that session's own secret. The proxy fetches nothing else:
//     not an address typed by hand, not one from another session, and not
//     one a third-party page embeds.
//   - Signed-in users only, and per-user rate and concurrency limits, with a
//     global cap on fetches in flight.
//   - Public destinations only. The dialler checks the address it actually
//     connects to, after DNS and after every redirect, so a hostname that
//     resolves to (or rebinds to) a private, loopback, link-local, metadata
//     or otherwise reserved address is refused. Only ports 80 and 443, no
//     credentials in URLs, no environment proxy, at most three redirects.
//   - Images only. The body is identified from its first bytes, not the
//     sender's Content-Type, and only raster formats are passed on. SVG is
//     refused because it can carry script. What goes back carries nosniff
//     and a sandboxing Content-Security-Policy, so even a mislabelled file
//     opened on its own can't run anything.
//   - Bounded. A size cap, read through a limit so a lying Content-Length or
//     a compressed bomb can't exceed it, and timeouts at each step.
//
// Nothing about the reader is forwarded: no cookies, no Referer, no browser
// User-Agent. Fetched images are cached on disk, shared across users (an
// image address only reaches a user inside their own mail), so a newsletter
// logo is fetched once. Failures are cached briefly so a dead host isn't
// hammered.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

const (
	imageMaxURL       = 4096
	imageMaxRedirects = 3
	imageFetchTimeout = 15 * time.Second
	imageCacheTTL     = 7 * 24 * time.Hour
	imageFailureTTL   = 10 * time.Minute
	// A newsletter opens a few dozen images at once; these let it load
	// promptly while stopping one user from turning the server into a
	// download engine.
	imagePerUserRate     = 10  // uncached fetches per second, sustained
	imagePerUserBurst    = 150 // ...and in a burst
	imagePerUserInFlight = 12
	imageGlobalInFlight  = 64
	imageQueueWait       = 5 * time.Second
	imageUserAgent       = "Mozilla/5.0 (compatible; ElemtaImageProxy/1.0)"
	imageSignContext     = "elemta image proxy v1"
)

var (
	errImageRefused  = errors.New("webmail: image address refused")
	errImageTooLarge = errors.New("webmail: image too large")
	errImageNotImage = errors.New("webmail: not an image")
)

// imageSigner signs and checks proxy URLs for one session.
type imageSigner struct{ key []byte }

// newImageSigner derives the session's signing key from its CSRF secret,
// which is random per session and shared by every webmail replica through
// the session store. The derivation keeps the CSRF token itself out of the
// signature.
func newImageSigner(sess *Session) imageSigner {
	m := hmac.New(sha256.New, []byte(sess.CSRF))
	m.Write([]byte(imageSignContext))
	return imageSigner{key: m.Sum(nil)}
}

func (s imageSigner) sign(raw string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s imageSigner) valid(raw, sig string) bool {
	want := s.sign(raw)
	return hmac.Equal([]byte(want), []byte(sig))
}

// url returns the proxy address for a remote image.
func (s imageSigner) url(raw string) string {
	return "/mail/image?" + url.Values{"u": {raw}, "s": {s.sign(raw)}}.Encode()
}

// imageProxy fetches, checks and caches remote images.
type imageProxy struct {
	client   *http.Client
	cache    *imageCache
	maxBytes int64
	log      *slog.Logger
	group    singleflight.Group
	global   chan struct{}

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	inFlight map[string]int
}

func newImageProxy(cacheDir string, cacheBytes, maxBytes int64, log *slog.Logger) (*imageProxy, error) {
	cache, err := newImageCache(cacheDir, cacheBytes, log)
	if err != nil {
		return nil, err
	}
	p := &imageProxy{
		cache: cache, maxBytes: maxBytes, log: log,
		global:   make(chan struct{}, imageGlobalInFlight),
		limiters: map[string]*rate.Limiter{}, inFlight: map[string]int{},
	}
	p.client = newImageClient(publicDialControl)
	return p, nil
}

// newImageClient builds the fetching client. control vets every address
// the client connects to; tests substitute one that admits a local server.
func newImageClient(control func(network, address string, c syscall.RawConn) error) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: control}
	transport := &http.Transport{
		Proxy:                  nil, // never an environment proxy: it would dial for us, unchecked
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    8,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   imageFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= imageMaxRedirects {
				return errImageRefused
			}
			if _, err := checkImageURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}

// checkImageURL accepts an absolute http(s) URL on a standard port with no
// credentials. The destination address is checked again when dialling.
func checkImageURL(raw string) (*url.URL, error) {
	if len(raw) > imageMaxURL {
		return nil, errImageRefused
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, errImageRefused
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, errImageRefused
	}
	if !imagePortAllowed(u.Port()) {
		return nil, errImageRefused
	}
	return u, nil
}

// imagePortAllowed admits the standard web ports only, so the proxy can't
// be pointed at mail, database or admin ports on public hosts. A variable so
// tests can reach servers on random local ports.
var imagePortAllowed = func(port string) bool {
	return port == "" || port == "80" || port == "443"
}

// publicDialControl refuses a connection to anything but a public unicast
// address. It runs on the resolved address of each connection, so neither a
// hostname pointing inward nor DNS rebinding gets past it.
func publicDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errImageRefused
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !publicAddr(ip) {
		return errImageRefused
	}
	return nil
}

// reservedPrefixes are ranges that aren't covered by netip's predicates but
// must not be reached: shared address space, documentation and benchmark
// ranges, and IPv6 translation and tunnelling prefixes that can wrap a
// private IPv4 address.
var reservedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:2::/48",
		"2001:db8::/32", "2002::/16", "fec0::/10",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// errImageBusy reports a limit reached; the browser may try again later.
var errImageBusy = errors.New("webmail: image proxy busy")

// admit applies the user's rate and concurrency limits to an uncached
// fetch. The returned function releases the user's slot.
func (p *imageProxy) admit(user string) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.limiters) > 10000 {
		// A cheap bound on memory; limits restart for everyone, briefly.
		p.limiters = map[string]*rate.Limiter{}
	}
	l, ok := p.limiters[user]
	if !ok {
		l = rate.NewLimiter(imagePerUserRate, imagePerUserBurst)
		p.limiters[user] = l
	}
	if p.inFlight[user] >= imagePerUserInFlight || !l.Allow() {
		return nil, errImageBusy
	}
	p.inFlight[user]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.inFlight[user]--; p.inFlight[user] <= 0 {
			delete(p.inFlight, user)
		}
	}, nil
}

// image returns a remote image's type and bytes, from the cache or fetched.
func (p *imageProxy) image(ctx context.Context, user, raw string) (string, []byte, error) {
	if e, ok := p.cache.get(raw); ok {
		if e.failed {
			return "", nil, errImageRefused
		}
		return e.contentType, e.body, nil
	}
	if _, err := checkImageURL(raw); err != nil {
		return "", nil, err
	}
	release, err := p.admit(user)
	if err != nil {
		return "", nil, err
	}
	defer release()
	// Readers of the same newsletter opening it at once share one fetch.
	v, err, _ := p.group.Do(raw, func() (any, error) {
		select {
		case p.global <- struct{}{}:
			defer func() { <-p.global }()
		case <-time.After(imageQueueWait):
			return nil, errImageBusy
		}
		// Detached from the one request, as the fetch serves everyone
		// waiting on it; the client's timeout bounds it.
		ct, body, err := p.fetch(context.WithoutCancel(ctx), raw)
		if errors.Is(err, errImageBusy) {
			return nil, err
		}
		if err != nil {
			p.cache.putFailure(raw)
			return nil, err
		}
		p.cache.put(raw, ct, body)
		return imageEntry{contentType: ct, body: body}, nil
	})
	if err != nil {
		return "", nil, err
	}
	e := v.(imageEntry)
	return e.contentType, e.body, nil
}

func (p *imageProxy) fetch(ctx context.Context, raw string) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", nil, errImageRefused
	}
	req.Header.Set("User-Agent", imageUserAgent)
	req.Header.Set("Accept", "image/avif,image/webp,image/png,image/jpeg,image/gif,image/*;q=0.8")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("webmail: image fetch: status %d", resp.StatusCode)
	}
	if resp.ContentLength > p.maxBytes {
		return "", nil, errImageTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxBytes+1))
	if err != nil {
		return "", nil, err
	}
	if int64(len(body)) > p.maxBytes {
		return "", nil, errImageTooLarge
	}
	ct := sniffImage(body)
	if ct == "" {
		return "", nil, errImageNotImage
	}
	return ct, body, nil
}

// sniffImage names a raster image format from its first bytes, or returns
// "" for anything else, SVG and HTML included.
func sniffImage(b []byte) string {
	if len(b) >= 12 && string(b[4:8]) == "ftyp" {
		switch string(b[8:12]) {
		case "avif", "avis":
			return "image/avif"
		}
	}
	switch ct := http.DetectContentType(b); ct {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/x-icon":
		return ct
	}
	return ""
}

// serveImage is GET /mail/image.
func (s *Server) serveImage(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.images == nil {
		http.NotFound(w, r)
		return
	}
	raw, sig := r.URL.Query().Get("u"), r.URL.Query().Get("s")
	if raw == "" || !newImageSigner(sess).valid(raw, sig) {
		http.Error(w, "Not a signed image address.", http.StatusForbidden)
		return
	}
	ct, body, err := s.images.image(r.Context(), sess.User, raw)
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	switch {
	case errors.Is(err, errImageBusy):
		h.Set("Retry-After", "5")
		http.Error(w, "Too many images at once. Try again shortly.", http.StatusTooManyRequests)
		return
	case err != nil:
		// The address isn't logged: image URLs often carry a per-recipient
		// tracking token.
		host := ""
		if u, perr := url.Parse(raw); perr == nil {
			host = u.Hostname()
		}
		s.log.Debug("webmail: image not proxied", "host", host, "error", err)
		h.Set("Cache-Control", "private, max-age=600")
		http.Error(w, "The image couldn't be loaded.", http.StatusBadGateway)
		return
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Content-Disposition", "inline")
	h.Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(body)
}

// ---- cache ------------------------------------------------------------------

type imageEntry struct {
	contentType string
	body        []byte
	failed      bool
}

// imageCache keeps fetched images on disk, one file per URL, named by the
// URL's hash. A file holds a short header (content type and fetch time) and
// the image. When the cache grows past its size, the files least recently
// used go first; a hit touches the file's modification time.
type imageCache struct {
	dir     string
	max     int64
	size    atomic.Int64
	pruning atomic.Bool
	log     *slog.Logger
}

func newImageCache(dir string, max int64, log *slog.Logger) (*imageCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("webmail: image cache: %w", err)
	}
	c := &imageCache{dir: dir, max: max, log: log}
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	c.size.Store(total)
	return c, nil
}

func (c *imageCache) path(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(c.dir, name[:2], name)
}

func (c *imageCache) get(raw string) (imageEntry, bool) {
	p := c.path(raw)
	// #nosec G304 -- the path is a hash under the cache directory
	b, err := os.ReadFile(p)
	if err != nil {
		return imageEntry{}, false
	}
	head, body, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return imageEntry{}, false
	}
	ct, ts, _ := strings.Cut(string(head), "\n")
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return imageEntry{}, false
	}
	age := time.Since(time.Unix(unix, 0))
	if ct == "failed" {
		return imageEntry{failed: true}, age < imageFailureTTL
	}
	if age > imageCacheTTL || sniffImage(body) != ct {
		return imageEntry{}, false
	}
	now := time.Now()
	_ = os.Chtimes(p, now, now)
	return imageEntry{contentType: ct, body: body}, true
}

func (c *imageCache) put(raw, ct string, body []byte) {
	c.write(raw, ct, body)
}

func (c *imageCache) putFailure(raw string) {
	c.write(raw, "failed", nil)
}

func (c *imageCache) write(raw, ct string, body []byte) {
	p := c.path(raw)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return
	}
	data := append([]byte(ct+"\n"+strconv.FormatInt(time.Now().Unix(), 10)+"\n\n"), body...)
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	var old int64
	if info, err := os.Stat(p); err == nil {
		old = info.Size()
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	if c.size.Add(int64(len(data))-old) > c.max && c.pruning.CompareAndSwap(false, true) {
		go c.prune()
	}
}

// prune deletes the least recently used files until the cache is at 90% of
// its size.
func (c *imageCache) prune() {
	defer c.pruning.Store(false)
	type file struct {
		path string
		size int64
		mod  time.Time
	}
	var files []file
	var total int64
	_ = filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		files = append(files, file{p, info.Size(), info.ModTime()})
		total += info.Size()
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	target := c.max * 9 / 10
	for _, f := range files {
		if total <= target {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
	c.size.Store(total)
}
