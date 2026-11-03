package webmail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// allowLocal lets a test client reach httptest servers on random local ports,
// which the production checks rightly refuse.
func allowLocal(t *testing.T) {
	t.Helper()
	old := imagePortAllowed
	imagePortAllowed = func(string) bool { return true }
	t.Cleanup(func() { imagePortAllowed = old })
}

func anyAddress(_, _ string, _ syscall.RawConn) error { return nil }

func testProxy(t *testing.T, max int64, control func(string, string, syscall.RawConn) error) *imageProxy {
	t.Helper()
	p, err := newImageProxy(t.TempDir(), 1<<20, max, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if control != nil {
		p.client = newImageClient(control)
	}
	return p
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.216.34":        true,
		"2606:4700::1111":      true,
		"127.0.0.1":            false,
		"10.1.2.3":             false,
		"172.17.0.2":           false, // a Docker network
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"100.64.0.1":           false, // shared address space
		"0.0.0.0":              false,
		"0.1.2.3":              false,
		"224.0.0.1":            false,
		"255.255.255.255":      false,
		"198.18.0.1":           false,
		"::1":                  false,
		"::":                   false,
		"fe80::1":              false,
		"fc00::1":              false,
		"fd12:3456::1":         false,
		"::ffff:10.0.0.1":      false, // IPv4-mapped private
		"::ffff:127.0.0.1":     false,
		"64:ff9b::a00:1":       false, // NAT64 of 10.0.0.1
		"2002:a00:1::1":        false, // 6to4 of 10.0.0.1
		"2001:0:a00:1::1":      false, // Teredo
		"fec0::1":              false,
		"2001:db8::1":          false,
		"::ffff:93.184.216.34": true,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestCheckImageURL(t *testing.T) {
	for _, raw := range []string{
		"ftp://example.com/a.png",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"data:image/png;base64,AAAA",
		"//example.com/a.png",
		"/relative.png",
		"https://user:pass@example.com/a.png",
		"https://example.com:8080/a.png",
		"https://example.com:25/a.png",
		"http://example.com:6379/",
		"https:///nohost",
		"https://example.com/" + strings.Repeat("a", imageMaxURL),
	} {
		if _, err := checkImageURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://example.com/a.png", "http://example.com:80/a.png?x=1", "https://media.example.com:443/x"} {
		if _, err := checkImageURL(raw); err != nil {
			t.Errorf("refused %q: %v", raw, err)
		}
	}
}

// The real dialler refuses loopback, so a message can't make the server
// fetch from itself or its neighbours, and nothing reaches the target.
func TestProxyRefusesInternalDestinations(t *testing.T) {
	allowLocal(t)
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("secret"))
	}))
	defer internal.Close()
	p := testProxy(t, 1<<20, nil) // production dial control
	port := internal.URL[strings.LastIndex(internal.URL, ":")+1:]
	for _, raw := range []string{
		internal.URL + "/x.png",
		"http://localhost:" + port + "/x.png",
		"http://[::1]:" + port + "/x.png",
		"http://127.1:" + port + "/x.png",
		"http://2130706433:" + port + "/x.png", // 127.0.0.1 as a decimal
	} {
		if _, _, err := p.image(context.Background(), "dana", raw); err == nil {
			t.Errorf("fetched %s", raw)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the internal server was reached %d times", hits.Load())
	}
}

// A public-looking server that redirects inward is stopped at the redirect.
func TestProxyRefusesRedirectInward(t *testing.T) {
	allowLocal(t)
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = w.Write(pngBytes(t))
	}))
	defer internal.Close()
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/x.png", http.StatusFound)
	}))
	defer public.Close()
	publicAddr := strings.TrimPrefix(public.URL, "http://")
	// Only the "public" server's address may be dialled, as if it alone were
	// on the internet.
	p := testProxy(t, 1<<20, func(_, address string, _ syscall.RawConn) error {
		if address != publicAddr {
			return errImageRefused
		}
		return nil
	})
	if _, _, err := p.image(context.Background(), "dana", public.URL+"/x.png"); err == nil {
		t.Fatal("followed a redirect to an internal address")
	}
	if internalHits.Load() != 0 {
		t.Fatal("the internal server was reached")
	}

	// Redirect chains are bounded, and a redirect to another scheme is refused.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer loop.Close()
	p = testProxy(t, 1<<20, anyAddress)
	if _, _, err := p.image(context.Background(), "dana", loop.URL+"/a"); err == nil {
		t.Fatal("followed an endless redirect")
	}
	toFile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer toFile.Close()
	if _, _, err := p.image(context.Background(), "dana", toFile.URL+"/a"); err == nil {
		t.Fatal("followed a redirect to file:")
	}
}

func TestProxyPassesOnlyImages(t *testing.T) {
	allowLocal(t)
	pngData := pngBytes(t)
	big := append(append([]byte{}, pngData...), make([]byte, 4096)...)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ok.png":
			w.Header().Set("Content-Type", "text/html") // the label is ignored
			_, _ = w.Write(pngData)
		case "/page.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("<html><script>alert(1)</script></html>"))
		case "/logo.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
		case "/big.png":
			_, _ = w.Write(big)
		case "/chunked.png":
			// No Content-Length: the limit has to hold while reading.
			w.Header().Set("Transfer-Encoding", "chunked")
			for range 4 {
				_, _ = w.Write(big)
				w.(http.Flusher).Flush()
			}
		case "/missing.png":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := testProxy(t, 2048, anyAddress)
	ct, body, err := p.image(context.Background(), "dana", srv.URL+"/ok.png")
	if err != nil || ct != "image/png" || !bytes.Equal(body, pngData) {
		t.Fatalf("png: %q %v", ct, err)
	}
	for path, want := range map[string]error{
		"/page.png":    errImageNotImage,
		"/logo.svg":    errImageNotImage,
		"/big.png":     errImageTooLarge,
		"/chunked.png": errImageTooLarge,
	} {
		if _, _, err := p.image(context.Background(), "dana", srv.URL+path); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", path, err, want)
		}
	}
	if _, _, err := p.image(context.Background(), "dana", srv.URL+"/missing.png"); err == nil {
		t.Error("404 passed on")
	}

	// Hits and failures are both cached: none of these reach the sender again.
	before := hits.Load()
	for _, path := range []string{"/ok.png", "/page.png", "/missing.png"} {
		_, _, _ = p.image(context.Background(), "dana", srv.URL+path)
	}
	if hits.Load() != before {
		t.Errorf("cached images fetched again: %d new requests", hits.Load()-before)
	}
}

// Nothing about the reader goes to the sender.
func TestProxySendsNothingAboutTheReader(t *testing.T) {
	allowLocal(t)
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write(pngBytes(t))
	}))
	defer srv.Close()
	p := testProxy(t, 1<<20, anyAddress)
	if _, _, err := p.image(context.Background(), "dana", srv.URL+"/p.png"); err != nil {
		t.Fatal(err)
	}
	if got.Get("Cookie") != "" || got.Get("Referer") != "" || got.Get("User-Agent") != imageUserAgent || got.Get("X-Forwarded-For") != "" {
		t.Fatalf("request headers: %v", got)
	}
}

func TestProxyLimits(t *testing.T) {
	p := testProxy(t, 1<<20, nil)
	var releases []func()
	for range imagePerUserInFlight {
		release, err := p.admit("dana")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := p.admit("dana"); !errors.Is(err, errImageBusy) {
		t.Fatalf("over the in-flight limit: %v", err)
	}
	if release, err := p.admit("erin"); err != nil {
		t.Fatalf("another user was limited: %v", err)
	} else {
		release()
	}
	for _, r := range releases {
		r()
	}
	// The burst runs out.
	n := 0
	for range imagePerUserBurst + 50 {
		release, err := p.admit("fay")
		if err != nil {
			break
		}
		release()
		n++
	}
	if n > imagePerUserBurst+5 {
		t.Fatalf("admitted %d fetches in a burst", n)
	}
}

func TestSanitizeRewritesRemoteImagesToProxy(t *testing.T) {
	signer := imageSigner{key: []byte("k")}
	in := `<style>.hero{background:url('https://cdn.example.com/Hero.PNG?t=AbC')}</style>` +
		`<img src="https://cdn.example.com/Logo.png?Sig=XyZ"><img src="http://cdn.example.com/a.gif">`
	res := sanitizeHTML(in, sanitizeOptions{AllowRemote: true, ImageURL: signer.url})
	if strings.Contains(res.HTML, `src="http`) || strings.Contains(res.CSS, "url('http") {
		t.Fatalf("a remote address survived:\n%s\n%s", res.HTML, res.CSS)
	}
	want := signer.url("https://cdn.example.com/Logo.png?Sig=XyZ")
	if !strings.Contains(res.HTML, strings.ReplaceAll(want, "&", "&amp;")) {
		t.Fatalf("image not rewritten to %s:\n%s", want, res.HTML)
	}
	if !strings.Contains(res.CSS, signer.url("https://cdn.example.com/Hero.PNG?t=AbC")) {
		t.Fatalf("CSS url not rewritten, or its case changed:\n%s", res.CSS)
	}
	// Without remote content allowed, nothing goes to the proxy either.
	res = sanitizeHTML(in, sanitizeOptions{ImageURL: signer.url})
	if strings.Contains(res.HTML, "/mail/image") || strings.Contains(res.CSS, "/mail/image") || res.BlockedImages != 3 {
		t.Fatalf("blocked images were proxied: %d\n%s", res.BlockedImages, res.HTML)
	}
}

func TestImageEndpoint(t *testing.T) {
	allowLocal(t)
	pngData := pngBytes(t)
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(pngData)
	}))
	defer origin.Close()

	h := newHarness(t)
	h.login()
	sess := h.onlySession()
	h.server.images.client = newImageClient(anyAddress)
	raw := origin.URL + "/logo.png"
	signed := newImageSigner(sess).url(raw)

	// Signed: served, with headers that keep it inert.
	resp, err := h.client.Get(h.srv.URL + signed)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, pngData) {
		t.Fatalf("signed image: %d", resp.StatusCode)
	}
	for k, v := range map[string]string{"Content-Type": "image/png", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox"} {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, resp.Header.Get(k), v)
		}
	}

	// Forged, altered, missing or another session's signature: refused
	// without fetching.
	before := hits.Load()
	other := imageSigner{key: []byte("another session")}
	for _, path := range []string{
		"/mail/image?" + url.Values{"u": {raw}, "s": {"forged"}}.Encode(),
		"/mail/image?" + url.Values{"u": {raw + "?x"}, "s": {newImageSigner(sess).sign(raw)}}.Encode(),
		"/mail/image?" + url.Values{"u": {origin.URL + "/other.png"}}.Encode(),
		other.url(origin.URL + "/other.png"),
	} {
		resp, err := h.client.Get(h.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", path, resp.StatusCode)
		}
	}
	if hits.Load() != before {
		t.Fatal("an unsigned request reached the origin")
	}

	// Signed-out: refused.
	resp, err = http.Get(h.srv.URL + signed)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed out: %d", resp.StatusCode)
	}
}

func TestBodyFrameUsesProxy(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.store.raw[7] = []byte("From: a@example.org\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n<p>hi</p><img src=\"https://cdn.example.com/a.png\">\r\n")
	resp, err := h.client.Get(h.srv.URL + "/mail/body?f=INBOX&uid=7&remote=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src data: 'self';") {
		t.Fatalf("frame policy allows remote images: %s", csp)
	}
	if strings.Contains(string(body), `src="https://cdn.example.com`) || !strings.Contains(string(body), "/mail/image?") {
		t.Fatalf("image not proxied:\n%s", body)
	}
	fmt.Fprint(io.Discard, body)
}

// onlySession returns the harness's one signed-in session.
func (h *harness) onlySession() *Session {
	h.t.Helper()
	h.server.sessions.mu.Lock()
	defer h.server.sessions.mu.Unlock()
	if len(h.server.sessions.sessions) != 1 {
		h.t.Fatalf("%d sessions", len(h.server.sessions.sessions))
	}
	for _, s := range h.server.sessions.sessions {
		return s
	}
	return nil
}
