package webmail

// PGP, from the server's side. Encryption and the unlocked key stay in the
// browser (static/pgp-worker.js). This carries keys between the browser and the
// mailbox service, finds other people's public keys, and publishes this domain's
// in the Web Key Directory.
//
// The server still delivers the page's code, so a compromised server could serve
// bad code. That is the known limit of encryption in any webmail. What this does
// protect is stored mail: reading it needs a key the server doesn't have.

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the Web Key Directory hash, not used for security
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const maxPGPLookup = 64 << 10

type pgpKeyInfo struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key,omitempty"`
	Created     string `json:"created,omitempty"`
	// Published is whether the key is in the public directory.
	Published bool `json:"published,omitempty"`
	// Status compares this key with the one the user last accepted: new, pinned
	// or changed.
	Status string `json:"status,omitempty"`
}

func (s *Server) pgpCall(w http.ResponseWriter, r *http.Request, sess *Session, method, path string, in, out any) bool {
	if s.security == nil || sess.AdminActor != "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "PGP isn't available here."})
		return false
	}
	pw, err := s.sessions.password(sess)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		err = s.security.call(ctx, method, path, sess.User, pw, in, out)
	}
	switch {
	case errors.Is(err, errSecurityAuth):
		s.limiter.fail(loginKey(sess.User, s.clientIP(r)))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That password isn't right."})
		return false
	case err != nil:
		s.log.Warn("webmail: pgp", "user", sess.User, "path", path, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "That didn't work. If you imported a key, check that it's for this address."})
		return false
	}
	return true
}

func (s *Server) pgpKeyGet(w http.ResponseWriter, r *http.Request, sess *Session) {
	var out *pgpKeyInfo
	if s.pgpCall(w, r, sess, http.MethodGet, "/v1/security/pgp", nil, &out) {
		if out == nil {
			out = &pgpKeyInfo{}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) pgpKeyPut(w http.ResponseWriter, r *http.Request, sess *Session) {
	in := map[string]string{"password": r.PostFormValue("password"), "public_key": r.PostFormValue("public_key"), "private_key": r.PostFormValue("private_key")}
	if s.pgpCall(w, r, sess, http.MethodPut, "/v1/security/pgp", in, nil) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Server) pgpKeyDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.pgpCall(w, r, sess, http.MethodPost, "/v1/security/pgp/delete", map[string]string{"password": r.PostFormValue("password")}, nil) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// pgpPublishSubmit is the switch in Settings. It's a plain form, because a
// published key is public anyway and nothing here needs the browser's crypto.
func (s *Server) pgpPublishSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	on := r.PostFormValue("published") == "1"
	if !s.securityAction(w, r, sess, "/v1/security/pgp/publish", map[string]bool{"published": on}, nil) {
		return
	}
	n := "pgp-unpublished"
	if on {
		n = "pgp-published"
	}
	http.Redirect(w, r, "/settings/security?n="+n+"#pgp", http.StatusSeeOther)
}

func (s *Server) pgpPin(w http.ResponseWriter, r *http.Request, sess *Session) {
	in := map[string]string{"address": r.PostFormValue("address"), "fingerprint": r.PostFormValue("fingerprint")}
	if s.pgpCall(w, r, sess, http.MethodPut, "/v1/security/pgp/pins", in, nil) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// pgpLookup finds keys for addresses: this server's first, then each address's
// own Web Key Directory, and says how each compares with what the user accepted.
func (s *Server) pgpLookup(w http.ResponseWriter, r *http.Request, sess *Session) {
	var addresses []string
	for _, a := range strings.FieldsFunc(r.PostFormValue("addresses"), func(c rune) bool { return c == '\n' || c == ',' }) {
		if a = strings.ToLower(strings.TrimSpace(a)); strings.Contains(a, "@") {
			addresses = append(addresses, a)
		}
	}
	if len(addresses) == 0 || len(addresses) > 100 {
		writeJSON(w, http.StatusOK, []pgpKeyInfo{})
		return
	}
	var found []pgpKeyInfo
	if !s.pgpCall(w, r, sess, http.MethodPost, "/v1/security/pgp/lookup", map[string]any{"addresses": addresses}, &found) {
		return
	}
	var pins []struct{ Address, Fingerprint string }
	if !s.pgpCall(w, r, sess, http.MethodGet, "/v1/security/pgp/pins", nil, &pins) {
		return
	}
	have := map[string]bool{}
	for _, k := range found {
		have[k.Address] = true
	}
	for _, a := range addresses {
		if have[a] {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		key, err := fetchWKD(ctx, a)
		cancel()
		if err == nil {
			found = append(found, key)
		}
	}
	pinned := map[string]string{}
	for _, p := range pins {
		pinned[strings.ToLower(p.Address)] = strings.ToUpper(p.Fingerprint)
	}
	for i := range found {
		switch fp, ok := pinned[found[i].Address]; {
		case !ok:
			found[i].Status = "new"
		case fp == found[i].Fingerprint:
			found[i].Status = "pinned"
		default:
			found[i].Status = "changed"
		}
	}
	if found == nil {
		found = []pgpKeyInfo{}
	}
	writeJSON(w, http.StatusOK, found)
}

// zbase32 is the Web Key Directory's encoding.
func zbase32(data []byte) string {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var out strings.Builder
	var buffer uint64
	bits := 0
	for _, b := range data {
		buffer = buffer<<8 | uint64(b)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alphabet[(buffer>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buffer<<(5-bits))&31])
	}
	return out.String()
}

// wkdClient fetches from addresses anyone can name, so it refuses private ones:
// otherwise a crafted recipient would have this server probe its own network.
var wkdClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("webmail: refusing a private address")
		}
		return nil
	}}).DialContext},
}

var wkdDomain = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)

// fetchWKD looks an address up in its domain's Web Key Directory, advanced
// method first. The key has to name the address it was asked for.
func fetchWKD(ctx context.Context, address string) (pgpKeyInfo, error) {
	local, domain, ok := strings.Cut(address, "@")
	if !ok || !wkdDomain.MatchString(domain) {
		return pgpKeyInfo{}, errors.New("webmail: not a domain")
	}
	sum := sha1.Sum([]byte(local)) // #nosec G401 -- the format requires it
	hash := zbase32(sum[:])
	query := "?l=" + url.QueryEscape(local)
	for _, u := range []string{
		"https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + "/hu/" + hash + query,
		"https://" + domain + "/.well-known/openpgpkey/hu/" + hash + query,
	} {
		// #nosec G704 -- wkdClient's dialer refuses private addresses at connection time, redirects included
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := wkdClient.Do(req) // #nosec G704 -- wkdClient refuses private addresses
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxPGPLookup))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if key, err := parseWKDKey(address, data); err == nil {
			return key, nil
		}
	}
	return pgpKeyInfo{}, errors.New("webmail: no key found")
}

func parseWKDKey(address string, data []byte) (pgpKeyInfo, error) {
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return pgpKeyInfo{}, err
	}
	for _, entity := range entities {
		for _, id := range entity.Identities {
			if !strings.EqualFold(id.UserId.Email, address) {
				continue
			}
			var armored bytes.Buffer
			if err := armorPublic(&armored, entity); err != nil {
				return pgpKeyInfo{}, err
			}
			return pgpKeyInfo{Address: address, Fingerprint: strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)), PublicKey: armored.String()}, nil
		}
	}
	return pgpKeyInfo{}, errors.New("webmail: the key doesn't name this address")
}

// wkdServe answers the Web Key Directory for this server's domains. The direct
// method has the domain in the host name, the advanced one in the path. It's
// public, like any published key, and the hash means guessing a name is the only
// way to find one.
func (s *Server) wkdServe(w http.ResponseWriter, r *http.Request) {
	// hu/<hash> or policy, with the domain in front of either on the advanced
	// method. The two can't be told apart by route patterns.
	parts := strings.Split(r.PathValue("path"), "/")
	domain := hostOnly(r.Host)
	if n := len(parts); n >= 2 && parts[n-2] != "hu" || n == 3 {
		domain, parts = parts[0], parts[1:]
	}
	if len(parts) == 1 && parts[0] == "policy" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		return
	}
	if s.security == nil || len(parts) != 2 || parts[0] != "hu" {
		http.NotFound(w, r)
		return
	}
	domain = strings.TrimPrefix(strings.ToLower(domain), "openpgpkey.")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	key, err := s.security.text(ctx, "/v1/pgp/wkd/"+url.PathEscape(domain)+"/"+url.PathEscape(parts[1]))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	binary, err := dearmorKey(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(binary)
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// composeEncrypted checks what compose was handed as a finished PGP message. It
// has to be one: anything else would go out under the claim of being encrypted.
func composeEncrypted(message string) ([]byte, error) {
	const head = "-----BEGIN PGP MESSAGE-----"
	message = strings.TrimSpace(message)
	if !strings.HasPrefix(message, head) || !strings.HasSuffix(message, "-----END PGP MESSAGE-----") {
		return nil, fmt.Errorf("webmail: not an armored PGP message")
	}
	return []byte(message + "\r\n"), nil
}
