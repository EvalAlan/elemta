// Package webpush sends Web Push messages (RFC 8030) to browsers: the
// payload encrypted for the one browser that subscribed (RFC 8291,
// aes128gcm), and the request signed with the server's VAPID key (RFC 8292)
// so the push service knows which server may use the subscription.
//
// The push services (Google's, Mozilla's, Apple's, Microsoft's) carry the
// message but can't read it: only the browser holds the private key. They
// do see that a message was sent, when, and how big it was.
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MaxPayload is the most a message may carry. Push services accept 4096
// bytes of encrypted body; the header and padding take the rest.
const MaxPayload = 3800

// recordSize is the aes128gcm record size. One record holds the whole
// message.
const recordSize = 4096

var b64 = base64.RawURLEncoding

// Subscription is what the browser's PushManager.subscribe returned.
type Subscription struct {
	Endpoint string
	// P256dh is the browser's public key, and Auth its shared secret, both
	// base64url as the browser gives them.
	P256dh string
	Auth   string
}

// Keys is a server's VAPID key pair.
type Keys struct {
	private *ecdsa.PrivateKey
	// Public is the uncompressed public key, base64url: what the page passes
	// to subscribe as applicationServerKey.
	Public string
}

// GenerateKeys makes a new VAPID key pair.
func GenerateKeys() (Keys, string, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, "", err
	}
	priv := b64.EncodeToString(k.Bytes())
	keys, err := ParseKeys(priv)
	return keys, priv, err
}

// ParseKeys reads a private key saved from GenerateKeys.
func ParseKeys(private string) (Keys, error) {
	raw, err := b64.DecodeString(strings.TrimRight(private, "="))
	if err != nil {
		return Keys{}, errors.New("webpush: bad private key")
	}
	k, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		return Keys{}, errors.New("webpush: bad private key")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return Keys{}, errors.New("webpush: bad private key")
	}
	return Keys{private: priv, Public: b64.EncodeToString(k.PublicKey().Bytes())}, nil
}

// decodeKey reads base64url, padded or not, as browsers send either.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := b64.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// Valid reports whether the subscription's keys are well formed.
func (s Subscription) Valid() error {
	pub, err := decodeKey(s.P256dh)
	if err != nil {
		return errors.New("webpush: bad p256dh")
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return errors.New("webpush: bad p256dh")
	}
	auth, err := decodeKey(s.Auth)
	if err != nil || len(auth) != 16 {
		return errors.New("webpush: bad auth secret")
	}
	return nil
}

// Encrypt seals a payload for the subscription (RFC 8291 section 3).
func Encrypt(sub Subscription, payload []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypt(sub, payload, local, salt)
}

func encrypt(sub Subscription, payload []byte, local *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("webpush: payload is %d bytes, more than %d", len(payload), MaxPayload)
	}
	uaRaw, err := decodeKey(sub.P256dh)
	if err != nil {
		return nil, errors.New("webpush: bad p256dh")
	}
	ua, err := ecdh.P256().NewPublicKey(uaRaw)
	if err != nil {
		return nil, errors.New("webpush: bad p256dh")
	}
	auth, err := decodeKey(sub.Auth)
	if err != nil || len(auth) != 16 {
		return nil, errors.New("webpush: bad auth secret")
	}
	shared, err := local.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := local.PublicKey().Bytes()
	info := append(append([]byte("WebPush: info\x00"), uaRaw...), asPublic...)
	ikm, err := hkdf.Key(sha256.New, shared, auth, string(info), 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The last (and only) record ends with the delimiter 0x02 and no padding.
	plain := append(append(make([]byte, 0, len(payload)+1), payload...), 2)
	var out bytes.Buffer
	out.Write(salt)
	_ = binary.Write(&out, binary.BigEndian, uint32(recordSize))
	out.WriteByte(65) // the key's length: an uncompressed P-256 point
	out.Write(asPublic)
	out.Write(gcm.Seal(nil, nonce, plain, nil))
	return out.Bytes(), nil
}

// Decrypt opens a message as the browser does, with its private key and
// auth secret. The server never needs it; tests and diagnostics do.
func Decrypt(private *ecdh.PrivateKey, auth, body []byte) ([]byte, error) {
	if len(body) < 21 || len(body) < 21+int(body[20]) {
		return nil, errors.New("webpush: short message")
	}
	salt, idlen := body[:16], int(body[20])
	as, err := ecdh.P256().NewPublicKey(body[21 : 21+idlen])
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(as)
	if err != nil {
		return nil, err
	}
	info := append(append([]byte("WebPush: info\x00"), private.PublicKey().Bytes()...), as.Bytes()...)
	ikm, err := hkdf.Key(sha256.New, shared, auth, string(info), 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, body[21+idlen:], nil)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 || plain[len(plain)-1] != 2 {
		return nil, errors.New("webpush: not a last record")
	}
	return plain[:len(plain)-1], nil
}

// vapid is the Authorization header for a request to this endpoint
// (RFC 8292): a short-lived ES256 token naming the push service's origin
// and how to reach whoever runs the server.
func (k Keys) vapid(endpoint, contact string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	header := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": now.Add(12 * time.Hour).Unix(), "sub": contact})
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + signing + "." + b64.EncodeToString(sig) + ", k=" + k.Public, nil
}

// Message is one push.
type Message struct {
	Payload []byte
	// TTL is how long the push service keeps it for a browser that's offline.
	TTL time.Duration
	// Urgency is "high" for things a person is waiting on, else "normal".
	Urgency string
	// Topic replaces a message to the same topic that is still waiting to be
	// delivered: up to 32 base64url characters.
	Topic string
}

// ErrGone means the subscription no longer exists (the browser
// unsubscribed, or the push service dropped it) and should be forgotten.
var ErrGone = errors.New("webpush: subscription is gone")

// Sender delivers messages.
type Sender struct {
	Keys Keys
	// Contact is the VAPID subject: a mailto: or https: URL push services
	// can use to reach whoever runs this server.
	Contact string
	Client  *http.Client
	// Allowed decides which endpoints may be sent to; nil is AllowedEndpoint.
	Allowed func(*url.URL) bool
	Now     func() time.Time
}

// pushHosts are the push services browsers use. A subscription's endpoint
// is whatever the browser said, so sending to anywhere else would let a
// user make this server post to an address of their choosing.
var pushHosts = []string{
	"fcm.googleapis.com",        // Chrome, Edge on Android, Opera, Samsung
	"android.googleapis.com",    // older Chrome subscriptions
	"push.services.mozilla.com", // Firefox
	"push.apple.com",            // Safari, and web apps on iPhone and iPad
	"notify.windows.com",        // Edge on Windows
}

// AllowedEndpoint reports whether u is an https URL on a known push service.
func AllowedEndpoint(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range pushHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// CheckEndpoint parses and vets an endpoint.
func (s *Sender) CheckEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 1024 {
		return errors.New("webpush: bad endpoint")
	}
	allowed := s.Allowed
	if allowed == nil {
		allowed = AllowedEndpoint
	}
	if !allowed(u) {
		return errors.New("webpush: endpoint is not a known push service")
	}
	return nil
}

// Send delivers one message. It returns ErrGone when the subscription
// should be deleted.
func (s *Sender) Send(ctx context.Context, sub Subscription, m Message) error {
	if err := s.CheckEndpoint(sub.Endpoint); err != nil {
		return err
	}
	body, err := Encrypt(sub, m.Payload)
	if err != nil {
		return err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	auth, err := s.Keys.vapid(sub.Endpoint, s.Contact, now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ttl := max(int(m.TTL/time.Second), 0)
	req.Header.Set("TTL", strconv.Itoa(ttl))
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", auth)
	if m.Urgency != "" {
		req.Header.Set("Urgency", m.Urgency)
	}
	if m.Topic != "" {
		req.Header.Set("Topic", m.Topic)
	}
	client := s.Client
	if client == nil {
		client = DefaultClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return ErrGone
	default:
		return fmt.Errorf("webpush: push service answered %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
}

// DefaultClient is an HTTP client for push services: short timeouts, and no
// redirects, which a push service has no reason to send and which would
// lead past the endpoint check.
func DefaultClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
