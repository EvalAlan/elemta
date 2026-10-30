package mailbox

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Message bodies are encrypted before they reach the body store, so a leaked
// bucket or volume is ciphertext. ELEMTA_MAILBOX_BODY_KEYS lists versioned
// keys as ELEMTA_MAILBOX_TOTP_KEYS does: the first encrypts, the rest stay
// readable until every body has been moved off them. It protects the store
// alone: the keys live with the service, and PostgreSQL holds the search index
// and message summaries.
//
// A stored body is:
//
//	magic | version length (1) | version | salt (32) | AES-256-GCM ciphertext
//
// Each body has its own key, derived from the master key and the salt, so the
// GCM nonce can be fixed and there is no limit from random nonces colliding.
// The header and the body's store key are authenticated: an object moved to
// another key, or given another key version, fails to open.

const (
	bodyKeySize    = 32
	bodySaltSize   = 32
	maxBodyVersion = 64
)

// bodyMagic can't begin a stored message written before encryption was on: mail
// starts with a header field name, and the leading NUL isn't one.
var bodyMagic = []byte("\x00ELMB1\x00")

// bodyOverhead is the most a body grows when sealed.
const bodyOverhead = 7 + 1 + maxBodyVersion + bodySaltSize + 16

// ErrBodyKeyUnavailable means a body needs a key version that isn't configured.
var ErrBodyKeyUnavailable = errors.New("message body key version unavailable")

type bodySecret struct {
	version string
	key     []byte
}

// parseBodyKeys reads "v2:<base64>,v1:<base64>". Empty means encryption is off.
func parseBodyKeys(value string) ([]bodySecret, error) {
	if value == "" {
		return nil, nil
	}
	var keys []bodySecret
	seen := map[string]bool{}
	for _, entry := range strings.Split(value, ",") {
		version, encoded, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || version == "" || len(version) > maxBodyVersion || strings.ContainsAny(version, ":,") || seen[version] {
			return nil, errors.New("invalid or duplicate message body key version")
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != bodyKeySize {
			return nil, errors.New("message body key must be 32 base64-encoded bytes")
		}
		keys = append(keys, bodySecret{version: version, key: raw})
		seen[version] = true
	}
	return keys, nil
}

// fingerprint identifies a key without revealing it.
func (k bodySecret) fingerprint() string {
	mac := hmac.New(sha256.New, k.key)
	_, _ = mac.Write([]byte("elemta mailbox body key check"))
	return hex.EncodeToString(mac.Sum(nil))
}

func (k bodySecret) aead(salt []byte) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, k.key, salt, "elemta mailbox body v1", bodyKeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func bodyAAD(header []byte, key string) []byte {
	return append(append([]byte{}, header...), key...)
}

func sealBody(k bodySecret, key string, plain []byte) ([]byte, error) {
	// #nosec G115 -- parseBodyKeys limits a version to maxBodyVersion bytes
	header := append(append([]byte{}, bodyMagic...), byte(len(k.version)))
	header = append(header, k.version...)
	salt := make([]byte, bodySaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	header = append(header, salt...)
	aead, err := k.aead(salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	// #nosec G407 -- the key is derived from a fresh random salt for this one
	// seal, so a key and nonce pair is never reused
	return aead.Seal(header, nonce, plain, bodyAAD(header, key)), nil
}

// bodyVersion returns the key version a stored body names, and false for a
// body stored in the clear.
func bodyVersion(stored []byte) (string, bool, error) {
	if !bytes.HasPrefix(stored, bodyMagic) {
		return "", false, nil
	}
	n := len(bodyMagic)
	if len(stored) < n+1 || len(stored) < n+1+int(stored[n])+bodySaltSize {
		return "", true, errors.New("message body ciphertext is truncated")
	}
	return string(stored[n+1 : n+1+int(stored[n])]), true, nil
}

// encryptedBodies wraps the real store.
type encryptedBodies struct {
	BodyStore
	keys []bodySecret
}

func (e *encryptedBodies) current() string { return e.keys[0].version }

func (e *encryptedBodies) seal(key string, plain []byte) ([]byte, error) {
	return sealBody(e.keys[0], key, plain)
}

// open returns a body's plaintext. A body from before encryption was turned on
// comes back as it is, which keeps old mail readable until it is migrated.
func (e *encryptedBodies) open(key string, stored []byte) ([]byte, error) {
	version, sealed, err := bodyVersion(stored)
	if err != nil || !sealed {
		return stored, err
	}
	for _, k := range e.keys {
		if k.version != version {
			continue
		}
		headerLen := len(bodyMagic) + 1 + len(version) + bodySaltSize
		header := stored[:headerLen]
		aead, err := k.aead(header[headerLen-bodySaltSize:])
		if err != nil {
			return nil, err
		}
		plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), stored[headerLen:], bodyAAD(header, key))
		if err != nil {
			return nil, errors.New("message body failed authentication")
		}
		return plain, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrBodyKeyUnavailable, version)
}

func (e *encryptedBodies) Put(ctx context.Context, key string, plain []byte) error {
	sealed, err := e.seal(key, plain)
	if err != nil {
		return err
	}
	return e.BodyStore.Put(ctx, key, sealed)
}

func (e *encryptedBodies) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	stored, err := e.BodyStore.Get(ctx, key, max+bodyOverhead)
	if err != nil {
		return nil, err
	}
	plain, err := e.open(key, stored)
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > max {
		return nil, ErrTooLarge
	}
	return plain, nil
}

func (e *encryptedBodies) Check(ctx context.Context) error {
	if err := e.BodyStore.Check(ctx); err != nil {
		return err
	}
	return checkBodyCanary(ctx, e)
}

// checkBodyKeys records each key's fingerprint and compares it with what is
// already there. Two replicas on different keys would each write mail the
// other can't read, and nothing else would notice until someone opened it.
// With no keys configured it refuses if any were ever used, so a lost
// environment file can't silently turn encryption off for new mail.
func (e *Engine) checkBodyKeys(ctx context.Context, keys []bodySecret) error {
	if len(keys) == 0 {
		var used int
		if err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_body_keys`).Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			return errors.New("message bodies are encrypted but ELEMTA_MAILBOX_BODY_KEYS is not set")
		}
		return nil
	}
	for _, k := range keys {
		if _, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_body_keys(version,fingerprint) VALUES($1,$2) ON CONFLICT(version) DO NOTHING`, k.version, k.fingerprint()); err != nil {
			return err
		}
		var want string
		if err := e.DB.QueryRowContext(ctx, `SELECT fingerprint FROM mailbox_body_keys WHERE version=$1`, k.version).Scan(&want); err != nil {
			return err
		}
		if !hmac.Equal([]byte(want), []byte(k.fingerprint())) {
			return fmt.Errorf("message body key %q is not the key this mailbox store was encrypted with", k.version)
		}
	}
	return nil
}
