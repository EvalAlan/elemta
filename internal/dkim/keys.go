package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Key generation and DNS records for DKIM key rotation.
//
// Rotating a key safely is a sequence, and the step that goes wrong is the
// order: a server that starts signing with a new selector before DNS serves
// that selector's key fails DKIM on every message until it does, which under
// a DMARC reject policy means mail is refused. The helpers here let the CLI
// generate a key, print the record to publish, and confirm DNS serves the
// matching key before the configuration is switched.

// GenerateKey creates a signing key. keyType is "rsa" (bits defaults to 2048)
// or "ed25519".
func GenerateKey(keyType string, bits int) (crypto.Signer, error) {
	switch strings.ToLower(keyType) {
	case "", "rsa":
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			// RFC 8301 lets verifiers accept 1024-bit keys, but signers
			// should use 2048 and some receivers already refuse less.
			return nil, fmt.Errorf("RSA keys must be at least 2048 bits")
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, fmt.Errorf("unknown key type %q: use rsa or ed25519", keyType)
	}
}

// WritePrivateKey saves key as PKCS#8 PEM, readable only by its owner. It will
// not overwrite an existing file: replacing a key that is still published and
// in use is how a rotation breaks signing.
func WritePrivateKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen output path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; choose a new file for the new key", path)
		}
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// LoadPublicKey reads a configured private key (with the same permission
// checks as signing) and returns its public half.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	signer, _, err := loadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// DNSRecord returns the TXT record value that publishes pub.
func DNSRecord(pub crypto.PublicKey) (string, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
	case ed25519.PublicKey:
		// RFC 8463: the raw 32-byte key, not a SubjectPublicKeyInfo.
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key), nil
	default:
		return "", fmt.Errorf("unsupported key type %T", pub)
	}
}

// RecordName is the DNS name a selector's key is published at.
func RecordName(selector, domain string) string {
	return selector + "._domainkey." + strings.TrimSuffix(domain, ".")
}

// PublishedKey parses the public key out of DKIM TXT records. A lookup can
// return the record as several strings; callers join each record's strings
// before passing it here.
func PublishedKey(records []string) (crypto.PublicKey, error) {
	for _, record := range records {
		tags := map[string]string{}
		for _, part := range strings.Split(record, ";") {
			name, value, found := strings.Cut(part, "=")
			if !found {
				continue
			}
			tags[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
		if v, ok := tags["v"]; ok && !strings.EqualFold(v, "DKIM1") {
			continue
		}
		encoded := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, tags["p"])
		if encoded == "" {
			// An empty p= is a revoked key (RFC 6376 §3.6.1).
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("published key is not valid base64")
		}
		keyType := strings.ToLower(tags["k"])
		switch keyType {
		case "", "rsa":
			parsed, err := x509.ParsePKIXPublicKey(raw)
			if err != nil {
				// Some generators publish PKCS#1 rather than SPKI.
				if pk, err2 := x509.ParsePKCS1PublicKey(raw); err2 == nil {
					return pk, nil
				}
				return nil, fmt.Errorf("published key is not a valid RSA public key")
			}
			return parsed, nil
		case "ed25519":
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("published ed25519 key has the wrong length")
			}
			return ed25519.PublicKey(raw), nil
		default:
			return nil, fmt.Errorf("published key uses unsupported type %q", keyType)
		}
	}
	return nil, fmt.Errorf("no published key found in the TXT record")
}

// SamePublicKey reports whether a and b are the same key.
func SamePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
