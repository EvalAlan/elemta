package dkim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

const testMessage = "From: Alice <alice@example.com>\r\n" +
	"To: Bob <bob@remote.test>\r\n" +
	"Subject: Hello\r\n" +
	"Date: Thu, 09 Jul 2026 12:00:00 +0000\r\n" +
	"Message-ID: <abc@example.com>\r\n" +
	"\r\n" +
	"This is the body.\r\n"

// writeRSAKey writes a fresh PKCS#8 RSA key to dir with mode 0600 and returns
// its path and the public key (for building a DNS resolver stub).
func writeRSAKey(t *testing.T, dir string) (string, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	path := filepath.Join(dir, "rsa.key")
	writeKeyFile(t, path, "PRIVATE KEY", der, 0o600)
	return path, &priv.PublicKey
}

func writeKeyFile(t *testing.T, path, blockType string, der []byte, mode os.FileMode) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, mode); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// os.WriteFile may be affected by umask; force the exact mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
}

// dnsRecord builds the TXT value a verifier would fetch for the given public key.
func rsaDNSRecord(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64Std(der)
}

func ed25519DNSRecord(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	return "v=DKIM1; k=ed25519; p=" + base64Std(pub)
}

// verifyWithKey verifies signed message content against a fixed public key
// record, bypassing DNS. This exercises the go-msgauth verification path — the
// same library the plugin verification code references.
func verifyWithKey(t *testing.T, signed []byte, selector, domain, txt string) []*dkim.Verification {
	t.Helper()
	opts := &dkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			want := selector + "._domainkey." + domain
			if strings.TrimSuffix(name, ".") != want {
				t.Fatalf("unexpected TXT lookup %q, want %q", name, want)
			}
			return []string{txt}, nil
		},
	}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(signed), opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return verifications
}

func newTestSigner(t *testing.T, cfg *Config) *Signer {
	t.Helper()
	s, err := NewSigner(cfg, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s == nil {
		t.Fatal("NewSigner returned nil signer")
	}
	return s
}

func TestSignAndVerifyRSA(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeRSAKey(t, dir)

	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	signed, err := s.Sign([]byte(testMessage), "example.com")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Fatal("signed message has no DKIM-Signature header")
	}

	vs := verifyWithKey(t, signed, "sel1", "example.com", rsaDNSRecord(t, pub))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verification, got %d", len(vs))
	}
	if vs[0].Err != nil {
		t.Fatalf("verification failed: %v", vs[0].Err)
	}
	if vs[0].Domain != "example.com" {
		t.Fatalf("verified domain = %q", vs[0].Domain)
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	keyPath := filepath.Join(dir, "ed.key")
	writeKeyFile(t, keyPath, "PRIVATE KEY", der, 0o600)

	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "ed", PrivateKeyPath: keyPath}},
	})

	signed, err := s.Sign([]byte(testMessage), "example.com")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	vs := verifyWithKey(t, signed, "ed", "example.com", ed25519DNSRecord(t, pub))
	if len(vs) != 1 || vs[0].Err != nil {
		t.Fatalf("ed25519 verification failed: %+v", vs)
	}
}

func TestSignSkipsUnconfiguredDomain(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeRSAKey(t, dir)
	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	out, err := s.Sign([]byte(testMessage), "other.test")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(out, []byte(testMessage)) {
		t.Fatal("message for unconfigured domain should be unchanged")
	}
	if bytes.Contains(out, []byte("DKIM-Signature:")) {
		t.Fatal("unconfigured domain must not be signed")
	}
}

// TestRetryDoesNotDoubleSign signs a message, then signs the already-signed
// output again (simulating a delivery retry). The second pass must be a no-op:
// exactly one DKIM-Signature for the domain.
func TestRetryDoesNotDoubleSign(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeRSAKey(t, dir)
	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	first, err := s.Sign([]byte(testMessage), "example.com")
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	second, err := s.Sign(first, "example.com")
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("retry re-signed an already-signed message")
	}
	if n := countHeader(second, "DKIM-Signature:"); n != 1 {
		t.Fatalf("expected exactly 1 DKIM-Signature after retry, got %d", n)
	}

	// The single signature must still verify.
	vs := verifyWithKey(t, second, "sel1", "example.com", rsaDNSRecord(t, pub))
	if len(vs) != 1 || vs[0].Err != nil {
		t.Fatalf("post-retry verification failed: %+v", vs)
	}
}

func TestSignUsesFromHeaderFallbackDomain(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeRSAKey(t, dir)
	newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	if got := FromHeaderDomain([]byte(testMessage)); got != "example.com" {
		t.Fatalf("FromHeaderDomain = %q, want example.com", got)
	}
}

func TestRejectInsecureKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPath := filepath.Join(dir, "insecure.key")
	writeKeyFile(t, keyPath, "PRIVATE KEY", der, 0o644) // group/other readable

	_, err = NewSigner(&Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	}, nil)
	if err == nil {
		t.Fatal("expected error for world/group-readable key")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSignerDisabled(t *testing.T) {
	s, err := NewSigner(&Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("disabled config should not error: %v", err)
	}
	if s != nil {
		t.Fatal("disabled config should return nil signer")
	}

	// nil signer Sign is a pass-through.
	var nilSigner *Signer
	out, err := nilSigner.Sign([]byte(testMessage), "example.com")
	if err != nil || !bytes.Equal(out, []byte(testMessage)) {
		t.Fatal("nil signer should pass content through unchanged")
	}
}

func TestNewSignerValidation(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeRSAKey(t, dir)

	cases := []struct {
		name string
		cfg  *Config
	}{
		{"empty domain", &Config{Enabled: true, Domains: []DomainConfig{{Selector: "s", PrivateKeyPath: keyPath}}}},
		{"empty selector", &Config{Enabled: true, Domains: []DomainConfig{{Domain: "example.com", PrivateKeyPath: keyPath}}}},
		{"empty key path", &Config{Enabled: true, Domains: []DomainConfig{{Domain: "example.com", Selector: "s"}}}},
		{"no domains", &Config{Enabled: true}},
		{"bad canon", &Config{Enabled: true, HeaderCanonicalization: "bogus", Domains: []DomainConfig{{Domain: "example.com", Selector: "s", PrivateKeyPath: keyPath}}}},
		{"duplicate domain", &Config{Enabled: true, Domains: []DomainConfig{
			{Domain: "example.com", Selector: "s1", PrivateKeyPath: keyPath},
			{Domain: "example.com", Selector: "s2", PrivateKeyPath: keyPath},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.cfg, nil); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestDomainFromAddress(t *testing.T) {
	cases := map[string]string{
		"user@example.com":     "example.com",
		"<user@EXAMPLE.com>":   "example.com",
		"  a@b.co  ":           "b.co",
		"noatsign":             "",
		"trailingat@":          "",
		"User@Sub.Example.Org": "sub.example.org",
	}
	for in, want := range cases {
		if got := DomainFromAddress(in); got != want {
			t.Errorf("DomainFromAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasKeyFor(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeRSAKey(t, dir)
	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "Example.COM", Selector: "s", PrivateKeyPath: keyPath}},
	})
	if !s.HasKeyFor("example.com") {
		t.Fatal("expected key for example.com (case-insensitive)")
	}
	if s.HasKeyFor("other.test") {
		t.Fatal("did not expect key for other.test")
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func countHeader(content []byte, prefix string) int {
	n := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}
