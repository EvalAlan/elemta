package tlssni

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed pair for names into dir/label, with serial
// so a test can tell certificates apart.
func writePair(t *testing.T, dir, label string, serial int64, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, label)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func serialOf(c *tls.Certificate) int64 {
	if c == nil || c.Leaf == nil {
		return 0
	}
	return c.Leaf.SerialNumber.Int64()
}

func TestLookupByName(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "mail.example.net", 2, "mail.example.net")
	writePair(t, dir, "wild", 3, "*.example.org")
	d := New(dir, nil)

	for name, want := range map[string]int64{
		"mail.example.net":  2,
		"MAIL.example.net.": 2,
		"imap.example.org":  3,
		"example.org":       0, // a wildcard doesn't cover the bare domain
		"other.example.com": 0,
		"":                  0,
	} {
		if got := serialOf(d.Lookup(name)); got != want {
			t.Errorf("Lookup(%q) = serial %d, want %d", name, got, want)
		}
	}
}

func TestWrapFallsBackToPrimary(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "extra", 2, "mail.example.net")
	primary := &tls.Certificate{}
	get := New(dir, nil).Wrap(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return primary, nil })

	if c, _ := get(&tls.ClientHelloInfo{ServerName: "dev.example.com"}); c != primary {
		t.Error("an unknown name should get the primary certificate")
	}
	if c, _ := get(&tls.ClientHelloInfo{}); c != primary {
		t.Error("a handshake without SNI should get the primary certificate")
	}
	if c, _ := get(&tls.ClientHelloInfo{ServerName: "mail.example.net"}); serialOf(c) != 2 {
		t.Error("a known name should get its own certificate")
	}
}

func TestMissingDirectoryThenAdded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sni")
	d := New(dir, nil)
	now := d.scanned
	d.now = func() time.Time { return now }
	if d.Lookup("mail.example.net") != nil {
		t.Fatal("nothing should match before the directory exists")
	}

	writePair(t, dir, "mail.example.net", 2, "mail.example.net")
	if d.Lookup("mail.example.net") != nil {
		t.Fatal("the directory should not be rescanned before the interval")
	}
	now = now.Add(defaultInterval)
	if serialOf(d.Lookup("mail.example.net")) != 2 {
		t.Fatal("a domain added later should be picked up on the next scan")
	}
}

func TestRenewalAndBrokenRenewal(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "m", 2, "mail.example.net")
	d := New(dir, nil)
	now := d.scanned
	d.now = func() time.Time { return now }

	writePair(t, dir, "m", 3, "mail.example.net")
	bump(t, filepath.Join(dir, "m"), time.Minute)
	now = now.Add(defaultInterval)
	if serialOf(d.Lookup("mail.example.net")) != 3 {
		t.Fatal("a renewed certificate should replace the old one")
	}

	// A renewal caught half-written keeps the certificate already loaded.
	if err := os.WriteFile(filepath.Join(dir, "m", "cert.pem"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	bump(t, filepath.Join(dir, "m"), 2*time.Minute)
	now = now.Add(defaultInterval)
	if serialOf(d.Lookup("mail.example.net")) != 3 {
		t.Fatal("a pair that fails to load should keep the previous certificate")
	}

	if err := os.RemoveAll(filepath.Join(dir, "m")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(defaultInterval)
	if d.Lookup("mail.example.net") != nil {
		t.Fatal("a removed domain should stop being served")
	}
}

// bump moves both files' modification times forward, since a test rewrites
// them faster than some filesystems' timestamp resolution.
func bump(t *testing.T, sub string, by time.Duration) {
	t.Helper()
	at := time.Now().Add(by)
	for _, f := range []string{"cert.pem", "key.pem"} {
		if err := os.Chtimes(filepath.Join(sub, f), at, at); err != nil {
			t.Fatal(err)
		}
	}
}
