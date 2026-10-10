package smtp

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

// writeSelfSigned writes a fresh self-signed pair for cn and returns its
// serial, so a test can tell certificates apart.
func writeSelfSigned(t *testing.T, certFile, keyFile, cn string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
}

func servedSerial(t *testing.T, r *certReloader) int64 {
	t.Helper()
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

// bumpMtime moves both files' modification times forward, so a rewrite within
// the filesystem's timestamp granularity still counts as a change.
func bumpMtime(t *testing.T, files ...string) {
	t.Helper()
	future := time.Now().Add(time.Minute)
	for _, f := range files {
		if err := os.Chtimes(f, future, future); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertReloaderPicksUpARenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certFile, keyFile, "mail.example.com", 1)

	r, err := newCertReloader(certFile, keyFile, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	now := r.lastChecked
	r.now = func() time.Time { return now }
	reloaded := 0
	r.onReload = func(tls.Certificate) { reloaded++ }

	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("serving serial %d, want 1", got)
	}

	writeSelfSigned(t, certFile, keyFile, "mail.example.com", 2)
	bumpMtime(t, certFile, keyFile)

	if got := servedSerial(t, r); got != 1 {
		t.Errorf("reloaded before the check interval: serving %d", got)
	}
	now = now.Add(r.checkInterval)
	if got := servedSerial(t, r); got != 2 {
		t.Errorf("after renewal on disk, serving serial %d, want 2", got)
	}
	if reloaded != 1 {
		t.Errorf("onReload called %d times, want 1", reloaded)
	}
}

// A renewal caught half-written must not take the server's certificate away.
func TestCertReloaderKeepsTheOldCertificateWhenTheNewOneIsBroken(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certFile, keyFile, "mail.example.com", 7)

	r, err := newCertReloader(certFile, keyFile, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	now := r.lastChecked
	r.now = func() time.Time { return now }

	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, certFile)
	now = now.Add(r.checkInterval)

	if got := servedSerial(t, r); got != 7 {
		t.Errorf("serving serial %d after a broken renewal, want the old 7", got)
	}
}

func TestCertReloaderFailsAtStartupWithoutACertificate(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCertReloader(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"), nil); err == nil {
		t.Fatal("expected an error for missing certificate files")
	}
}
