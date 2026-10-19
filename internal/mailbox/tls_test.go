package mailbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cn := func() string {
		c, _ := r.GetCertificate(&tls.ClientHelloInfo{})
		x, _ := x509.ParseCertificate(c.Certificate[0])
		return x.Subject.CommonName
	}
	if cn() != "first" {
		t.Fatal("first certificate not served")
	}
	writeCert(t, dir, "renewed")
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future)
	r.checked = time.Now().Add(-2 * time.Minute) // as if a minute passed
	if cn() != "renewed" {
		t.Fatal("renewed certificate not picked up")
	}
	// A broken renewal keeps the working certificate.
	_ = os.WriteFile(certFile, []byte("not a cert"), 0o600)
	later := future.Add(time.Minute)
	_ = os.Chtimes(certFile, later, later)
	r.checked = time.Now().Add(-2 * time.Minute)
	if cn() != "renewed" {
		t.Fatal("broken renewal replaced the working certificate")
	}
}
