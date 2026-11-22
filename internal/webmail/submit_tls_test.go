package webmail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	smtp "github.com/emersion/go-smtp"
)

type refuseAll struct{}

func (refuseAll) Reset()        {}
func (refuseAll) Logout() error { return nil }
func (refuseAll) Mail(string, *smtp.MailOptions) error {
	return errors.New("not here")
}
func (refuseAll) Rcpt(string, *smtp.RcptOptions) error { return errors.New("not here") }
func (refuseAll) Data(io.Reader) error                 { return errors.New("not here") }

// startTLSNameServer is a STARTTLS SMTP server that reports the TLS server
// name (SNI) each client asked for. It refuses everything after the
// handshake: the name is all the test needs.
func startTLSNameServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"mail.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	names := make(chan string, 4)
	server := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return refuseAll{}, nil
	}))
	server.Domain = "mail.example.test"
	server.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			names <- hello.ServerName
			return &cert, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String(), names
}

func TestSubmitterChecksTheConfiguredServerName(t *testing.T) {
	addr, names := startTLSNameServer(t)
	for _, tc := range []struct {
		serverName, want string
	}{
		// An IP host sends no SNI, so the certificate could never match it.
		{"", ""},
		{"mail.example.test", "mail.example.test"},
	} {
		s := SMTPSubmitter{Addr: addr, TLSMode: TLSModeStartTLS, InsecureSkipVerify: true, ServerName: tc.serverName}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// Fails at AUTH, after the handshake this test is about.
		_ = s.Submit(ctx, "dana@example.test", "pw", "dana@example.test", []string{"lee@example.test"}, []byte("x\r\n"))
		cancel()
		select {
		case got := <-names:
			if got != tc.want {
				t.Errorf("ServerName %q: client asked for %q, want %q", tc.serverName, got, tc.want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("ServerName %q: no TLS handshake", tc.serverName)
		}
	}
}

func TestSubmitterVerifiesAgainstTheServerName(t *testing.T) {
	addr, names := startTLSNameServer(t)
	// Verification on: the self-signed certificate is refused, which shows
	// the override doesn't loosen verification.
	s := SMTPSubmitter{Addr: addr, TLSMode: TLSModeStartTLS, ServerName: "mail.example.test"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.Submit(ctx, "dana@example.test", "pw", "dana@example.test", []string{"lee@example.test"}, []byte("x\r\n"))
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("Submit = %v, want an unknown-authority refusal", err)
	}
	if got := <-names; got != "mail.example.test" {
		t.Errorf("client asked for %q", got)
	}
}
