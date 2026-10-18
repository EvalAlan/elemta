package smtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

type verifyTLSSession struct{ conn *gosmtp.Conn }

func (s *verifyTLSSession) Reset()                                 {}
func (s *verifyTLSSession) Logout() error                          { return nil }
func (s *verifyTLSSession) Mail(string, *gosmtp.MailOptions) error { return nil }
func (s *verifyTLSSession) Data(r io.Reader) error                 { _, err := io.Copy(io.Discard, r); return err }
func (s *verifyTLSSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if _, secure := s.conn.TLSConnectionState(); !secure {
		return &gosmtp.SMTPError{Code: 530, Message: "TLS first"}
	}
	if to != "known@example.com" {
		return &gosmtp.SMTPError{Code: 550, Message: "no such user"}
	}
	return nil
}

func TestRecipientVerifierStartTLS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mailbox.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := gosmtp.NewServer(gosmtp.BackendFunc(func(c *gosmtp.Conn) (gosmtp.Session, error) { return &verifyTLSSession{conn: c}, nil }))
	server.LMTP = true
	server.Domain = "mailbox.test"
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	v := newRecipientVerifier(ln.Addr().String(), "mx.example.com", slog.Default())
	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(der)
	pool.AddCert(cert)
	v.tlsConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if verdict, _ := v.Verify(context.Background(), "known@example.com"); verdict != rcptExists {
		t.Fatalf("known over TLS = %v", verdict)
	}
	if verdict, _ := v.Verify(context.Background(), "nobody@example.com"); verdict != rcptRejected {
		t.Fatalf("unknown over TLS = %v", verdict)
	}
}
