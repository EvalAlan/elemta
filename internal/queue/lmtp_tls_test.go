package queue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	smtp "github.com/emersion/go-smtp"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mailbox.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"mailbox.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type tlsSeenSession struct {
	conn *smtp.Conn
	seen chan bool
}

func (s *tlsSeenSession) Reset()        {}
func (s *tlsSeenSession) Logout() error { return nil }
func (s *tlsSeenSession) Mail(string, *smtp.MailOptions) error {
	_, secure := s.conn.TLSConnectionState()
	s.seen <- secure
	return nil
}
func (s *tlsSeenSession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (s *tlsSeenSession) Data(r io.Reader) error               { _, err := io.Copy(io.Discard, r); return err }

func startLMTP(t *testing.T, withTLS bool) (string, int, chan bool) {
	t.Helper()
	seen := make(chan bool, 4)
	server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) { return &tlsSeenSession{conn: c, seen: seen}, nil }))
	server.LMTP = true
	server.Domain = "mailbox.test"
	if withTLS {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	return host, port, seen
}

func TestLMTPStartTLS(t *testing.T) {
	host, port, seen := startLMTP(t, true)
	h := NewLMTPDeliveryHandler(host, port, 10, 0)
	h.SetTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- test certificate
	msg := Message{ID: "q", From: "a@example.com", To: []string{"b@example.com"}}
	if err := h.DeliverMessage(context.Background(), msg, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if !<-seen {
		t.Fatal("MAIL FROM was sent before TLS")
	}
}

// With TLS required, a server that doesn't offer it gets nothing: no
// MAIL FROM, and a temporary failure the queue retries.
func TestLMTPStartTLSRequiredNoDowngrade(t *testing.T) {
	host, port, seen := startLMTP(t, false)
	h := NewLMTPDeliveryHandler(host, port, 10, 0)
	h.SetTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	msg := Message{ID: "q", From: "a@example.com", To: []string{"b@example.com"}}
	res, err := h.DeliverMessageWithMetadata(context.Background(), msg, []byte("Subject: x\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("delivered without TLS")
	}
	if res != nil {
		for _, o := range res.RecipientOutcomes {
			if o.Status != RecipientTemporaryFailure {
				t.Errorf("outcome = %+v, want a temporary failure", o)
			}
		}
	}
	select {
	case <-seen:
		t.Fatal("MAIL FROM reached a server without TLS")
	default:
	}
}
