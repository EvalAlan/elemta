package queue

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMessageRequiresTLS(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want bool
	}{
		{name: "no annotations", msg: Message{}, want: false},
		{name: "require tls true", msg: Message{Annotations: map[string]string{"require_tls": "true"}}, want: true},
		{name: "require tls numeric", msg: Message{Annotations: map[string]string{"require_tls": "1"}}, want: true},
		{name: "require tls false", msg: Message{Annotations: map[string]string{"require_tls": "false"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messageRequiresTLS(tt.msg); got != tt.want {
				t.Fatalf("messageRequiresTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// startFakeSMTPServer runs a minimal single-connection SMTP server on localhost
// and returns its address. If offerSTARTTLS is true, it advertises and completes
// a STARTTLS handshake using a self-signed certificate.
func startFakeSMTPServer(t *testing.T, offerSTARTTLS bool) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake SMTP server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cert := generateSelfSignedCert(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		writeLine := func(s string) {
			_, _ = rw.WriteString(s + "\r\n")
			_ = rw.Flush()
		}

		writeLine("220 fake.test ESMTP")
		if _, err := rw.ReadString('\n'); err != nil { // EHLO
			return
		}

		if offerSTARTTLS {
			writeLine("250-fake.test")
			writeLine("250 STARTTLS")
			if _, err := rw.ReadString('\n'); err != nil { // STARTTLS
				return
			}
			writeLine("220 Ready to start TLS")

			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
			if _, err := rw.ReadString('\n'); err != nil { // EHLO after STARTTLS
				return
			}
			writeLine("250 fake.test")
		} else {
			writeLine("250 fake.test")
		}

		// Idle until the client closes the connection.
		_, _ = rw.ReadString('\n')
	}()

	return ln.Addr().String()
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestConnectSMTPWithMetadata_RequireTLSButNotSupported(t *testing.T) {
	addr := startFakeSMTPServer(t, false)
	h := NewSMTPDeliveryHandler(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, conn, tlsUsed, err := h.connectSMTPWithMetadata(ctx, addr, true)
	if err == nil {
		t.Fatal("expected error when STARTTLS is required but not supported by the server")
	}
	if client != nil || conn != nil {
		t.Fatal("expected no connection to be returned on failure")
	}
	if tlsUsed {
		t.Fatal("expected tlsUsed=false on failure")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected error to mention STARTTLS, got: %v", err)
	}
}

func TestConnectSMTPWithMetadata_STARTTLSNegotiationSucceeds(t *testing.T) {
	addr := startFakeSMTPServer(t, true)
	h := NewSMTPDeliveryHandler(0)
	h.insecureSkipVerify = true // fake server uses a self-signed certificate

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, conn, tlsUsed, err := h.connectSMTPWithMetadata(ctx, addr, true)
	if err != nil {
		t.Fatalf("expected successful STARTTLS negotiation, got error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if conn == nil {
		t.Fatal("expected a connection to be returned")
	}
	if !tlsUsed {
		t.Fatal("expected tlsUsed=true after successful STARTTLS negotiation")
	}
}

// stubMTASTSEnforcer is a test double for mtastsEnforcer that avoids making
// real DNS/HTTPS lookups and records how it was called.
type stubMTASTSEnforcer struct {
	err                    error
	calls                  int
	lastDomain, lastMXHost string
	lastTLSUsed            bool
}

func (s *stubMTASTSEnforcer) EnforcePolicy(ctx context.Context, domain, mxHost string, tlsUsed bool) error {
	s.calls++
	s.lastDomain = domain
	s.lastMXHost = mxHost
	s.lastTLSUsed = tlsUsed
	return s.err
}

// startFakeSMTPServerFullTransaction runs a minimal single-connection SMTP
// server that completes an entire EHLO/MAIL FROM/RCPT TO/DATA/QUIT exchange.
// It reports via mailFromSeen whether a MAIL FROM command was received.
func startFakeSMTPServerFullTransaction(t *testing.T, mailFromSeen *atomic.Bool) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake SMTP server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		writeLine := func(s string) {
			_, _ = rw.WriteString(s + "\r\n")
			_ = rw.Flush()
		}

		writeLine("220 fake.test ESMTP")
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(upper, "EHLO"):
				writeLine("250 fake.test")
			case strings.HasPrefix(upper, "MAIL FROM"):
				if mailFromSeen != nil {
					mailFromSeen.Store(true)
				}
				writeLine("250 OK")
			case strings.HasPrefix(upper, "RCPT TO"):
				writeLine("250 OK")
			case upper == "DATA":
				writeLine("354 End data with <CR><LF>.<CR><LF>")
				for {
					dataLine, err := rw.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(dataLine, "\r\n") == "." {
						break
					}
				}
				writeLine("250 OK")
			case upper == "QUIT":
				writeLine("221 Bye")
				return
			default:
				writeLine("500 unrecognized command")
			}
		}
	}()

	return ln.Addr().String()
}

func TestDeliverToAddressWithMetadata_MTASTSPolicyAllowsDelivery(t *testing.T) {
	var mailFromSeen atomic.Bool
	addr := startFakeSMTPServerFullTransaction(t, &mailFromSeen)

	h := NewSMTPDeliveryHandler(0)
	stub := &stubMTASTSEnforcer{}
	h.mtastsManager = stub

	msg := Message{ID: "msg-1", From: "sender@example.com", To: []string{"recipient@example.com"}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, "example.com", "mail.example.com")
	if err != nil {
		t.Fatalf("expected delivery to succeed when MTA-STS policy allows it, got: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("expected EnforcePolicy to be called once, got %d", stub.calls)
	}
	if stub.lastDomain != "example.com" || stub.lastMXHost != "mail.example.com" {
		t.Fatalf("EnforcePolicy called with unexpected domain/mxHost: %q/%q", stub.lastDomain, stub.lastMXHost)
	}
	if stub.lastTLSUsed {
		t.Fatal("expected tlsUsed=false since the fake server doesn't offer STARTTLS")
	}
	if !mailFromSeen.Load() {
		t.Fatal("expected MAIL FROM to be sent once the policy check passed")
	}
}

func TestDeliverToAddressWithMetadata_MTASTSPolicyViolationBlocksDelivery(t *testing.T) {
	var mailFromSeen atomic.Bool
	addr := startFakeSMTPServerFullTransaction(t, &mailFromSeen)

	h := NewSMTPDeliveryHandler(0)
	stub := &stubMTASTSEnforcer{err: errors.New("policy violation: TLS required but not used")}
	h.mtastsManager = stub

	msg := Message{ID: "msg-1", From: "sender@example.com", To: []string{"recipient@example.com"}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, "example.com", "mail.example.com")
	if err == nil {
		t.Fatal("expected delivery to fail when the MTA-STS policy check fails")
	}
	if !strings.Contains(err.Error(), "MTA-STS policy check failed") || !strings.Contains(err.Error(), "policy violation") {
		t.Fatalf("expected error to mention the MTA-STS policy failure, got: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("expected EnforcePolicy to be called once, got %d", stub.calls)
	}
	if mailFromSeen.Load() {
		t.Fatal("expected delivery to be blocked before MAIL FROM was ever sent")
	}
}
