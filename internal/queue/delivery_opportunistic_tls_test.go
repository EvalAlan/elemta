package queue

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMX is a multi-connection SMTP server with a certificate no client
// trusts, recording what each session saw.
type fakeMX struct {
	mu        sync.Mutex
	ehloNames []string
	delivered []bool // per accepted message: was it sent inside TLS?
}

func startFakeMX(t *testing.T, offerSTARTTLS bool) (*fakeMX, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cert := generateSelfSignedCert(t)
	mx := &fakeMX{}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go mx.serve(conn, cert, offerSTARTTLS)
		}
	}()
	return mx, ln.Addr().String()
}

func (mx *fakeMX) serve(conn net.Conn, cert tls.Certificate, offerSTARTTLS bool) {
	defer conn.Close()
	var c net.Conn = conn
	inTLS := false
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	write := func(s string) { _, _ = rw.WriteString(s + "\r\n"); _ = rw.Flush() }
	write("220 mx.test ESMTP")
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			mx.mu.Lock()
			mx.ehloNames = append(mx.ehloNames, strings.TrimSpace(line[5:]))
			mx.mu.Unlock()
			if offerSTARTTLS && !inTLS {
				write("250-mx.test")
				write("250 STARTTLS")
			} else {
				write("250 mx.test")
			}
		case cmd == "STARTTLS":
			write("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tc.Handshake(); err != nil {
				return // the client refused our certificate; it must reconnect
			}
			inTLS = true
			rw = bufio.NewReadWriter(bufio.NewReader(tc), bufio.NewWriter(tc))
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			write("250 ok")
		case cmd == "DATA":
			write("354 go")
			for {
				l, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			mx.mu.Lock()
			mx.delivered = append(mx.delivered, inTLS)
			mx.mu.Unlock()
			write("250 queued")
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func deliverToFakeMX(t *testing.T, h *SMTPDeliveryHandler, addr string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg := Message{ID: "m1", From: "a@sender.test", To: []string{"b@example.com"}}
	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"b@example.com"},
		[]byte("Subject: t\r\n\r\nbody\r\n"), false, "example.com", "mx.example.com")
	return err
}

// Most MX certificates do not validate for the MX name. Opportunistic TLS must
// still encrypt and deliver, on a fresh connection, and must not tell MTA-STS
// the certificate was valid.
func TestUnverifiableMXCertificateStillDeliversEncrypted(t *testing.T) {
	mx, addr := startFakeMX(t, true)
	h := NewSMTPDeliveryHandler(0)
	h.SetHeloHostname("mail.sender.test")
	stub := &stubMTASTSEnforcer{}
	h.mtastsManager = stub

	if err := deliverToFakeMX(t, h, addr); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	mx.mu.Lock()
	defer mx.mu.Unlock()
	if len(mx.delivered) != 1 || !mx.delivered[0] {
		t.Fatalf("delivered %v, want one message over TLS", mx.delivered)
	}
	if stub.calls != 1 || stub.lastTLSUsed {
		t.Errorf("MTA-STS saw verified=%v (%d calls); an unvalidated certificate must not count", stub.lastTLSUsed, stub.calls)
	}
	for _, name := range mx.ehloNames {
		if name != "mail.sender.test" {
			t.Errorf("EHLO %q, want the configured hostname", name)
		}
	}
}

// A server that advertises STARTTLS but cannot complete it is still reachable
// in plaintext, on a new connection.
func TestBrokenSTARTTLSFallsBackToPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	mx := &fakeMX{}
	broken := tls.Certificate{} // handshake always fails
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go mx.serve(conn, broken, true)
		}
	}()

	h := NewSMTPDeliveryHandler(0)
	h.mtastsManager = &stubMTASTSEnforcer{}
	h.SetHeloHostname("mail.sender.test")
	if err := deliverToFakeMX(t, h, ln.Addr().String()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	mx.mu.Lock()
	defer mx.mu.Unlock()
	if len(mx.delivered) != 1 || mx.delivered[0] {
		t.Fatalf("delivered %v, want one plaintext message", mx.delivered)
	}
}

func TestMXDeliveryUsesPort25Only(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	var dialed []string
	h.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, &net.OpError{Op: "dial", Err: errRefused}
	}
	_, _, _, _ = h.attemptDeliveryToHostWithMetadata(context.Background(), "mx.example.com",
		Message{ID: "m"}, []string{"b@example.com"}, []byte("x"), false, "example.com")
	if len(dialed) != 1 || dialed[0] != "mx.example.com:25" {
		t.Errorf("dialed %v, want only mx.example.com:25", dialed)
	}
}

var errRefused = &net.AddrError{Err: "connection refused", Addr: "test"}
