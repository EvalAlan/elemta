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
	"fmt"
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
// a STARTTLS handshake using a self-signed certificate. If advertiseRequireTLS is
// true, it additionally advertises REQUIRETLS in the post-STARTTLS EHLO response
// (RFC 8689); it has no effect when offerSTARTTLS is false, matching real servers
// which only advertise REQUIRETLS once a TLS channel is established.
func startFakeSMTPServer(t *testing.T, offerSTARTTLS bool, advertiseRequireTLS bool) string {
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
			if advertiseRequireTLS {
				writeLine("250-fake.test")
				writeLine("250 REQUIRETLS")
			} else {
				writeLine("250 fake.test")
			}
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
	addr := startFakeSMTPServer(t, false, false)
	h := NewSMTPDeliveryHandler(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, conn, tlsUsed, _, err := h.connectSMTPWithRequireTLS(ctx, addr, true)
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
	// This must be a permanent error: RFC 8689 REQUIRETLS mail must never be
	// retried over an insecure channel, and a server that lacks STARTTLS
	// entirely will not gain it on the next retry.
	var permErr *PermanentError
	if !errors.As(err, &permErr) {
		t.Fatalf("expected a *PermanentError, got: %T", err)
	}
}

func TestConnectSMTPWithMetadata_STARTTLSNegotiationSucceeds(t *testing.T) {
	// Advertise REQUIRETLS post-STARTTLS since this test exercises requireTLS=true;
	// a mandatory-TLS delivery also requires next-hop REQUIRETLS support (RFC 8689 §4.2.1).
	addr := startFakeSMTPServer(t, true, true)
	h := NewSMTPDeliveryHandler(0)
	h.tlsConfig = &tls.Config{InsecureSkipVerify: true} // fake server uses a self-signed certificate

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, conn, tlsUsed, _, err := h.connectSMTPWithRequireTLS(ctx, addr, true)
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
	return startFakeSMTPServerFullTransactionTLS(t, mailFromSeen, nil, fullTransactionTLSOptions{})
}

// fullTransactionTLSOptions configures optional STARTTLS/REQUIRETLS support for
// startFakeSMTPServerFullTransactionTLS.
type fullTransactionTLSOptions struct {
	offerSTARTTLS       bool
	advertiseRequireTLS bool // only takes effect once TLS is established
}

// startFakeSMTPServerFullTransactionTLS is like startFakeSMTPServerFullTransaction
// but can additionally negotiate STARTTLS (and advertise REQUIRETLS afterwards)
// and reports the raw MAIL FROM command line via mailFromLine, if non-nil.
func startFakeSMTPServerFullTransactionTLS(t *testing.T, mailFromSeen *atomic.Bool, mailFromLine *atomic.Value, opts fullTransactionTLSOptions) string {
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

		tlsActive := false
		ehloResponse := func() {
			if tlsActive && opts.advertiseRequireTLS {
				writeLine("250-fake.test")
				writeLine("250 REQUIRETLS")
			} else if opts.offerSTARTTLS && !tlsActive {
				writeLine("250-fake.test")
				writeLine("250 STARTTLS")
			} else {
				writeLine("250 fake.test")
			}
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
				ehloResponse()
			case upper == "STARTTLS" && opts.offerSTARTTLS && !tlsActive:
				writeLine("220 Ready to start TLS")
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
				tlsActive = true
			case strings.HasPrefix(upper, "MAIL FROM"):
				if mailFromSeen != nil {
					mailFromSeen.Store(true)
				}
				if mailFromLine != nil {
					mailFromLine.Store(strings.TrimSpace(line))
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

	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, "example.com", "mail.example.com")
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

	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), false, "example.com", "mail.example.com")
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

// TestDeliverToAddressWithMetadata_RequireTLSSucceedsAndSkipsMTASTS verifies the
// success path for RFC 8689 enforcement: when the next hop offers STARTTLS and
// advertises REQUIRETLS post-STARTTLS, delivery completes over TLS, the outbound
// MAIL FROM carries the REQUIRETLS parameter, and the separate MTA-STS policy
// check is skipped entirely because REQUIRETLS is strictly stronger.
func TestDeliverToAddressWithMetadata_RequireTLSSucceedsAndSkipsMTASTS(t *testing.T) {
	var mailFromSeen atomic.Bool
	var mailFromLine atomic.Value
	addr := startFakeSMTPServerFullTransactionTLS(t, &mailFromSeen, &mailFromLine, fullTransactionTLSOptions{
		offerSTARTTLS:       true,
		advertiseRequireTLS: true,
	})

	h := NewSMTPDeliveryHandler(0)
	h.tlsConfig = &tls.Config{InsecureSkipVerify: true} // fake server uses a self-signed certificate
	stub := &stubMTASTSEnforcer{}
	h.mtastsManager = stub

	msg := Message{
		ID:          "msg-1",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Annotations: map[string]string{"require_tls": "true"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), true, "example.com", "mail.example.com")
	if err != nil {
		t.Fatalf("expected REQUIRETLS delivery to succeed when the next hop supports it, got: %v", err)
	}
	if !mailFromSeen.Load() {
		t.Fatal("expected MAIL FROM to be sent")
	}
	if line, _ := mailFromLine.Load().(string); !strings.Contains(strings.ToUpper(line), "REQUIRETLS") {
		t.Fatalf("expected outbound MAIL FROM to carry the REQUIRETLS parameter, got: %q", line)
	}
	if stub.calls != 0 {
		t.Fatalf("expected MTA-STS EnforcePolicy to be skipped when REQUIRETLS is active, got %d calls", stub.calls)
	}
}

// TestDeliverToAddressWithMetadata_RequireTLSButNextHopDoesNotAdvertiseIt covers
// RFC 8689 §4.2.1: even if the next hop supports STARTTLS, a relay must refuse to
// forward REQUIRETLS mail unless the next hop itself advertises REQUIRETLS.
func TestDeliverToAddressWithMetadata_RequireTLSButNextHopDoesNotAdvertiseIt(t *testing.T) {
	var mailFromSeen atomic.Bool
	addr := startFakeSMTPServerFullTransactionTLS(t, &mailFromSeen, nil, fullTransactionTLSOptions{
		offerSTARTTLS:       true,
		advertiseRequireTLS: false, // next hop supports TLS but not REQUIRETLS
	})

	h := NewSMTPDeliveryHandler(0)
	h.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	stub := &stubMTASTSEnforcer{}
	h.mtastsManager = stub

	msg := Message{
		ID:          "msg-1",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Annotations: map[string]string{"require_tls": "true"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), true, "example.com", "mail.example.com")
	if err == nil {
		t.Fatal("expected delivery to fail when the next hop does not advertise REQUIRETLS")
	}
	if !strings.Contains(err.Error(), "REQUIRETLS") {
		t.Fatalf("expected error to mention REQUIRETLS, got: %v", err)
	}
	var permErr *PermanentError
	if !errors.As(err, &permErr) {
		t.Fatalf("expected a *PermanentError so the message is bounced rather than retried, got: %T (%v)", err, err)
	}
	if mailFromSeen.Load() {
		t.Fatal("expected delivery to be refused before MAIL FROM was ever sent")
	}
}

// TestDeliverToAddressWithMetadata_RequireTLSRefusesCleartextDowngrade covers the
// no-downgrade requirement: a next hop that doesn't offer STARTTLS at all must
// never receive REQUIRETLS mail in cleartext.
func TestDeliverToAddressWithMetadata_RequireTLSRefusesCleartextDowngrade(t *testing.T) {
	var mailFromSeen atomic.Bool
	addr := startFakeSMTPServerFullTransactionTLS(t, &mailFromSeen, nil, fullTransactionTLSOptions{
		offerSTARTTLS: false,
	})

	h := NewSMTPDeliveryHandler(0)
	stub := &stubMTASTSEnforcer{}
	h.mtastsManager = stub

	msg := Message{
		ID:          "msg-1",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Annotations: map[string]string{"require_tls": "true"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _, err := h.deliverToAddressWithMetadata(ctx, addr, msg, []string{"recipient@example.com"}, []byte("Subject: test\r\n\r\nbody\r\n"), true, "example.com", "mail.example.com")
	if err == nil {
		t.Fatal("expected delivery to fail rather than downgrade to cleartext")
	}
	var permErr *PermanentError
	if !errors.As(err, &permErr) {
		t.Fatalf("expected a *PermanentError, got: %T (%v)", err, err)
	}
	if mailFromSeen.Load() {
		t.Fatal("expected delivery to be refused before MAIL FROM was ever sent (no cleartext fallback)")
	}
}

// TestIsTemporaryFailure_RequireTLSErrorsArePermanent confirms unmet REQUIRETLS
// requirements are always classified as permanent by the processor, regardless
// of how they're wrapped, so they are bounced and never retried insecurely.
func TestIsTemporaryFailure_RequireTLSErrorsArePermanent(t *testing.T) {
	p := &Processor{}

	errs := []error{
		newRequireTLSError("next-hop %s does not advertise REQUIRETLS", "mail.example.com:25"),
		fmt.Errorf("failed to connect to mail.example.com:25: %w", newRequireTLSError("STARTTLS required but not supported by server")),
	}
	for _, err := range errs {
		if p.isTemporaryFailure(err) {
			t.Errorf("expected REQUIRETLS error to be classified as permanent, got temporary for: %v", err)
		}
	}
}

// stubBounceEngine is a test double for BounceEngine that records whether a
// bounce was requested for a failed message.
type stubBounceEngine struct {
	calls  atomic.Int32
	result *BounceResult
}

func (s *stubBounceEngine) GenerateBounceIfNeeded(ctx context.Context, msg Message, failureReason string) *BounceResult {
	s.calls.Add(1)
	if s.result != nil {
		return s.result
	}
	return &BounceResult{BounceGenerated: true, BounceID: "bounce-1"}
}

// requireTLSFailureHandler is a minimal DeliveryHandler stub that always fails
// with the same permanent error a real SMTPDeliveryHandler would produce when
// RFC 8689 REQUIRETLS cannot be satisfied (e.g. next hop lacks REQUIRETLS).
// It reports a non-zero failed-queue retention so failed messages are moved to
// the failed queue (rather than deleted immediately), which the test asserts on.
type requireTLSFailureHandler struct{}

func (h *requireTLSFailureHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

func (h *requireTLSFailureHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	err := newRequireTLSError("next-hop mail.example.com:25 does not advertise REQUIRETLS")
	return &DeliveryResult{Success: false, Error: err}, err
}

func (h *requireTLSFailureHandler) GetFailedQueueRetentionHours() int { return 24 }

// TestProcessor_RequireTLSFailureBouncesWithoutRetry verifies the end-to-end
// wiring: a REQUIRETLS delivery failure is classified as permanent, moves the
// message straight to the failed queue (never deferred/retried), and triggers
// DSN bounce generation via the configured BounceEngine.
func TestProcessor_RequireTLSFailureBouncesWithoutRetry(t *testing.T) {
	queueDir := t.TempDir()
	manager := NewManager(queueDir, 24)
	defer manager.Stop()

	config := ProcessorConfig{
		Enabled:       true,
		Interval:      100 * time.Millisecond,
		MaxConcurrent: 2,
		MaxRetries:    3,
		RetrySchedule: []int{1, 2, 4},
		CleanupAge:    time.Hour,
	}

	handler := &requireTLSFailureHandler{}
	processor := NewProcessor(manager, config, handler)

	bounceEngine := &stubBounceEngine{}
	processor.SetBounceEngine(bounceEngine)

	msgID, err := manager.EnqueueMessage(
		"sender@example.com",
		[]string{"recipient@example.com"},
		"Test Subject",
		[]byte("Test message content"),
		PriorityNormal,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to enqueue message: %v", err)
	}
	if err := manager.SetAnnotation(msgID, "require_tls", "true"); err != nil {
		t.Fatalf("failed to set require_tls annotation: %v", err)
	}
	// Simulate that DSN was requested, so GenerateBounceIfNeeded actually builds a bounce.
	if err := manager.SetAnnotation(msgID, "dsn_return", "HDRS"); err != nil {
		t.Fatalf("failed to set dsn_return annotation: %v", err)
	}

	if err := processor.Start(); err != nil {
		t.Fatalf("failed to start processor: %v", err)
	}
	defer processor.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if bounceEngine.calls.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if calls := bounceEngine.calls.Load(); calls != 1 {
		t.Fatalf("expected bounce engine to be called exactly once, got %d", calls)
	}

	stats := manager.GetStats()
	if stats.DeferredCount != 0 {
		t.Fatalf("expected message to never be deferred/retried, got DeferredCount=%d", stats.DeferredCount)
	}
	if stats.FailedCount != 1 {
		t.Fatalf("expected message to land in the failed queue, got FailedCount=%d", stats.FailedCount)
	}
}
