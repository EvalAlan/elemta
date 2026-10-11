package smtp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/authresult"
)

// TestVerifyAuthenticationIsBoundedByOneBudget: with DNS not answering, SPF
// and DMARC each ran to their own timeout one after the other, so a client at
// end-of-DATA waited for the sum. A stress run saw 20s replies against a 10s
// timeout. The whole step now waits at most the verifier's budget.
func TestVerifyAuthenticationIsBoundedByOneBudget(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	// A private resolver rather than a patched net.DefaultResolver: lookups
	// from other tests' goroutines read DefaultResolver's fields while they
	// run, so writing them here is a data race.
	stalled := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}

	// A real TCP peer, so SPF has a client address to check.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	const each = 500 * time.Millisecond
	session := NewSession(t.Context(), serverConn, &Config{Hostname: "mx.example"}, nil)
	session.SetAuthVerifier(authresult.New(authresult.Config{
		Enabled: true, SPFEnabled: true, DMARCEnabled: true,
		Timeout: each, SPFTimeout: each, DMARCTimeout: each,
		Resolver: stalled,
	}))

	message := []byte("From: a@stalled.example\r\nSubject: hi\r\n\r\nbody\r\n")
	start := time.Now()
	if err := session.VerifyAuthentication(t.Context(), "a@stalled.example", message); err != nil {
		t.Fatalf("VerifyAuthentication: %v", err)
	}
	// SPF then DMARC at 500ms each was 1s; one budget is 500ms.
	if elapsed := time.Since(start); elapsed > each+300*time.Millisecond {
		t.Errorf("verification took %v, want about %v", elapsed, each)
	}
}
