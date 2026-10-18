package smtp

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLMTP answers RCPT with 250 for known mailboxes and 550 otherwise, and
// counts probes.
func fakeLMTP(t *testing.T, known map[string]bool) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var probes int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				w("220 lmtp ready")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(line)
					switch {
					case strings.HasPrefix(cmd, "LHLO"):
						w("250-lmtp")
						w("250 PIPELINING")
					case strings.HasPrefix(cmd, "MAIL"):
						w("250 ok")
					case strings.HasPrefix(cmd, "RCPT"):
						atomic.AddInt32(&probes, 1)
						addr := strings.TrimSuffix(strings.TrimPrefix(cmd, "RCPT TO:<"), ">")
						if known[addr] {
							w("250 ok")
						} else {
							w("550 5.1.1 <" + addr + "> User doesn't exist")
						}
					case cmd == "QUIT":
						w("221 bye")
						return
					default:
						w("250 ok")
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), &probes
}

func TestRecipientVerifier(t *testing.T) {
	addr, probes := fakeLMTP(t, map[string]bool{"alice@example.com": true})
	v := newRecipientVerifier(addr, "mx.example.com", slog.Default())
	ctx := context.Background()

	if got, _ := v.Verify(ctx, "alice@example.com"); got != rcptExists {
		t.Errorf("existing mailbox: verdict %v", got)
	}
	if got, reply := v.Verify(ctx, "nobody@example.com"); got != rcptRejected || !strings.Contains(reply, "550") {
		t.Errorf("missing mailbox: verdict %v reply %q", got, reply)
	}
	before := atomic.LoadInt32(probes)
	v.Verify(ctx, "alice@example.com")
	v.Verify(ctx, "NOBODY@example.com")
	if atomic.LoadInt32(probes) != before {
		t.Error("cached answers were probed again")
	}
}

// An unreachable mailbox server must not refuse mail, and must not be retried
// on every RCPT while it is down.
func TestRecipientVerifierFailsOpenAndBacksOff(t *testing.T) {
	v := newRecipientVerifier("127.0.0.1:1", "mx.example.com", slog.Default())
	var dials int32
	v.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	now := time.Now()
	v.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if got, _ := v.Verify(context.Background(), "x@example.com"); got != rcptUnknown {
			t.Fatalf("verdict %v with the mailbox server down, want unknown (accept)", got)
		}
	}
	if dials != 1 {
		t.Errorf("dialled %d times during the backoff, want 1", dials)
	}
	now = now.Add(rcptProbeBackoff + time.Second)
	v.Verify(context.Background(), "x@example.com")
	if dials != 2 {
		t.Errorf("did not retry after the backoff (dials=%d)", dials)
	}
}

// Through a real SMTP session: an unknown local user is refused at RCPT.
func TestRCPTRefusesUnknownLocalMailbox(t *testing.T) {
	addr, _ := fakeLMTP(t, map[string]bool{"user@example.com": true})
	host, portStr, _ := net.SplitHostPort(addr)
	cfg := createTestConfig(t)
	cfg.LocalDomains = []string{"example.com"}
	if cfg.Delivery == nil {
		cfg.Delivery = &DeliveryConfig{}
	}
	cfg.Delivery.Mode = "lmtp"
	cfg.Delivery.Host = host
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	cfg.Delivery.Port = port

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<someone@outside.example>")
	if reply := p.cmd("RCPT TO:<nobody@example.com>"); !strings.HasPrefix(reply, "550 5.1.1") {
		t.Errorf("unknown local mailbox: got %q, want 550 5.1.1", reply)
	}
	if reply := p.cmd("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("existing local mailbox: got %q, want 250", reply)
	}
}

func TestRecipientVerifierProvisioningGeneration(t *testing.T) {
	addr, probes := fakeLMTP(t, map[string]bool{"alice@example.com": true})
	v := newRecipientVerifier(addr, "mx.example.com", slog.Default())
	generation := "initial"
	v.generation = func() string { return generation }
	ctx := context.Background()
	v.Verify(ctx, "alice@example.com")
	v.Verify(ctx, "missing@example.com")
	before := atomic.LoadInt32(probes)
	v.Verify(ctx, "alice@example.com")
	v.Verify(ctx, "missing@example.com")
	if atomic.LoadInt32(probes) != before {
		t.Fatal("cache unused before provisioning")
	}
	generation = "after-provisioning"
	v.Verify(ctx, "alice@example.com")
	v.Verify(ctx, "missing@example.com")
	if atomic.LoadInt32(probes) != before+2 {
		t.Fatal("provisioning did not invalidate both verdicts")
	}
}
