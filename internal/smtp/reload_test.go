package smtp

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Reload changes policy on a running server, so these tests are about the two
// ways that goes wrong: a change that does not take, and a change that lands in
// the middle of somebody's message.

func TestReloadAppliesNewPolicyToTheNextSession(t *testing.T) {
	cfg := createTestConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	// Nothing is refused to begin with.
	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	if reply := p.cmd("MAIL FROM:<someone@blocked.example>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("expected the sender to be accepted before the reload, got %q", reply)
	}

	// Same server, new policy, no restart.
	next := createTestConfig(t)
	next.AccessControl = &AccessControlConfig{
		Enabled:     true,
		DenyDomains: []string{"blocked.example"},
	}
	if err := server.Reload(context.Background(), next); err != nil {
		t.Fatalf("reload: %v", err)
	}

	fresh := dialProbe(t, server.Addr().String())
	fresh.cmd("EHLO probe.example")
	if reply := fresh.cmd("MAIL FROM:<someone@blocked.example>"); !strings.HasPrefix(reply, "550") {
		t.Errorf("the reloaded deny rule should refuse this sender, got %q", reply)
	}
	// And a sender the new policy permits still gets through, so the reload
	// changed the policy rather than breaking the server.
	if reply := fresh.cmd("MAIL FROM:<someone@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("an unlisted sender should still be accepted, got %q", reply)
	}
}

// TestReloadLeavesSessionsInFlightAlone is the reason reload exists rather than
// a restart. A session that has already been greeted keeps the policy it
// started under, so a message cannot be accepted under one configuration and
// judged under another.
func TestReloadLeavesSessionsInFlightAlone(t *testing.T) {
	cfg := createTestConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	// A session that is already open and mid-transaction.
	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	if reply := p.cmd("MAIL FROM:<someone@blocked.example>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("setup: sender should be accepted, got %q", reply)
	}

	next := createTestConfig(t)
	next.AccessControl = &AccessControlConfig{
		Enabled:     true,
		DenyDomains: []string{"blocked.example"},
	}
	if err := server.Reload(context.Background(), next); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The open session finishes under the policy it began with.
	if reply := p.cmd("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("a session in flight should not be disturbed by a reload, got %q", reply)
	}
	if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
		t.Errorf("the transaction should still be able to proceed, got %q", reply)
	}
}

// TestReloadRefusesInvalidConfigurationWithoutChangingAnything: a reload that
// half-applies is worse than one that is refused, and an operator who saves a
// broken rule should still have a server that delivers mail.
func TestReloadRefusesInvalidConfigurationWithoutChangingAnything(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.AccessControl = &AccessControlConfig{Enabled: true, DenyDomains: []string{"blocked.example"}}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	broken := createTestConfig(t)
	broken.AccessControl = &AccessControlConfig{Enabled: true, DenyIPs: []string{"not-an-address"}}
	// The RBL half is fine; the access control half is not. Neither may apply.
	broken.RBL = &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}}

	if err := server.Reload(context.Background(), broken); err == nil {
		t.Fatal("a configuration that cannot be built must be refused")
	}

	// The policy that was running is still running.
	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	if reply := p.cmd("MAIL FROM:<someone@blocked.example>"); !strings.HasPrefix(reply, "550") {
		t.Errorf("the previous deny rule should still be in force after a refused reload, got %q", reply)
	}
	// Read directly: there is no accessor for this, and nothing is reloading
	// concurrently here.
	if server.rblChecker.Enabled() {
		t.Error("the valid half of a refused reload was applied")
	}
}

// TestReloadIsSafeUnderTraffic covers the data race the accessors exist for:
// an operator saving a setting is exactly the moment connections are arriving.
// Run with -race, this fails without the lock.
func TestReloadIsSafeUnderTraffic(t *testing.T) {
	cfg := createTestConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	addr := server.Addr().String()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Connections arriving throughout. These deliberately make no assertions:
	// the point is to have the accept loop reading the policy while Reload
	// writes it, and a connection refused by the per-IP limit is the server
	// working, not a failure. Assertions here would also be reported from a
	// goroutine that is not the test's own.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 128)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("EHLO probe.example\r\n"))
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("MAIL FROM:<someone@example.com>\r\n"))
				_, _ = conn.Read(buf)
				_ = conn.Close()
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	// Reloads landing among them.
	for i := 0; i < 20; i++ {
		next := createTestConfig(t)
		next.AccessControl = &AccessControlConfig{
			Enabled:     i%2 == 0,
			DenyDomains: []string{"blocked.example"},
		}
		if err := server.Reload(context.Background(), next); err != nil {
			t.Errorf("reload %d: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(stop)
	wg.Wait()
}
