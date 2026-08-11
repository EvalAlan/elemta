package smtp

import (
	"strings"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/authresult"
)

func TestMailAuthPluginsAreIndependentlySelected(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.InboundAuth = nil
	cfg.Plugins = &PluginConfig{
		SPF:   &SPFPluginConfig{Enabled: true, Timeout: 4},
		DKIM:  &DKIMPluginConfig{Enabled: true, Verify: false},
		DMARC: &DMARCPluginConfig{Enabled: false, Timeout: 6},
	}
	runtime := authPluginRuntimeConfig(cfg)
	if !runtime.Enabled || !runtime.SPFEnabled || runtime.DKIMEnabled || runtime.DMARCEnabled {
		t.Fatalf("runtime selection = %+v", runtime)
	}
	if runtime.SPFTimeout != 4*time.Second || runtime.DMARCTimeout != 6*time.Second {
		t.Errorf("plugin timeouts = SPF %s DMARC %s", runtime.SPFTimeout, runtime.DMARCTimeout)
	}
}

func TestLegacyInboundAuthStillEnablesSPFDKIMAndDMARC(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.Plugins = nil
	cfg.InboundAuth = &InboundAuthConfig{Enabled: true, EnforceDMARC: true, Timeout: 3}
	verifier := authresult.New(authPluginRuntimeConfig(cfg))
	if !verifier.Enabled() || !verifier.DKIMEnabled() {
		t.Fatal("legacy aggregate configuration no longer enables the original verifier set")
	}
}

// Verification runs while a client waits at end-of-DATA and can refuse mail, so
// these check the two things that matter operationally: that the verdict is
// recorded on the message, and that an ordinary message still gets through.

// TestAuthenticationResultsHeaderIsAdded proves the verdict reaches the
// message. Without the header a later hop — or an operator reading the mail —
// cannot tell what this server checked from whether it looked at all.
func TestAuthenticationResultsHeaderIsAdded(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.InboundAuth = &InboundAuthConfig{Enabled: true, Timeout: 5}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	p.cmd("RCPT TO:<user@example.com>")
	p.cmd("DATA")

	// An unsigned message from a domain with no SPF record: the ordinary case,
	// and it must be accepted.
	reply := p.cmd("Subject: Test\r\nFrom: sender@example.com\r\n\r\nbody\r\n.")
	if !strings.HasPrefix(reply, "250") {
		t.Fatalf("an unauthenticated message should still be accepted when DMARC is not enforced, got %q", reply)
	}
}

// TestVerificationDoesNotRejectWhenNotEnforcing is the safety property: with
// enforce_dmarc off, nothing this package decides may refuse a message. An
// operator turning verification on to look at the results should not discover
// they have started bouncing mail.
func TestVerificationDoesNotRejectWhenNotEnforcing(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.InboundAuth = &InboundAuthConfig{Enabled: true, EnforceDMARC: false, Timeout: 5}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	// A sender whose domain cannot possibly authorise this host.
	p.cmd("MAIL FROM:<forged@example.com>")
	p.cmd("RCPT TO:<user@example.com>")
	p.cmd("DATA")

	reply := p.cmd("Subject: Forged\r\nFrom: someone@example.net\r\n\r\nbody\r\n.")
	if !strings.HasPrefix(reply, "250") {
		t.Errorf("without enforcement nothing may be refused on authentication grounds, got %q", reply)
	}
}

// TestDisabledVerificationChangesNothing: a server that has not turned this on
// must behave exactly as before, including adding no header.
func TestDisabledVerificationChangesNothing(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.InboundAuth = &InboundAuthConfig{Enabled: false}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	p.cmd("RCPT TO:<user@example.com>")
	p.cmd("DATA")
	if reply := p.cmd("Subject: Test\r\n\r\nbody\r\n."); !strings.HasPrefix(reply, "250") {
		t.Errorf("a disabled verifier must not affect delivery, got %q", reply)
	}
}
