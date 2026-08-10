package smtp

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Access control refuses mail, so every rule here is one an operator can lose
// legitimate messages with. The cases that matter most are the ones where a
// list quietly does not do what it looks like it does.

func mustAccessControl(t *testing.T, cfg *AccessControlConfig) *AccessControl {
	t.Helper()
	ac, err := NewAccessControl(cfg, quietLogger())
	if err != nil {
		t.Fatalf("build access control: %v", err)
	}
	return ac
}

func addr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}

func TestAccessControlDisabledDeniesNothing(t *testing.T) {
	for _, cfg := range []*AccessControlConfig{
		nil,
		{Enabled: false, DenyIPs: []string{"0.0.0.0/0"}},
	} {
		ac := mustAccessControl(t, cfg)
		if d := ac.CheckPeer(addr(t, "203.0.113.5:2525")); d.Denied {
			t.Error("a disabled or absent access control section must not refuse anything")
		}
		if d := ac.CheckSender("anyone@example.com"); d.Denied {
			t.Error("a disabled section must not refuse senders")
		}
	}
}

func TestAccessControlDeniesAndAllowsPeers(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled:  true,
		DenyIPs:  []string{"203.0.113.0/24", "198.51.100.7"},
		AllowIPs: []string{"203.0.113.9"},
	})

	cases := []struct {
		peer       string
		wantDenied bool
		why        string
	}{
		{"203.0.113.5:2525", true, "inside a denied range"},
		{"198.51.100.7:2525", true, "a bare address in the deny list"},
		{"198.51.100.8:2525", false, "a neighbour of a denied host is not denied"},
		{"203.0.113.9:2525", false, "an allow entry beats the denied range it sits inside"},
		{"192.0.2.1:2525", false, "an address in no list is allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if got := ac.CheckPeer(addr(t, tc.peer)).Denied; got != tc.wantDenied {
				t.Errorf("CheckPeer(%s) denied = %v, want %v (%s)", tc.peer, got, tc.wantDenied, tc.why)
			}
		})
	}
}

// TestAccessControlAllowBeatsDeny pins the precedence. The other order makes
// the lists unusable: permitting one host inside a denied /8 would mean
// enumerating the rest of it.
func TestAccessControlAllowBeatsDeny(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled:  true,
		DenyIPs:  []string{"10.0.0.0/8"},
		AllowIPs: []string{"10.1.2.3"},
	})
	if ac.CheckPeer(addr(t, "10.1.2.3:2525")).Denied {
		t.Error("an explicitly allowed host inside a denied range must be allowed")
	}
	if !ac.CheckPeer(addr(t, "10.1.2.4:2525")).Denied {
		t.Error("the rest of the denied range must still be denied")
	}
}

func TestAccessControlSenderDomains(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled:      true,
		DenyDomains:  []string{"spam.example"},
		AllowDomains: []string{"newsletter.spam.example"},
	})

	cases := []struct {
		sender     string
		wantDenied bool
		why        string
	}{
		{"a@spam.example", true, "the listed domain"},
		{"a@SPAM.EXAMPLE", true, "domains match case-insensitively"},
		{"<a@mail.spam.example>", true, "a subdomain of a denied domain, angle brackets and all"},
		{"a@newsletter.spam.example", false, "an allowed subdomain beats the denied parent"},
		{"a@example.com", false, "an unlisted domain"},
		{"", false, "the empty sender is the bounce path and is never refused"},
		{"<>", false, "the empty sender written out"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if got := ac.CheckSender(tc.sender).Denied; got != tc.wantDenied {
				t.Errorf("CheckSender(%q) denied = %v, want %v (%s)", tc.sender, got, tc.wantDenied, tc.why)
			}
		})
	}
}

// TestAccessControlDoesNotBlockWholeTLDs guards a footgun: walking a domain up
// to its parents must stop before a bare TLD, or an entry of "example.com"
// would end up matching on "com" and refuse everything.
func TestAccessControlDoesNotBlockWholeTLDs(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled:     true,
		DenyDomains: []string{"com"},
	})
	if ac.CheckSender("someone@example.com").Denied {
		t.Error("a bare TLD entry must not refuse every domain under it")
	}
}

func TestAccessControlRejectsMalformedRules(t *testing.T) {
	for _, cfg := range []*AccessControlConfig{
		{Enabled: true, DenyIPs: []string{"not-an-address"}},
		{Enabled: true, AllowIPs: []string{"10.0.0.0/33"}},
	} {
		if _, err := NewAccessControl(cfg, quietLogger()); err == nil {
			t.Errorf("a malformed rule must fail loudly, not be skipped: %+v", cfg)
		}
	}
}

// TestAccessControlIgnoresUnparseableAddresses: refusing mail because an
// address could not be parsed would be a denial on the strength of a bug.
func TestAccessControlIgnoresUnparseableAddresses(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled: true,
		DenyIPs: []string{"0.0.0.0/0"},
	})
	if ac.CheckPeer(nil).Denied {
		t.Error("a nil address must not be denied")
	}
}

func TestAccessControlAcceptsCIDRAndBareAddresses(t *testing.T) {
	ac := mustAccessControl(t, &AccessControlConfig{
		Enabled: true,
		DenyIPs: []string{"192.0.2.0/24", "2001:db8::1"},
	})
	if !ac.CheckPeer(addr(t, "192.0.2.44:25")).Denied {
		t.Error("CIDR entry did not match")
	}
	if !ac.CheckPeer(addr(t, "[2001:db8::1]:25")).Denied {
		t.Error("bare IPv6 entry did not match")
	}
	if ac.CheckPeer(addr(t, "[2001:db8::2]:25")).Denied {
		t.Error("a different IPv6 address must not match a single-host rule")
	}
}

// The unit tests above check the rules. These check that the rules are
// actually consulted by a running server — the gap where a correct matcher
// enforces nothing because it was never wired in.

func TestAccessControlRefusesDeniedSenderOverSMTP(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.AccessControl = &AccessControlConfig{
		Enabled:     true,
		DenyDomains: []string{"blocked.example"},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")

	if reply := p.cmd("MAIL FROM:<spammer@blocked.example>"); !strings.HasPrefix(reply, "550") {
		t.Errorf("a denied sender domain should be refused with 550, got %q", reply)
	}
	// A refused sender must leave the session usable for a permitted one.
	if reply := p.cmd("MAIL FROM:<real@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("an allowed sender should still be accepted after a refusal, got %q", reply)
	}
}

func TestAccessControlRefusesDeniedPeerAtConnect(t *testing.T) {
	cfg := createTestConfig(t)
	// Deny everything, which on a loopback listener means this client.
	cfg.AccessControl = &AccessControlConfig{
		Enabled: true,
		DenyIPs: []string{"0.0.0.0/0", "::/0"},
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", server.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	got := string(buf[:n])
	if !strings.Contains(got, "554") {
		t.Errorf("a denied peer should be refused at connect with 554, got %q", got)
	}
	if strings.Contains(got, "220") {
		t.Errorf("a denied peer must not be greeted: %q", got)
	}
}
