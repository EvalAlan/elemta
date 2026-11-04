package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/stretchr/testify/require"
)

// ruleServer is a server for example.com with these rules, and a dial function
// for a client that arrives through a PROXY header from address, because
// loopback is exempt from every rule.
func ruleServer(t *testing.T, rules ...abuse.Rule) func(address string) *smtpProbe {
	t.Helper()
	cfg := createTestConfig(t)
	cfg.LocalDomains = []string{"example.com"}
	cfg.AllowedRelays = []string{"203.0.113.50/32"}
	cfg.DevMode = false
	cfg.ProxyProtocolFrom = []string{"127.0.0.1/32", "::1/128"}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	p := abuse.DefaultPolicy()
	p.Rules = rules
	require.NoError(t, p.Validate())
	engine := abuse.New("test", "", nil)
	engine.Own(p)
	server.SetAbuse(engine)
	go func() { _ = server.Start() }()
	require.Eventually(t, func() bool { return server.Addr() != nil }, 5*time.Second, 5*time.Millisecond)

	return func(address string) *smtpProbe {
		conn, err := net.DialTimeout("tcp", server.Addr().String(), 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		_, err = conn.Write([]byte("PROXY TCP4 " + address + " 198.51.100.1 40000 25\r\n"))
		require.NoError(t, err)
		return &smtpProbe{t: t, conn: conn, r: bufio.NewReader(conn)}
	}
}

func TestDeniedClientIsRefusedOnSMTP(t *testing.T) {
	dial := ruleServer(t,
		abuse.Rule{Action: abuse.ActionDeny, Direction: abuse.DirectionInbound, Value: "203.0.113.0/24"},
		abuse.Rule{Action: abuse.ActionAllow, Direction: abuse.DirectionInbound, Value: "203.0.113.9"},
		abuse.Rule{Action: abuse.ActionDeny, Direction: abuse.DirectionInbound, Value: "192.0.2.1", Protocols: "imap"},
	)
	if reply := dial("203.0.113.7").readReply(); !strings.HasPrefix(reply, "554 5.7.1") {
		t.Errorf("denied client: %q", reply)
	}
	if reply := dial("203.0.113.9").readReply(); !strings.HasPrefix(reply, "220") {
		t.Errorf("allowed inside the denied range: %q", reply)
	}
	if reply := dial("192.0.2.1").readReply(); !strings.HasPrefix(reply, "220") {
		t.Errorf("a rule for IMAP stopped SMTP: %q", reply)
	}
}

func TestInboundSenderRule(t *testing.T) {
	dial := ruleServer(t, abuse.Rule{Action: abuse.ActionDeny, Direction: abuse.DirectionInbound, Value: "spam.example"})
	p := dial("198.51.100.20")
	p.expect("220")
	p.cmd("EHLO remote.example")
	if reply := p.cmd("MAIL FROM:<x@spam.example>"); !strings.HasPrefix(reply, "550 5.7.1") {
		t.Errorf("denied sender: %q", reply)
	}
	if reply := p.cmd("MAIL FROM:<x@fine.example>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("other sender: %q", reply)
	}
}

func TestOutboundRecipientRule(t *testing.T) {
	dial := ruleServer(t, abuse.Rule{Action: abuse.ActionDeny, Direction: abuse.DirectionOutbound, Value: "rival.example"})
	p := dial("203.0.113.50") // in allowed_relays, so it may send outside
	p.expect("220")
	p.cmd("EHLO app.example")
	p.cmd("MAIL FROM:<app@example.com>")
	if reply := p.cmd("RCPT TO:<x@rival.example>"); !strings.HasPrefix(reply, "550 5.7.1") {
		t.Errorf("denied recipient: %q", reply)
	}
	if reply := p.cmd("RCPT TO:<x@fine.example>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("other recipient: %q", reply)
	}
}

// An outbound rule on a domain is about mail leaving: mail from that domain
// still arrives.
func TestOutboundRuleLeavesInboundMailAlone(t *testing.T) {
	dial := ruleServer(t, abuse.Rule{Action: abuse.ActionDeny, Direction: abuse.DirectionOutbound, Value: "rival.example"})
	p := dial("198.51.100.20")
	p.expect("220")
	p.cmd("EHLO remote.example")
	if reply := p.cmd("MAIL FROM:<x@rival.example>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("inbound from an outbound-denied domain: %q", reply)
	}
}

// Mail from one outside address past its hourly limit is deferred, so a real
// server retries later; the deployment's own relays are left alone.
func TestInboundMessageLimitDefersMail(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.LocalDomains = []string{"example.com"}
	cfg.AllowedRelays = []string{"203.0.113.50/32"}
	cfg.DevMode = false
	cfg.ProxyProtocolFrom = []string{"127.0.0.1/32", "::1/128"}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	p := abuse.DefaultPolicy()
	p.MessagesPerAddressPerHour = 2
	p.MessagesPerDomainPerHour = 3
	engine := abuse.New("test", "", nil)
	engine.Own(p)
	server.SetAbuse(engine)
	go func() { _ = server.Start() }()
	require.Eventually(t, func() bool { return server.Addr() != nil }, 5*time.Second, 5*time.Millisecond)

	dial := func(address string) *smtpProbe {
		conn, err := net.DialTimeout("tcp", server.Addr().String(), 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		_, err = conn.Write([]byte("PROXY TCP4 " + address + " 198.51.100.1 40000 25\r\n"))
		require.NoError(t, err)
		p := &smtpProbe{t: t, conn: conn, r: bufio.NewReader(conn)}
		p.expect("220")
		p.cmd("EHLO remote.example")
		return p
	}
	outside := dial("198.51.100.20")
	for i := 0; i < 2; i++ {
		if reply := outside.cmd("MAIL FROM:<x@remote.example>"); !strings.HasPrefix(reply, "250") {
			t.Fatalf("message %d: %q", i+1, reply)
		}
		outside.cmd("RSET")
	}
	if reply := outside.cmd("MAIL FROM:<x@remote.example>"); !strings.HasPrefix(reply, "451 4.7.1") {
		t.Fatalf("over the limit: %q", reply)
	}
	// Another address claiming the same domain is under its own limit, but
	// the domain's is shared.
	other := dial("198.51.100.21")
	if reply := other.cmd("MAIL FROM:<y@remote.example>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("third from the domain: %q", reply)
	}
	other.cmd("RSET")
	if reply := other.cmd("MAIL FROM:<y@remote.example>"); !strings.HasPrefix(reply, "451 4.7.1") || !strings.Contains(reply, "domain") {
		t.Fatalf("fourth from the domain: %q", reply)
	}
	// An allowed relay is this deployment's own, and isn't counted.
	relay := dial("203.0.113.50")
	for i := 0; i < 4; i++ {
		if reply := relay.cmd("MAIL FROM:<app@example.com>"); !strings.HasPrefix(reply, "250") {
			t.Fatalf("allowed relay, message %d: %q", i+1, reply)
		}
		relay.cmd("RSET")
	}
}
