package smtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/queue"
	"github.com/EvalAlan/elemta/internal/srs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// srsServer is a server for example.com, and a client that arrives through a
// PROXY header from a public address. Loopback may always relay, so without
// this nothing here would test the relay rules at all.
func srsServer(t *testing.T, rewriter *srs.Rewriter) *smtpProbe {
	t.Helper()
	cfg := createTestConfig(t)
	cfg.LocalDomains = []string{"example.com"}
	cfg.AllowedRelays = nil
	cfg.DevMode = false
	cfg.ProxyProtocolFrom = []string{"127.0.0.1/32", "::1/128"}
	cfg.SRS = rewriter
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	require.Eventually(t, func() bool { return server.Addr() != nil }, 5*time.Second, 5*time.Millisecond)

	conn, err := net.DialTimeout("tcp", server.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Write([]byte("PROXY TCP4 203.0.113.9 198.51.100.1 40000 25\r\n"))
	require.NoError(t, err)
	p := &smtpProbe{t: t, conn: conn, r: bufio.NewReader(conn)}
	p.expect("220")
	p.cmd("EHLO remote.example")
	return p
}

// The rest of these tests mean nothing unless this client can't relay.
func TestSRSClientCannotRelay(t *testing.T) {
	p := srsServer(t, srs.New([]string{"secret"}))
	p.cmd("MAIL FROM:<someone@elsewhere.example>")
	if reply := p.cmd("RCPT TO:<victim@outside.example>"); strings.HasPrefix(reply, "250") {
		t.Fatalf("relayed for an outside client: %q", reply)
	}
}

func TestBounceToAnSRSAddressReachesTheOriginalSender(t *testing.T) {
	rewriter := srs.New([]string{"secret"})
	address, err := rewriter.Forward("alice@outside.example", "example.com")
	require.NoError(t, err)

	p := srsServer(t, rewriter)
	p.cmd("MAIL FROM:<>")
	if reply := p.cmd("RCPT TO:<" + address + ">"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("a bounce for a signed address: %q", reply)
	}
}

func TestSRSAddressesRefuseEverythingElse(t *testing.T) {
	rewriter := srs.New([]string{"secret"})
	good, err := rewriter.Forward("alice@outside.example", "example.com")
	require.NoError(t, err)
	forged, err := srs.New([]string{"guessed"}).Forward("victim@outside.example", "example.com")
	require.NoError(t, err)

	// Ordinary mail to a real address must not pass through to the sender.
	p := srsServer(t, rewriter)
	p.cmd("MAIL FROM:<someone@elsewhere.example>")
	if reply := p.cmd("RCPT TO:<" + good + ">"); !strings.HasPrefix(reply, "550 5.7.1") {
		t.Fatalf("ordinary mail to an SRS address: %q", reply)
	}
	p.cmd("RSET")

	// Without the secret, this would be an open relay.
	p.cmd("MAIL FROM:<>")
	if reply := p.cmd("RCPT TO:<" + forged + ">"); !strings.HasPrefix(reply, "550 5.1.1") {
		t.Fatalf("a forged address: %q", reply)
	}
}

// Only our own domains: anyone else's SRS address is just outside mail.
func TestSRSAddressAtAnotherDomainIsStillRelayChecked(t *testing.T) {
	rewriter := srs.New([]string{"secret"})
	address, err := rewriter.Forward("alice@outside.example", "elsewhere.example")
	require.NoError(t, err)

	p := srsServer(t, rewriter)
	p.cmd("MAIL FROM:<>")
	if reply := p.cmd("RCPT TO:<" + address + ">"); strings.HasPrefix(reply, "250") {
		t.Fatalf("relayed for another domain: %q", reply)
	}
}

func TestBounceOfForwardedMailGoesToTheOriginalSender(t *testing.T) {
	engine, mgr := newTestBounceEngine(t)
	engine.srs = srs.New([]string{"secret"})
	from, err := engine.srs.Forward("alice@outside.example", "example.com")
	require.NoError(t, err)

	id, err := mgr.EnqueueMessage(from, []string{"far@remote.example"}, "Forwarded",
		[]byte("From: alice@outside.example\r\nSubject: Forwarded\r\n\r\nbody\r\n"), queue.PriorityNormal, time.Now())
	require.NoError(t, err)
	result := engine.GenerateBounceIfNeeded(context.Background(), queue.Message{
		ID: id, From: from, To: []string{"far@remote.example"}, Subject: "Forwarded", CreatedAt: time.Now(),
	}, "550 5.1.1 User unknown")
	require.True(t, result.BounceGenerated)

	bounce, err := mgr.GetMessage(result.BounceID)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice@outside.example"}, bounce.To)
	assert.Empty(t, bounce.From)
}
