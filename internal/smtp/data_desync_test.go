package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startDesyncTestServer brings up a server on an ephemeral port, following the
// pattern used by the other socket-level tests in this package.
func startDesyncTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(createTestConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)
	return server
}

// Once the server answers DATA with 354, the connection is in data-transfer
// mode until <CRLF>.<CRLF>. A message rejected part-way through does not change
// that: the client is still sending the body.
//
// The server used to return to the command loop the moment it rejected a
// message, with the rest of the body still arriving, and parsed that body as
// SMTP commands. A sender could trip the rejection deliberately with one
// over-long line and have whatever it sent next executed — including a fresh
// MAIL FROM / RCPT TO / DATA, forging a message on a connection whose first
// message had just been refused.
//
// These tests drive a real server over a real socket, because the bug lives in
// the relationship between the data reader and the command loop.

// smtpProbe is a raw SMTP client that can send a body the server did not ask
// for, which no well-behaved client library will do.
type smtpProbe struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialProbe(t *testing.T, addr string) *smtpProbe {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	p := &smtpProbe{t: t, conn: conn, r: bufio.NewReader(conn)}
	p.expect("220")
	return p
}

// readReply reads one full SMTP reply, following multi-line continuations.
func (p *smtpProbe) readReply() string {
	p.t.Helper()
	var sb strings.Builder
	for {
		line, err := p.r.ReadString('\n')
		if err != nil {
			if sb.Len() == 0 {
				return fmt.Sprintf("<read error: %v>", err)
			}
			return sb.String()
		}
		sb.WriteString(line)
		// "250-" continues, "250 " terminates.
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) < 4 || trimmed[3] != '-' {
			return sb.String()
		}
	}
}

func (p *smtpProbe) send(s string) {
	p.t.Helper()
	if _, err := p.conn.Write([]byte(s)); err != nil {
		p.t.Fatalf("write %q: %v", truncate(s), err)
	}
}

func (p *smtpProbe) cmd(c string) string {
	p.t.Helper()
	p.send(c + "\r\n")
	return p.readReply()
}

func (p *smtpProbe) expect(prefix string) string {
	p.t.Helper()
	reply := p.readReply()
	if !strings.HasPrefix(reply, prefix) {
		p.t.Fatalf("expected reply starting %q, got %q", prefix, reply)
	}
	return reply
}

// drainFor collects everything the server sends within d, so the test can
// assert on what it did *not* say as well as what it did.
func (p *smtpProbe) drainFor(d time.Duration) string {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = p.conn.SetReadDeadline(time.Now().Add(30 * time.Second)) }()

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := p.conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			return sb.String()
		}
	}
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// TestRejectedMessageBodyIsNotExecutedAsCommands is the regression test for the
// injection. It rejects a message mid-body and then sends a complete forged
// transaction as body content. None of it may be acted on.
func TestRejectedMessageBodyIsNotExecutedAsCommands(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	if reply := p.cmd("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("MAIL FROM: %q", reply)
	}
	if reply := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RCPT TO: %q", reply)
	}
	if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA: %q", reply)
	}

	// A line past the hard limit rejects the message mid-body...
	p.send("Subject: probe\r\n")
	p.send("X-Pad: " + strings.Repeat("A", 128*1024) + "\r\n")
	// ...and everything after it is body content, not commands.
	p.send("MAIL FROM:<attacker@evil.example>\r\n")
	p.send("RCPT TO:<victim@example.com>\r\n")
	p.send("DATA\r\n")
	p.send("Subject: FORGED\r\n\r\ninjected\r\n")
	p.send(".\r\n")

	got := p.drainFor(3 * time.Second)

	// The rejection itself is expected and fine.
	if !strings.Contains(got, "552") && !strings.Contains(got, "554") && !strings.Contains(got, "500") {
		t.Errorf("expected the over-long line to be rejected, got:\n%s", got)
	}

	// What must never happen: the body being executed. A second "354" or an
	// acceptance means the forged transaction was processed.
	if strings.Contains(got, "354") {
		t.Errorf("server issued a DATA prompt for body content — message body was executed as commands:\n%s", got)
	}
	if strings.Contains(got, "250 2.0.0 Message accepted for delivery") {
		t.Errorf("server accepted a message forged from body content:\n%s", got)
	}
	if strings.Contains(got, "Recipient OK") {
		t.Errorf("server accepted a recipient from body content:\n%s", got)
	}
}

// TestRejectedMessageResynchronisesForLegitimateReuse checks the fix did not
// simply break connection reuse: after a rejection that *can* be drained, a
// well-behaved client that finishes its body may carry on.
func TestRejectedMessageResynchronisesForLegitimateReuse(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	p.cmd("RCPT TO:<rcpt@example.com>")
	if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA: %q", reply)
	}

	// Rejected mid-body, then the client correctly terminates the message.
	p.send("X-Pad: " + strings.Repeat("A", 128*1024) + "\r\n")
	p.send("some more body\r\n")
	p.send(".\r\n")

	reply := p.readReply()
	if strings.HasPrefix(reply, "250 2.0.0") {
		t.Fatalf("over-long line should have been rejected, got %q", reply)
	}

	// The connection is back at a command boundary, so a new transaction works.
	if got := p.cmd("RSET"); !strings.HasPrefix(got, "250") {
		t.Fatalf("RSET after a drained rejection: %q", got)
	}
	if got := p.cmd("MAIL FROM:<second@example.com>"); !strings.HasPrefix(got, "250") {
		t.Fatalf("MAIL FROM after a drained rejection: %q", got)
	}
}

// TestOrdinaryLongLinesAreAccepted pins the limit change. Real mail carries
// lines well past 1000 octets — unwrapped base64, long tracking URLs, DKIM and
// References headers. A 2000-octet cap refused about 5% of a real corpus.
func TestOrdinaryLongLinesAreAccepted(t *testing.T) {
	for _, size := range []int{1500, 4000, 26193} { // 26193 = longest seen in a real corpus
		t.Run(fmt.Sprintf("%d_octets", size), func(t *testing.T) {
			server := startDesyncTestServer(t)
			p := dialProbe(t, server.Addr().String())

			p.cmd("EHLO probe.example")
			p.cmd("MAIL FROM:<sender@example.com>")
			p.cmd("RCPT TO:<rcpt@example.com>")
			if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
				t.Fatalf("DATA: %q", reply)
			}

			p.send("Subject: long line\r\n")
			p.send("\r\n")
			p.send(strings.Repeat("x", size) + "\r\n")
			p.send(".\r\n")

			reply := p.readReply()
			if !strings.HasPrefix(reply, "250") {
				t.Errorf("a %d-octet line is ordinary mail and should be accepted, got %q", size, reply)
			}
		})
	}
}

// BDAT carries the same hazard as DATA in a different shape: the chunk follows
// the command immediately, with no server reply in between, so a refused BDAT
// leaves those octets in the stream. Reading them as commands lets content
// that an application treated as a message body issue SMTP commands on that
// application's session — adding recipients it never authorised.
//
// Confirmed against a running server before the fix:
//
//	BDAT 99999999                 -> 552 size exceeds maximum
//	RCPT TO:<victim@example.com>  -> 250 2.1.5 Recipient OK
//	BDAT 10 LAST / injected!      -> 250 2.0.0 Message accepted for delivery

func TestRefusedBDATChunkIsNotExecutedAsCommands(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	if reply := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RCPT TO: %q", reply)
	}

	// A chunk far larger than max_size is refused before it is read.
	p.send("BDAT 99999999\r\n")
	// These are chunk octets, not commands.
	p.send("RCPT TO:<victim@example.com>\r\n")
	p.send("BDAT 10 LAST\r\n")
	p.send("injected!\n")

	got := p.drainFor(3 * time.Second)

	if !strings.Contains(got, "552") {
		t.Errorf("expected the oversized chunk to be refused, got:\n%s", got)
	}
	if strings.Contains(got, "Recipient OK") {
		t.Errorf("a recipient was accepted from chunk content — the envelope gained "+
			"a recipient it never authorised:\n%s", got)
	}
	if strings.Contains(got, "Message accepted for delivery") {
		t.Errorf("a message was accepted from chunk content:\n%s", got)
	}
}

// TestRefusedSmallBDATChunkKeepsConnectionUsable pins that a chunk small enough
// to discard leaves the connection at a command boundary, rather than closing
// on every refusal.
func TestRefusedSmallBDATChunkKeepsConnectionUsable(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")

	// BDAT before any RCPT is refused with 503, and the chunk is discarded.
	p.send("BDAT 5\r\n")
	p.send("hello")

	reply := p.readReply()
	if !strings.HasPrefix(reply, "503") {
		t.Fatalf("expected 503 for BDAT without a recipient, got %q", reply)
	}

	// The five chunk octets must have been consumed, leaving the connection
	// at a command boundary.
	if got := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(got, "250") {
		t.Errorf("connection was not left at a command boundary after a refused chunk: %q", got)
	}
}
