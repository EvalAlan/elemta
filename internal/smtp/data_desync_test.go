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

// trySend writes s and reports whether it went out. After the server has
// refused an over-long line it closes the connection on purpose, and a write
// racing that close fails with "connection reset by peer". That is the
// server refusing to read further, the outcome these tests want, not a
// failure.
func (p *smtpProbe) trySend(s string) bool {
	_, err := p.conn.Write([]byte(s))
	return err == nil
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
	closed := !p.trySend("X-Pad: " + strings.Repeat("A", 128*1024) + "\r\n")
	// ...and everything after it is body content, not commands. The server
	// may already have hung up, which is as good as ignoring it.
	for _, line := range []string{"MAIL FROM:<attacker@evil.example>\r\n", "RCPT TO:<victim@example.com>\r\n", "DATA\r\n", "Subject: FORGED\r\n\r\ninjected\r\n", ".\r\n"} {
		if closed || !p.trySend(line) {
			closed = true
			break
		}
	}

	got := p.drainFor(3 * time.Second)

	// The rejection itself is expected and fine. A reset can discard it
	// in flight, so it is only required when the connection stayed open.
	if !closed && !strings.Contains(got, "552") && !strings.Contains(got, "554") && !strings.Contains(got, "500") {
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

// An overlong DATA line cannot be safely drained without letting a peer
// stream unbounded bytes, so the connection must close at that point.
func TestOverlongMessageClosesUnsynchronizedConnection(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	p.cmd("RCPT TO:<rcpt@example.com>")
	if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA: %q", reply)
	}

	// Rejected mid-body, then the client correctly terminates the message.
	// Writes after the over-long line may meet the server's close.
	_ = p.trySend("X-Pad: "+strings.Repeat("A", 128*1024)+"\r\n") && p.trySend("some more body\r\n") && p.trySend(".\r\n")

	reply := p.readReply()
	if strings.HasPrefix(reply, "250 2.0.0") {
		t.Fatalf("over-long line should have been rejected, got %q", reply)
	}

	_, _ = p.conn.Write([]byte("RSET\r\n"))
	if got := p.readReply(); strings.HasPrefix(got, "250") {
		t.Fatalf("overlong line left connection usable: %q", got)
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
	// These are chunk octets, not commands. The server gives up on a chunk
	// this large and closes the connection, so a write can lose that race.
	for _, chunk := range []string{"RCPT TO:<victim@example.com>\r\n", "BDAT 10 LAST\r\n", "injected!\n"} {
		if !p.trySend(chunk) {
			break
		}
	}

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

// Refusing MAIL leaves the session where BDAT isn't accepted at all, and that
// refusal has to consume the chunk too. A relay that forwards a stranger's mail
// sends the body straight after BDAT, so otherwise a crafted body issues
// commands on the relay's connection, with the relay's reputation.
func TestBDATRefusedBySessionPhaseIsNotExecutedAsCommands(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	if reply := p.cmd("MAIL FROM:<refused|sender@example.com>"); !strings.HasPrefix(reply, "5") {
		t.Fatalf("MAIL FROM: %q", reply)
	}

	body := "MAIL FROM:<forged@example.com>\r\nRCPT TO:<victim@example.com>\r\nBDAT 10 LAST\r\ninjected!\n"
	p.send(fmt.Sprintf("BDAT %d LAST\r\n%s", len(body), body))
	got := p.drainFor(2 * time.Second)

	if !strings.Contains(got, "503") {
		t.Errorf("expected the chunk to be refused, got:\n%s", got)
	}
	for _, accepted := range []string{"Sender OK", "Recipient OK", "accepted for delivery"} {
		if strings.Contains(got, accepted) {
			t.Errorf("chunk content ran as a command (%s):\n%s", accepted, got)
		}
	}
	if reply := p.cmd("NOOP"); !strings.HasPrefix(reply, "250") {
		t.Errorf("the connection isn't at a command boundary: %q", reply)
	}
}

// The senders that forwarding and bounce handling really use, through a whole
// transaction rather than one validator.
func TestSendersFromRealMailAreAccepted(t *testing.T) {
	for _, sender := range []string{
		"alan.denniston+caf_=alan=example.org@gmail.com",
		"bounces+5341422-7092-someone=gmail.com@cloudmail.example.com",
		"prvs=1234abcd=user@example.com",
		"SRS0=ab/c=TT=example.org=user@forwarder.example",
		"updates@linkedin.example",
		"o'brien@example.com",
	} {
		t.Run(sender, func(t *testing.T) {
			server := startDesyncTestServer(t)
			p := dialProbe(t, server.Addr().String())
			p.cmd("EHLO probe.example")
			if reply := p.cmd("MAIL FROM:<" + sender + "> SIZE=8034"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("MAIL FROM: %q", reply)
			}
			if reply := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("RCPT TO: %q", reply)
			}
			msg := "Subject: forwarded\r\n\r\nhello\r\n"
			p.send(fmt.Sprintf("BDAT %d LAST\r\n%s", len(msg), msg))
			if reply := p.readReply(); !strings.HasPrefix(reply, "250") {
				t.Fatalf("BDAT: %q", reply)
			}
		})
	}
}
