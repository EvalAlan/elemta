package smtp

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Protocol abuse suite.
//
// Two remotely exploitable desyncs (DATA in #98, BDAT here) shipped in a
// codebase with explicit anti-smuggling work, and the entire unit suite passed
// on both. They were found by pointing a raw socket and a real corpus at a
// running server. This file is that technique, kept.
//
// The invariant every test here defends is one sentence: **content the server
// accepted as message data must never be executed as SMTP commands.** That
// matters most when the party choosing the content is not the party writing
// the commands — an application sending mail with an attacker-supplied body.
// If the body can break out into commands, that attacker issues commands on
// the application's session: extra recipients, a forged envelope.
//
// Add a case here whenever a new path can refuse input the server has already
// committed to receiving.

// abuseCase is one hostile exchange and the responses it must never produce.
type abuseCase struct {
	name string
	// send is the raw conversation after EHLO/MAIL/RCPT, written verbatim.
	send []string
	// mustReject is a response fragment that must appear (the refusal itself).
	mustReject string
	// mustNotAppear are responses that would mean payload became commands.
	mustNotAppear []string
}

func TestProtocolAbuseDoesNotExecutePayloadAsCommands(t *testing.T) {
	// Payload lines shared by the cases: a complete forged transaction.
	forged := []string{
		"MAIL FROM:<attacker@evil.example>\r\n",
		"RCPT TO:<victim@example.com>\r\n",
		"DATA\r\n",
		"Subject: FORGED\r\n\r\ninjected\r\n.\r\n",
	}

	cases := []abuseCase{
		{
			name: "over-long DATA line then a forged transaction",
			send: append([]string{
				"DATA\r\n",
				"Subject: probe\r\n",
				"X-Pad: " + strings.Repeat("A", 128*1024) + "\r\n",
			}, forged...),
			mustReject: "5",
			// "Sender OK" and an acceptance are decisive: the legitimate
			// MAIL FROM and DATA replies were already consumed by cmd() above,
			// so anything matching here came from the payload.
			mustNotAppear: []string{"Sender OK", "Message accepted for delivery"},
		},
		{
			name: "oversized BDAT chunk then a forged transaction",
			send: append([]string{
				"BDAT 99999999\r\n",
			}, forged...),
			mustReject:    "552",
			mustNotAppear: []string{"Recipient OK", "Message accepted for delivery"},
		},
		{
			name: "BDAT declaring more than it sends, then commands",
			send: append([]string{
				"BDAT 4000\r\n",
				"short",
			}, forged...),
			mustNotAppear: []string{"Message accepted for delivery"},
		},
		{
			name: "dot-stuffed terminator lookalike does not end DATA early",
			send: []string{
				"DATA\r\n",
				"Subject: probe\r\n\r\n",
				"..\r\n", // stuffed content, not a terminator
				"MAIL FROM:<attacker@evil.example>\r\n",
				".\r\n",
			},
			mustNotAppear: []string{"Sender OK"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := startDesyncTestServer(t)
			p := dialProbe(t, server.Addr().String())

			p.cmd("EHLO probe.example")
			p.cmd("MAIL FROM:<sender@example.com>")
			if reply := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(reply, "250") {
				t.Fatalf("RCPT TO: %q", reply)
			}

			// A server that refuses (an oversized BDAT gets 552 and the
			// connection closed) can hang up while the forged commands are
			// still being written. That is the refusal these cases want,
			// so stop sending and judge what it said before closing.
			for _, chunk := range tc.send {
				if !p.trySend(chunk) {
					break
				}
			}

			got := p.drainFor(3 * time.Second)

			if tc.mustReject != "" && !strings.Contains(got, tc.mustReject) {
				t.Errorf("expected a refusal containing %q, got:\n%s", tc.mustReject, got)
			}
			for _, forbidden := range tc.mustNotAppear {
				if strings.Contains(got, forbidden) {
					t.Errorf("payload was executed as commands — response contained %q:\n%s",
						forbidden, got)
				}
			}
		})
	}
}

// TestPipelinedCommandsAfterRejectionStayInSync covers the pipelining case:
// a client may have several commands in flight when one is refused, and the
// refusal must not shift the server's idea of where the next command starts.
func TestPipelinedCommandsAfterRejectionStayInSync(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")

	// A bad recipient followed immediately by valid commands, all in one write.
	p.send("MAIL FROM:<sender@example.com>\r\n" +
		"RCPT TO:<not-an-address>\r\n" +
		"RSET\r\n" +
		"MAIL FROM:<second@example.com>\r\n")

	got := p.drainFor(2 * time.Second)

	// The final MAIL FROM must have been understood as a command, which only
	// happens if the rejection left the stream aligned.
	if strings.Count(got, "250") < 2 {
		t.Errorf("pipelined commands after a rejection were not processed in sync:\n%s", got)
	}
}

// TestOversizedDeclaredSizeIsRefusedBeforeData pins that a SIZE declaration
// beyond the limit is refused at MAIL FROM, so no body is ever invited.
func TestOversizedDeclaredSizeIsRefusedBeforeData(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	reply := p.cmd(fmt.Sprintf("MAIL FROM:<sender@example.com> SIZE=%d", int64(1)<<40))
	if strings.HasPrefix(reply, "250") {
		t.Errorf("a 1TB declared size should be refused at MAIL FROM, got %q", reply)
	}
}

// TestGarbageLinesCloseTheSessionAtTheErrorLimit pins the hard error limit.
// Internet scanners write binary at port 25 (TLS handshakes, other protocols'
// probes); every line is refused, and without a limit the server answered
// each one until the idle timeout.
func TestGarbageLinesCloseTheSessionAtTheErrorLimit(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	// Invalid UTF-8 plus control bytes. It must not start like a TLS
	// handshake, which is closed on the first line instead.
	junk := "\x00\x01\x02\xfc\x03\x03\xff\xfe\r\n"
	for i := 0; i < maxSessionErrors+5; i++ {
		if !p.trySend(junk) {
			break
		}
	}

	got := p.drainFor(3 * time.Second)
	if n := strings.Count(got, "500 5.5.2"); n != maxSessionErrors {
		t.Errorf("expected %d refusals before closing, got %d:\n%s", maxSessionErrors, n, got)
	}
	if !strings.Contains(got, "421 4.7.0 Too many errors") {
		t.Errorf("expected a 421 once the limit was reached, got:\n%s", got)
	}
}

// TestSessionBelowTheErrorLimitStaysUsable makes sure the limit is not hit by
// a client that makes mistakes but is still speaking SMTP.
func TestSessionBelowTheErrorLimitStaysUsable(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	p.cmd("EHLO probe.example")
	for i := 0; i < maxSessionErrors-1; i++ {
		if reply := p.cmd("NOSUCHCOMMAND"); !strings.HasPrefix(reply, "5") {
			t.Fatalf("unknown command %d: expected a 5xx refusal, got %q", i, reply)
		}
	}
	if reply := p.cmd("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("session should still accept commands below the limit, got %q", reply)
	}
}

// TestTLSHandshakeOnPlaintextPortIsClosedAtOnce covers a client that expects
// implicit TLS. Its ClientHello has no line feed and it then waits for a
// ServerHello, so without the check both sides sat until the command timeout.
func TestTLSHandshakeOnPlaintextPortIsClosedAtOnce(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	// Record header, then the start of a ClientHello; no CRLF anywhere.
	p.send("\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03")

	// drainFor returns early only when the server closes the connection, so
	// finishing well inside its window is the proof that it hung up.
	start := time.Now()
	got := p.drainFor(3 * time.Second)
	if strings.Contains(got, "500") {
		t.Errorf("a TLS handshake should be closed, not answered as commands:\n%s", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the server did not close the connection within %v; it waited for a line it would never get", elapsed)
	}
}

// TestFirstCommandIsNotEatenByTheTLSCheck makes sure peeking at the first
// bytes leaves a normal first command intact.
func TestFirstCommandIsNotEatenByTheTLSCheck(t *testing.T) {
	server := startDesyncTestServer(t)
	p := dialProbe(t, server.Addr().String())

	if reply := p.cmd("EHLO probe.example"); !strings.HasPrefix(reply, "250") {
		t.Errorf("EHLO after the TLS check: %q", reply)
	}
}

// TestRefusedBodyDrainHonoursStrictLineEndings pins that the drain after a
// mid-body refusal ends the message exactly where the strict reader would.
// Strict mode is the default; the shared test config uses legacy mode, where
// ".\n" is a terminator by design, so this builds its own server.
func TestRefusedBodyDrainHonoursStrictLineEndings(t *testing.T) {
	cfg := strictTestConfig(t)
	cfg.MaxSize = 4096
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")
	p.cmd("MAIL FROM:<sender@example.com>")
	if reply := p.cmd("RCPT TO:<rcpt@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RCPT TO: %q", reply)
	}
	if reply := p.cmd("DATA"); !strings.HasPrefix(reply, "354") {
		t.Fatalf("DATA: %q", reply)
	}
	p.trySend("Subject: probe\r\n\r\n" +
		strings.Repeat(strings.Repeat("A", 98)+"\r\n", 60) + // over max_size
		".\n" + // bare-LF dot: not a terminator in strict mode
		"MAIL FROM:<attacker@evil.example>\r\n" +
		"RCPT TO:<victim@example.com>\r\n" +
		"DATA\r\n" +
		"Subject: FORGED\r\n\r\ninjected\r\n.\r\n")

	got := p.drainFor(3 * time.Second)
	if !strings.Contains(got, "552") {
		t.Errorf("expected the oversized body to be refused, got:\n%s", got)
	}
	for _, forbidden := range []string{"Sender OK", "Recipient OK", "Message accepted for delivery"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("payload was executed as commands — response contained %q:\n%s", forbidden, got)
		}
	}
}
