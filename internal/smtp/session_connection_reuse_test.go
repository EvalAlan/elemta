package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Connection reuse — several messages over one connection — is the normal case
// for any sending MTA, but nothing tested it. After a completed DATA the
// session dropped back to PhaseInit, the same state as before EHLO, so the
// next MAIL FROM was answered with "503 Bad sequence of commands". RSET had
// the same effect. A stress run with connection reuse enabled reported a 59%
// success rate because of it.
//
// These tests assert on response codes rather than merely on a response
// arriving, which is what let the defect through earlier.

// expectCode reads one response line and requires the given 3-digit code.
func expectCode(t *testing.T, reader *bufio.Reader, code, what string) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("%s: read failed: %v", what, err)
	}
	if !strings.HasPrefix(line, code) {
		t.Fatalf("%s: expected %s, got %q", what, code, strings.TrimSpace(line))
	}
}

// dialGreeted returns a connection that has completed EHLO.
func dialGreeted(t *testing.T, cfg *Config) (net.Conn, *bufio.Reader) {
	t.Helper()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := server.Addr(); addr != nil {
			if conn, err = net.Dial("tcp", addr.String()); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become reachable: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	mustWrite(t, conn, "EHLO test.example.com\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO response: %v", err)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	return conn, reader
}

// sendMessage runs one full transaction and requires it to be accepted.
func sendMessage(t *testing.T, conn net.Conn, reader *bufio.Reader, n int) {
	t.Helper()
	mustWrite(t, conn, fmt.Sprintf("MAIL FROM:<sender%d@example.com>\r\n", n))
	expectCode(t, reader, "250", fmt.Sprintf("message %d MAIL FROM", n))
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectCode(t, reader, "250", fmt.Sprintf("message %d RCPT TO", n))
	mustWrite(t, conn, "DATA\r\n")
	expectCode(t, reader, "354", fmt.Sprintf("message %d DATA", n))
	mustWrite(t, conn, fmt.Sprintf("Subject: message %d\r\n\r\nBody %d\r\n.\r\n", n, n))
	expectCode(t, reader, "250", fmt.Sprintf("message %d acceptance", n))
}

// TestConnectionReuse_MultipleMessages is the direct regression test.
func TestConnectionReuse_MultipleMessages(t *testing.T) {
	conn, reader := dialGreeted(t, strictTestConfig(t))

	for i := 1; i <= 3; i++ {
		sendMessage(t, conn, reader, i)
	}

	mustWrite(t, conn, "QUIT\r\n")
	expectCode(t, reader, "221", "QUIT")
}

// TestRSETAllowsNewTransaction covers the same defect reached via RSET, which
// RFC 5321 §4.1.1.5 defines as aborting the transaction, not the session.
func TestRSETAllowsNewTransaction(t *testing.T) {
	conn, reader := dialGreeted(t, strictTestConfig(t))

	mustWrite(t, conn, "MAIL FROM:<first@example.com>\r\n")
	expectCode(t, reader, "250", "first MAIL FROM")

	mustWrite(t, conn, "RSET\r\n")
	expectCode(t, reader, "250", "RSET")

	// Must be accepted without another EHLO.
	mustWrite(t, conn, "MAIL FROM:<second@example.com>\r\n")
	expectCode(t, reader, "250", "MAIL FROM after RSET")

	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectCode(t, reader, "250", "RCPT TO after RSET")
}

// TestRSETClearsPreviousSender makes sure restoring the phase did not also
// leave the aborted transaction's envelope behind.
func TestRSETClearsPreviousSender(t *testing.T) {
	conn, reader := dialGreeted(t, strictTestConfig(t))

	mustWrite(t, conn, "MAIL FROM:<first@example.com>\r\n")
	expectCode(t, reader, "250", "first MAIL FROM")
	mustWrite(t, conn, "RSET\r\n")
	expectCode(t, reader, "250", "RSET")

	// RCPT without a fresh MAIL FROM must fail: the envelope was cleared.
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectCode(t, reader, "503", "RCPT without MAIL FROM after RSET")
}

// TestMailFromRequiresGreeting confirms the fix did not make the server accept
// a transaction from a client that never greeted.
func TestMailFromRequiresGreeting(t *testing.T) {
	cfg := strictTestConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := server.Addr(); addr != nil {
			if conn, err = net.Dial("tcp", addr.String()); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become reachable: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	mustWrite(t, conn, "MAIL FROM:<sender@example.com>\r\n")
	expectCode(t, reader, "503", "MAIL FROM without EHLO")
}

// TestPipelinedSecondTransactionSucceeds is the pipelined form of connection
// reuse: the next transaction arrives in the same write as the terminator and
// must be accepted, not merely answered.
func TestPipelinedSecondTransactionSucceeds(t *testing.T) {
	conn, reader := dialGreeted(t, strictTestConfig(t))

	mustWrite(t, conn, "MAIL FROM:<first@example.com>\r\n")
	expectCode(t, reader, "250", "first MAIL FROM")
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectCode(t, reader, "250", "first RCPT TO")
	mustWrite(t, conn, "DATA\r\n")
	expectCode(t, reader, "354", "first DATA")

	// Terminator and the whole next transaction in one write.
	mustWrite(t, conn,
		"Subject: first\r\n\r\nBody\r\n.\r\n"+
			"MAIL FROM:<second@example.com>\r\nRCPT TO:<user@example.com>\r\n")

	expectCode(t, reader, "250", "first message acceptance")
	expectCode(t, reader, "250", "pipelined MAIL FROM")
	expectCode(t, reader, "250", "pipelined RCPT TO")
}
