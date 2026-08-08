package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// The tests in session_pipelining_test.go all stop their pipelined group at
// DATA, so none of them exercised what happens to a command sent in the same
// write as the end-of-data marker. That was the one case ReadData got wrong:
// it discarded everything still buffered after the terminator, silently
// dropping the client's next command.

// dialDataPhase brings a connection up to the point where the server has
// answered 354 and is reading message content.
func dialDataPhase(t *testing.T, cfg *Config) (net.Conn, *bufio.Reader) {
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

	mustWrite(t, conn, "MAIL FROM:<sender@example.com>\r\n")
	expectPrefix(t, reader, "250", "MAIL FROM")
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectPrefix(t, reader, "250", "RCPT TO")
	mustWrite(t, conn, "DATA\r\n")
	expectPrefix(t, reader, "354", "DATA")

	return conn, reader
}

// TestPipelinedQUITAfterTerminator is the direct regression test: the QUIT
// arrives in the same TCP segment as the terminator and must still be answered.
// Before the fix the client got no 221 and the connection hung until timeout.
func TestPipelinedQUITAfterTerminator(t *testing.T) {
	conn, reader := dialDataPhase(t, strictTestConfig(t))

	mustWrite(t, conn, "Subject: test\r\n\r\nTest body\r\n.\r\nQUIT\r\n")

	expectPrefix(t, reader, "250", "message acceptance")

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("no response to the pipelined QUIT — it was dropped: %v", err)
	}
	if !strings.HasPrefix(line, "221") {
		t.Errorf("expected 221 for pipelined QUIT, got %q", strings.TrimSpace(line))
	}
}

// TestPipelinedSecondMessageAfterTerminator is the case with real consequences:
// a client that pipelines the start of its next transaction. Dropping the MAIL
// FROM leaves both sides waiting, and a client that times out and retries can
// deliver the first message twice.
func TestPipelinedSecondMessageAfterTerminator(t *testing.T) {
	conn, reader := dialDataPhase(t, strictTestConfig(t))

	mustWrite(t, conn,
		"Subject: first\r\n\r\nFirst body\r\n.\r\n"+
			"MAIL FROM:<sender@example.com>\r\nRCPT TO:<user@example.com>\r\n")

	expectPrefix(t, reader, "250", "first message acceptance")

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("pipelined MAIL FROM after terminator was dropped: %v", err)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("pipelined RCPT TO after terminator was dropped: %v", err)
	}
}

// TestQuotedPrintableHTMLDoesNotLeakIntoCommands reproduces the symptom that
// originally prompted the Discard workaround: HTML mail whose content was
// being parsed as SMTP commands ("td align=3D\"right\"").
//
// The cause was early end-of-data detection, not buffering. A message whose
// body contains a line that is a lone "." terminates DATA in legacy mode,
// after which the remainder is parsed as commands. With strict line endings
// the body is transferred intact and nothing leaks.
func TestQuotedPrintableHTMLDoesNotLeakIntoCommands(t *testing.T) {
	conn, reader := dialDataPhase(t, strictTestConfig(t))

	// A dot-stuffed lone "." line, followed by quoted-printable HTML of the
	// kind that showed up in the original "Invalid command name" reports.
	body := "Subject: html test\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"<table>\r\n" +
		"..\r\n" + // dot-stuffed "." line inside the body
		"<td align=3D\"right\">value</td>\r\n" +
		"</table>\r\n" +
		".\r\n"

	mustWrite(t, conn, body)

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("message should have been accepted, got %q", strings.TrimSpace(resp))
	}

	// Nothing from the body should have been interpreted as a command. If it
	// had been, the server would have written an extra error response here.
	mustWrite(t, conn, "QUIT\r\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read QUIT response: %v", err)
	}
	if !strings.HasPrefix(line, "221") {
		t.Errorf("expected 221 for QUIT, got %q — message content leaked into command parsing",
			strings.TrimSpace(line))
	}
}
