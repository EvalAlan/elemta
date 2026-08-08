package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// These tests exercise RFC 5321 line-ending enforcement over a real socket.
//
// The unit tests in session_data_test.go cover validateLineEndings and
// isValidEndOfData directly. What they cannot show is that the enforcement is
// actually reachable from a live session — which for a long time it was not,
// because strict_line_endings could never be set to true in a shipped binary.
// These tests close that gap and pin the default.

// strictTestConfig returns a server config that leaves StrictLineEndings unset,
// so the test exercises whatever the production default resolves to.
func strictTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := createTestConfig(t)
	cfg.StrictLineEndings = nil
	cfg.ApplyDefaults()
	return cfg
}

// smtpTestConn starts a server and returns a connection sitting at the
// "ready for DATA payload" point, having already sent EHLO/MAIL/RCPT/DATA.
func smtpTestConn(t *testing.T, cfg *Config) (net.Conn, *bufio.Reader) {
	t.Helper()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	go func() { _ = server.Start() }()

	// Wait for the listener to come up rather than sleeping a fixed amount.
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		addr := server.Addr()
		if addr != nil {
			conn, err = net.Dial("tcp", addr.String())
			if err == nil {
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

	if _, err := reader.ReadString('\n'); err != nil { // greeting
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

func mustWrite(t *testing.T, conn net.Conn, s string) {
	t.Helper()
	if _, err := conn.Write([]byte(s)); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}

func expectPrefix(t *testing.T, reader *bufio.Reader, prefix, what string) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read %s response: %v", what, err)
	}
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("%s: expected %s response, got %q", what, prefix, strings.TrimSpace(line))
	}
	return line
}

// TestStrictLineEndings_DefaultsToEnabled is the regression test for the
// config-mapping bug: a server built from a config that says nothing about
// line endings must still enforce them.
func TestStrictLineEndings_DefaultsToEnabled(t *testing.T) {
	cfg := strictTestConfig(t)
	if !cfg.StrictLineEndingsEnabled() {
		t.Fatal("strict line endings must default to enabled")
	}
}

// TestStrictMode_RejectsBareLFInMessageBody covers the inbound half of the
// SMTP smuggling problem: a bare LF inside DATA must not be accepted, because
// a downstream server may treat it as a line terminator when we relay.
func TestStrictMode_RejectsBareLFInMessageBody(t *testing.T) {
	conn, reader := smtpTestConn(t, strictTestConfig(t))

	// Bare LF (no CR) in the body.
	mustWrite(t, conn, "Subject: test\r\n\r\nline one\nline two\r\n.\r\n")

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if strings.HasPrefix(resp, "250") {
		t.Errorf("bare LF in DATA was accepted in strict mode: %q", strings.TrimSpace(resp))
	}
	if !strings.HasPrefix(resp, "500") && !strings.HasPrefix(resp, "554") {
		t.Errorf("expected a 5xx rejection for bare LF, got %q", strings.TrimSpace(resp))
	}
}

// TestStrictMode_RejectsBareLFTerminator covers the classic smuggling vector:
// ".\n" must not be honoured as end-of-data when strict mode is on.
func TestStrictMode_RejectsBareLFTerminator(t *testing.T) {
	conn, reader := smtpTestConn(t, strictTestConfig(t))

	// "\n.\n" is the smuggling sequence: a server that accepts it ends the
	// message early, letting everything after it be injected as new commands.
	mustWrite(t, conn, "Subject: test\r\n\r\nbody\r\n.\n")

	// The bare LF must be rejected rather than treated as a terminator.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected a rejection response, got error: %v", err)
	}
	if strings.HasPrefix(resp, "250") {
		t.Errorf("bare LF terminator was honoured in strict mode: %q", strings.TrimSpace(resp))
	}
}

// TestLegacyMode_AcceptsBareLF documents the opt-out: operators who must
// interoperate with legacy senders can still turn enforcement off.
func TestLegacyMode_AcceptsBareLF(t *testing.T) {
	cfg := createTestConfig(t) // already sets StrictLineEndings to false
	cfg.ApplyDefaults()
	if cfg.StrictLineEndingsEnabled() {
		t.Fatal("explicit strict_line_endings=false should survive ApplyDefaults")
	}

	conn, reader := smtpTestConn(t, cfg)
	mustWrite(t, conn, "Subject: test\r\n\r\nline one\nline two\r\n.\r\n")

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Errorf("legacy mode should accept bare LF, got %q", strings.TrimSpace(resp))
	}
}
