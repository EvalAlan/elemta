package smtp

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Round-trip fidelity tests.
//
// These characterise what the server currently stores for a given submission,
// so that moving DATA off the heap and onto a spool file can be shown not to
// change a single byte. They are written against the existing in-memory
// implementation deliberately: a refactor is only safe if the behaviour it
// preserves has been pinned first.
//
// The interesting cases are the ones where SMTP framing and message content
// overlap — dot-stuffing, CRLF, 8-bit data, and a body line that looks like
// the end-of-data marker.

// submitMessage runs one transaction and returns the server's final response.
// body is written verbatim after the 354, so callers control the exact octets
// on the wire including the terminator.
func submitMessage(t *testing.T, conn net.Conn, reader *bufio.Reader, body string) string {
	t.Helper()

	mustWrite(t, conn, "MAIL FROM:<sender@example.com>\r\n")
	expectPrefix(t, reader, "250", "MAIL FROM")
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectPrefix(t, reader, "250", "RCPT TO")
	mustWrite(t, conn, "DATA\r\n")
	expectPrefix(t, reader, "354", "DATA")

	mustWrite(t, conn, body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	return strings.TrimSpace(line)
}

// storedContents returns every message body the queue has persisted.
func storedContents(t *testing.T, queueDir string) [][]byte {
	t.Helper()

	dataDir := filepath.Join(queueDir, "data")
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read queue data dir: %v", err)
	}

	var out [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dataDir, e.Name())) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatalf("read stored content %s: %v", e.Name(), err)
		}
		out = append(out, b)
	}
	return out
}

// waitForStoredMessage polls until exactly one message has been persisted.
// Enqueue completes before the 250 is written, but the file backend writes
// through a temp file and rename, so allow a moment for it to settle.
func waitForStoredMessage(t *testing.T, queueDir string) []byte {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		contents := storedContents(t, queueDir)
		if len(contents) == 1 {
			return contents[0]
		}
		if len(contents) > 1 {
			t.Fatalf("expected exactly one stored message, found %d", len(contents))
		}
		if time.Now().After(deadline) {
			t.Fatal("message was accepted but never appeared in the queue")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// roundTripCase describes a submission and the body octets the server is
// expected to have stored for it.
type roundTripCase struct {
	name string
	// wire is written verbatim after the 354, terminator included.
	wire string
	// wantBody is what should survive into the queue, after RFC 5321 §4.5.2
	// dot-unstuffing and with the terminator removed.
	wantBody string
}

func TestMessageRoundTrip_BodyIsStoredVerbatim(t *testing.T) {
	cases := []roundTripCase{
		{
			name:     "plain body",
			wire:     "Subject: plain\r\n\r\nhello world\r\n.\r\n",
			wantBody: "hello world\r\n",
		},
		{
			name:     "blank lines preserved",
			wire:     "Subject: blanks\r\n\r\nfirst\r\n\r\n\r\nlast\r\n.\r\n",
			wantBody: "first\r\n\r\n\r\nlast\r\n",
		},
		{
			name: "dot-stuffed leading period is unstuffed",
			// The client stuffs a body line that begins with a period.
			wire:     "Subject: stuffed\r\n\r\n..hidden\r\n.\r\n",
			wantBody: ".hidden\r\n",
		},
		{
			name:     "lone dot-stuffed period line",
			wire:     "Subject: lonedot\r\n\r\nbefore\r\n..\r\nafter\r\n.\r\n",
			wantBody: "before\r\n.\r\nafter\r\n",
		},
		{
			name:     "period mid-line untouched",
			wire:     "Subject: middot\r\n\r\nfoo.bar\r\n.\r\n",
			wantBody: "foo.bar\r\n",
		},
		{
			name:     "8-bit content survives",
			wire:     "Subject: utf8\r\n\r\nnaïve café — €5\r\n.\r\n",
			wantBody: "naïve café — €5\r\n",
		},
		{
			name:     "long line near the RFC limit",
			wire:     "Subject: long\r\n\r\n" + strings.Repeat("x", 900) + "\r\n.\r\n",
			wantBody: strings.Repeat("x", 900) + "\r\n",
		},
		{
			name:     "many lines",
			wire:     "Subject: many\r\n\r\n" + strings.Repeat("line\r\n", 500) + ".\r\n",
			wantBody: strings.Repeat("line\r\n", 500),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := strictTestConfig(t)
			queueDir := cfg.QueueDir

			conn, reader := dialGreeted(t, cfg)
			resp := submitMessage(t, conn, reader, tc.wire)
			if !strings.HasPrefix(resp, "250") {
				t.Fatalf("message was not accepted: %s", resp)
			}

			stored := string(waitForStoredMessage(t, queueDir))

			if !strings.HasSuffix(stored, tc.wantBody) {
				t.Errorf("stored body does not match what was sent\n  want suffix: %q\n  stored tail: %q",
					tc.wantBody, tail(stored, len(tc.wantBody)+64))
			}
			if strings.Contains(stored, "\r\n.\r\n") && !strings.Contains(tc.wantBody, "\r\n.\r\n") {
				t.Errorf("end-of-data marker leaked into stored content: %q", tail(stored, 96))
			}
		})
	}
}

// TestMessageRoundTrip_HeadersArePrependedNotRewritten checks that the trace
// headers the server adds go in front of the submission rather than being
// merged into it.
//
// Two things depend on this. RFC 5321 §4.4 requires the Received record at the
// top of the mail data, so that a multi-hop trace reads newest-first; the
// server used to splice its headers in below the sender's, reversing that
// order. And prepending is what will let the body be streamed from a spool
// file: the submission is never parsed or rebuilt, just written after the
// headers this hop contributes.
func TestMessageRoundTrip_HeadersArePrependedNotRewritten(t *testing.T) {
	cfg := strictTestConfig(t)
	queueDir := cfg.QueueDir

	conn, reader := dialGreeted(t, cfg)
	resp := submitMessage(t, conn, reader,
		"Subject: trace test\r\nX-Client-Marker: keep-me\r\n\r\nbody text\r\n.\r\n")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("message was not accepted: %s", resp)
	}

	stored := string(waitForStoredMessage(t, queueDir))

	for _, want := range []string{"Subject: trace test", "X-Client-Marker: keep-me", "body text"} {
		if !strings.Contains(stored, want) {
			t.Errorf("stored message lost %q", want)
		}
	}
	if !strings.HasSuffix(stored, "body text\r\n") {
		t.Errorf("body is not the tail of the stored message: %q", tail(stored, 64))
	}

	// RFC 5321 §4.4: this hop's trace record goes at the very top.
	if !strings.HasPrefix(stored, "Received: from ") {
		t.Errorf("Received is not the first header: %q", head(stored, 96))
	}

	// The submission must survive byte-for-byte below the added block, which
	// is what makes it streamable rather than something to parse and rebuild.
	const submitted = "Subject: trace test\r\nX-Client-Marker: keep-me\r\n\r\nbody text\r\n"
	if !strings.HasSuffix(stored, submitted) {
		idx := strings.Index(stored, "Subject: trace test")
		got := stored
		if idx >= 0 {
			got = stored[idx:]
		}
		t.Errorf("submission was rewritten rather than preserved verbatim:\n  want tail: %q\n  got:       %q", submitted, got)
	}

	// The added block must be a contiguous run of headers ending immediately
	// before the submission, not interleaved with it.
	if idx := strings.Index(stored, submitted); idx > 0 {
		added := stored[:idx]
		if strings.Contains(added, "\r\n\r\n") {
			t.Errorf("added headers contain a blank line, so the submission is not the message body: %q", added)
		}
	}
}

// TestMessageRoundTrip_RejectedMessageIsNotStored pins the negative case: a
// submission the server refuses must leave nothing behind. Once DATA is
// spooled to a file this becomes the test that catches orphaned spool files.
func TestMessageRoundTrip_RejectedMessageIsNotStored(t *testing.T) {
	cfg := strictTestConfig(t)
	queueDir := cfg.QueueDir

	conn, reader := dialGreeted(t, cfg)

	// Bare LF is refused in strict mode.
	resp := submitMessage(t, conn, reader, "Subject: bad\r\n\r\nline one\nline two\r\n.\r\n")
	if strings.HasPrefix(resp, "250") {
		t.Fatalf("expected a rejection, got %s", resp)
	}

	// Give any stray write a chance to land before asserting.
	time.Sleep(200 * time.Millisecond)
	if contents := storedContents(t, queueDir); len(contents) != 0 {
		t.Errorf("rejected message left %d file(s) in the queue", len(contents))
	}
}

// TestMessageRoundTrip_ClientDisconnectMidDataStoresNothing covers the abort
// path: the connection drops after the headers but before the terminator.
func TestMessageRoundTrip_ClientDisconnectMidDataStoresNothing(t *testing.T) {
	cfg := strictTestConfig(t)
	queueDir := cfg.QueueDir

	conn, reader := dialGreeted(t, cfg)

	mustWrite(t, conn, "MAIL FROM:<sender@example.com>\r\n")
	expectPrefix(t, reader, "250", "MAIL FROM")
	mustWrite(t, conn, "RCPT TO:<user@example.com>\r\n")
	expectPrefix(t, reader, "250", "RCPT TO")
	mustWrite(t, conn, "DATA\r\n")
	expectPrefix(t, reader, "354", "DATA")

	// Partial message, then drop the connection without a terminator.
	mustWrite(t, conn, "Subject: truncated\r\n\r\npartial body\r\n")
	_ = conn.Close()

	time.Sleep(300 * time.Millisecond)
	if contents := storedContents(t, queueDir); len(contents) != 0 {
		t.Errorf("aborted transfer left %d file(s) in the queue", len(contents))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
