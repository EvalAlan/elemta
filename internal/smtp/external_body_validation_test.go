package smtp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn is a net.Conn that only needs to answer RemoteAddr; nothing here
// reads or writes it.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c *fakeConn) RemoteAddr() net.Addr          { return c.remote }
func (c *fakeConn) LocalAddr() net.Addr           { return c.remote }
func (c *fakeConn) Close() error                  { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error { return nil }
func (c *fakeConn) Read(b []byte) (int, error)    { return 0, net.ErrClosed }
func (c *fakeConn) Write(b []byte) (int, error)   { return len(b), nil }

// externalDataHandler builds a DataHandler whose peer address is a public IP,
// so isInternalConnection reports false and the external content-analysis path
// runs.
//
// Every other test in this package connects over loopback, and the compose
// stack connects from a Docker 172.x address. Both are treated as internal and
// return early from performContentAnalysis, so nothing exercised the branch
// that real inbound mail from the internet takes.
func externalDataHandler(t *testing.T) *DataHandler {
	t.Helper()
	return &DataHandler{
		logger:            quietLogger(),
		conn:              &fakeConn{remote: &mockAddr{addr: "203.0.113.5:41234"}},
		config:            &Config{Hostname: "mail.example.com"},
		enhancedValidator: NewEnhancedValidator(quietLogger()),
	}
}

// TestExternalBodyOverLineLimitIsNotRejected pins the behaviour that matters
// for anything receiving mail from the internet.
//
// performContentAnalysis hands the whole message body to
// ValidateSMTPParameter("DATA_LINE", body). validateDataLineParameter applies
// the RFC 5321 *per-line* limit of 1000 octets to whatever it is given, so a
// body longer than that was reported as "line_too_long" with a
// "buffer_overflow_attempt" threat — which fails the scan and rejects the
// message.
//
// A 1000-byte ceiling on the body would reject essentially all real mail from
// external senders.
func TestExternalBodyOverLineLimitIsNotRejected(t *testing.T) {
	dh := externalDataHandler(t)

	// Ordinary message: short lines, body comfortably over 1000 bytes total.
	body := strings.Repeat("This is a perfectly ordinary line of message text.\r\n", 40)
	content := "Subject: ordinary mail\r\nFrom: sender@example.com\r\n\r\n" + body

	if len(body) <= 1000 {
		t.Fatalf("test body must exceed the 1000-octet line limit, got %d", len(body))
	}

	result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
	if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content)), result); err != nil {
		t.Fatalf("content analysis returned an error: %v", err)
	}

	if !result.Passed {
		t.Errorf("an ordinary %d-byte body from an external sender was rejected: %v",
			len(body), result.Threats)
	}
}

// TestExternalLongSingleLineStillRejectedAtReception shows the protection was
// not lost, only moved to the layer that always owned it: validateLineContent
// checks each line as it arrives, against the RFC 5321 limits.
func TestExternalLongSingleLineStillRejectedAtReception(t *testing.T) {
	dh := externalDataHandler(t)
	state := &DataReaderState{LineCount: 1}

	longLine := strings.Repeat("A", 5000) + "\r\n"
	err := dh.validateLineContent(context.Background(), longLine, state)
	if err == nil {
		t.Fatal("a 5000-octet line should be rejected at reception")
	}
	if !strings.Contains(err.Error(), "552") {
		t.Errorf("expected a 552 line-length rejection, got %v", err)
	}

	// And an ordinary line is still accepted.
	if err := dh.validateLineContent(context.Background(), "a normal line of text\r\n", state); err != nil {
		t.Errorf("ordinary line was rejected at reception: %v", err)
	}
}

// TestExternalControlCharsStillRejectedAtReception shows the protection the
// body-level pass shared with reception is intact: dangerous control
// characters are refused as the line arrives.
func TestExternalControlCharsStillRejectedAtReception(t *testing.T) {
	dh := externalDataHandler(t)
	state := &DataReaderState{LineCount: 5}

	err := dh.validateLineContent(context.Background(), "text with \x00\x01 nulls\r\n", state)
	if err == nil {
		t.Fatal("a line containing control characters should be rejected at reception")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected a 500 security rejection, got %v", err)
	}
}

// TestExternalForwardedMailIsAccepted is the deliverability case that decided
// how the body-level check was handled.
//
// Its injection patterns match a blank line followed by a header line, which
// is exactly the shape of a forwarded message or a quoted reply. Enforcing
// them would refuse ordinary mail, and they guard content that cannot become a
// header downstream, so the block check was dropped rather than enabled.
func TestExternalForwardedMailIsAccepted(t *testing.T) {
	bodies := map[string]string{
		"forwarded message": "Hi team, see below.\r\n\r\n" +
			"---------- Forwarded message ---------\r\n" +
			"From: alice@example.com\r\n" +
			"Subject: Q3 numbers\r\n\r\n" +
			"The numbers look good.\r\n",
		"quoted reply": "Thanks!\r\n\r\n" +
			"On Tuesday, Bob wrote:\r\n" +
			"To: me@example.com\r\n" +
			"> original text\r\n",
		"plain paragraphs": "First paragraph.\r\n\r\nSecond paragraph.\r\n\r\nThird.\r\n",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			dh := externalDataHandler(t)
			content := "Subject: probe\r\nFrom: sender@example.com\r\n\r\n" + body

			result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
			if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content)), result); err != nil {
				t.Fatalf("content analysis returned an error: %v", err)
			}
			if !result.Passed {
				t.Errorf("ordinary mail from an external sender was rejected: %v", result.Threats)
			}
		})
	}
}

// TestExternalOrdinaryMailIsAcceptedEndToEnd walks an ordinary external
// message through both layers: every line accepted at reception, and the
// assembled message passing content analysis.
func TestExternalOrdinaryMailIsAcceptedEndToEnd(t *testing.T) {
	dh := externalDataHandler(t)
	state := &DataReaderState{}

	lines := []string{
		"Subject: quarterly update\r\n",
		"From: sender@example.com\r\n",
		"To: recipient@example.com\r\n",
		"\r\n",
	}
	for i := 0; i < 60; i++ {
		lines = append(lines, "This is an ordinary sentence in an ordinary email body.\r\n")
	}

	var content strings.Builder
	for _, ln := range lines {
		state.LineCount++
		if err := dh.validateLineContent(context.Background(), ln, state); err != nil {
			t.Fatalf("ordinary line %d rejected at reception: %v", state.LineCount, err)
		}
		content.WriteString(ln)
	}

	if content.Len() <= 1000 {
		t.Fatalf("message must exceed 1000 octets to be meaningful, got %d", content.Len())
	}

	result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
	if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content.String())), result); err != nil {
		t.Fatalf("content analysis returned an error: %v", err)
	}
	if !result.Passed {
		t.Errorf("an ordinary %d-byte external message was rejected: %v", content.Len(), result.Threats)
	}
}
