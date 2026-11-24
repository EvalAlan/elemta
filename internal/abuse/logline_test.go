package abuse

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func abuseLines(buf *bytes.Buffer) []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["event_type"] == "abuse" {
			out = append(out, m)
		}
	}
	return out
}

// Every recorded abuse event is one log line that says what happened and
// files its target where log shipping can place it: an address or network
// in client_ip (source.ip, GeoIP and ASN), an account in username.
func TestAbuseEventsAreLoggedOnce(t *testing.T) {
	ctx := context.Background()
	p := DefaultPolicy()
	p.FailuresPerAddress = 2
	p.OutboundRecipientsPerHour = 1
	var buf bytes.Buffer
	e := New("test", "", slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := e.Publish(ctx, p); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		e.Failure(ctx, "203.0.113.9:4000", "imap", "dana@example.com")
	}
	lines := abuseLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("a block made %d abuse lines, want 1: %v", len(lines), lines)
	}
	b := lines[0]
	if b["msg"] != "Address blocked" || b["level"] != "WARN" || b["abuse_action"] != "blocked" ||
		b["client_ip"] != "203.0.113.9" || b["protocol"] != "imap" {
		t.Errorf("block line %v", b)
	}

	buf.Reset()
	if _, err := e.BlockAddress(ctx, "2001:db8:1:2::7/64", "testing", "admin@example.com", time.Hour); err != nil {
		t.Fatal(err)
	}
	lines = abuseLines(&buf)
	if len(lines) != 1 || lines[0]["network"] != "2001:db8:1:2::/64" || lines[0]["client_ip"] != "2001:db8:1:2::" ||
		lines[0]["by"] != "admin@example.com" || lines[0]["protocol"] != nil {
		t.Errorf("manual block lines %v", lines)
	}

	buf.Reset()
	e.OutboundRecipient(ctx, "sam@example.com")
	e.OutboundRecipient(ctx, "sam@example.com")
	lines = abuseLines(&buf)
	if len(lines) != 1 || lines[0]["abuse_action"] != "held" || lines[0]["username"] != "sam@example.com" || lines[0]["client_ip"] != nil {
		t.Errorf("hold lines %v", lines)
	}
}

func TestAddressAttrs(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":        "203.0.113.9",
		"::ffff:203.0.113.9": "203.0.113.9",
		"203.0.113.0/24":     "203.0.113.0",
		"2001:db8::5/64":     "2001:db8::",
		"example.org":        "",
		"dana@example.com":   "",
	} {
		got := ""
		if a := addressAttrs(in); a != nil {
			got = a[3].(string)
		}
		if got != want {
			t.Errorf("addressAttrs(%q) client_ip = %q, want %q", in, got, want)
		}
	}
}
