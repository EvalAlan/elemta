package mailpolicy

import (
	"strings"
	"testing"
)

func TestResolveOrderAndSources(t *testing.T) {
	q := func(v int64) *int64 { return &v }
	f := false
	eff := Resolve("dana@example.com", "staff",
		Layer{Name: "default class", Settings: Settings{QuotaBytes: q(1), Filters: &f}},
		Layer{Name: "domain class staff", Settings: Settings{QuotaBytes: q(2), Protocols: map[string]bool{POP3: false}}},
		Layer{Name: "account", Settings: Settings{QuotaBytes: q(3)}},
	)
	if eff.QuotaBytes != 3 || eff.Source["quota_bytes"] != "account" {
		t.Errorf("quota = %d from %q", eff.QuotaBytes, eff.Source["quota_bytes"])
	}
	if eff.Filters || eff.Allows(POP3) || !eff.Allows(IMAP) || !eff.ExternalForwarding {
		t.Errorf("effective = %+v", eff)
	}
	if b := Builtin(); !b.Allows(Submission) || b.QuotaBytes != 0 || b.RequireTwoFactor {
		t.Errorf("built-in defaults = %+v", b)
	}
}

func TestLargestAttachment(t *testing.T) {
	msg := "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("body ", 1000) + "\r\n" +
		"--b\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" + // 40 base64 chars = 30 bytes
		"--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=b.png\r\n\r\n" + strings.Repeat("p", 120) + "\r\n--b--\r\n"
	if got := LargestAttachment([]byte(msg)); got != 120 {
		t.Errorf("largest attachment = %d, want 120 (the body text is not an attachment)", got)
	}
	if got := LargestAttachment([]byte("Subject: plain\r\n\r\nno files\r\n")); got != 0 {
		t.Errorf("plain message = %d", got)
	}
}
