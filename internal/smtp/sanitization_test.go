package smtp

import (
	"strings"
	"testing"
)

func TestSanitizeHeloForHeader(t *testing.T) {
	cases := map[string]string{
		"mail.example.com":               "mail.example.com",
		"[192.0.2.1]":                    "[192.0.2.1]",
		"evil\r\nX-Injected: yes":        "evilX-Injected:yes",
		"name with (comment) and; semis": "namewithcommentandsemis",
		"[IPv6:2001:db8::1]":             "[IPv6:2001:db8::1]",
	}
	for in, want := range cases {
		if got := sanitizeHeloForHeader(in); got != want {
			t.Errorf("sanitizeHeloForHeader(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeHeloForHeader(strings.Repeat("a", 1000)); len(got) > 255 {
		t.Errorf("length %d not capped", len(got))
	}
}
