package smtp

import "testing"

func TestOriginatingIP(t *testing.T) {
	for in, want := range map[string]string{
		"[203.0.113.9]":         "203.0.113.9",
		" [203.0.113.9] ":       "203.0.113.9",
		"203.0.113.9":           "203.0.113.9",
		"[2001:db8::1]":         "2001:db8::1",
		"[::ffff:203.0.113.9]":  "203.0.113.9",
		"":                      "",
		"[unknown]":             "",
		"203.0.113.9, 10.0.0.1": "",
		"[203.0.113.9]:443":     "",
	} {
		if got := originatingIP(in); got != want {
			t.Errorf("originatingIP(%q) = %q, want %q", in, got, want)
		}
	}
}
