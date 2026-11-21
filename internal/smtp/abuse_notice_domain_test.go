package smtp

import "testing"

// Alerts come from the domain the server's own host belongs to, not whatever
// domain happens to be listed first, which can be a test or alias subdomain
// with no SPF or DKIM of its own.
func TestNoticeDomain(t *testing.T) {
	for _, c := range []struct {
		host   string
		locals []string
		want   string
	}{
		{"mail.example.net", []string{"alias.test.example.org", "test.example.org", "example.net", "example.com"}, "example.net"},
		{"mail.Example.com.", []string{"example.com", "mail.example.com"}, "mail.example.com"},
		{"mx.other.org", []string{"first.example", "second.example"}, "first.example"},
		{"mx.other.org", nil, "mx.other.org"},
		{"", nil, "localhost"},
	} {
		s := &Server{config: &Config{Hostname: c.host, LocalDomains: c.locals}}
		if got := s.noticeDomain(); got != c.want {
			t.Errorf("%s %v: %q, want %q", c.host, c.locals, got, c.want)
		}
	}
}
