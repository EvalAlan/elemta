package api

import (
	"net"
	"strings"
	"testing"
)

// The admin API runs unauthenticated by default and the shipped container
// binds 0.0.0.0. Without a warning, that exposure — read any queued message,
// flush queues, rewrite config — is completely silent. These tests pin when
// the warning fires.

func TestUnauthenticatedExposureWarning(t *testing.T) {
	cases := []struct {
		name       string
		bound      net.Addr
		configured string
		wantWarn   bool
	}{
		{
			name:       "loopback IPv4 is safe",
			bound:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8025},
			configured: "127.0.0.1:8025",
			wantWarn:   false,
		},
		{
			name:       "loopback IPv6 is safe",
			bound:      &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8025},
			configured: "[::1]:8025",
			wantWarn:   false,
		},
		{
			name:       "all interfaces warns",
			bound:      &net.TCPAddr{IP: net.IPv4zero, Port: 8025},
			configured: "0.0.0.0:8025",
			wantWarn:   true,
		},
		{
			name:       "explicit external IP warns",
			bound:      &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 8025},
			configured: "10.1.2.3:8025",
			wantWarn:   true,
		},
		{
			name:       "unspecified via configured string warns",
			bound:      nil,
			configured: "0.0.0.0:8025",
			wantWarn:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unauthenticatedExposureWarning(tc.bound, tc.configured)
			if tc.wantWarn && got == "" {
				t.Errorf("expected a warning for %s, got none", tc.configured)
			}
			if !tc.wantWarn && got != "" {
				t.Errorf("expected no warning for %s, got: %s", tc.configured, got)
			}
			if got != "" && !strings.Contains(got, "SECURITY") {
				t.Errorf("warning should be recognisable as a security warning: %q", got)
			}
		})
	}
}
