package smtp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/datasource"
	"github.com/stretchr/testify/require"
)

// An AUTH reply longer than the reader's buffer used to be taken in part,
// leaving the rest to be read as commands. Each line is now taken whole, and
// one over RFC 4954's 12288 octets is refused; either way the next command
// is answered as itself.
func TestAuthExchangeLongLinesStayInStep(t *testing.T) {
	old := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = old })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(context.Context, string, string) (bool, error) { return false, nil }}, nil
	}
	cfg := createTestConfig(t)
	cfg.SubmissionAddr = "127.0.0.1:0" // logins are taken on the submission listener only
	cfg.Auth = &AuthConfig{Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal"}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	for _, tc := range []struct {
		name, start string
		size        int
		want        string
	}{
		{"PLAIN, 6000 octets", "AUTH PLAIN", 6000, "535"},
		{"PLAIN, over the limit", "AUTH PLAIN", 20000, "500 5.5.6"},
		{"LOGIN username, over the limit", "AUTH LOGIN", 20000, "500 5.5.6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dialProbe(t, server.getSubmissionListener().Addr().String())
			p.cmd("EHLO client.example")
			if r := p.cmd(tc.start); !strings.HasPrefix(r, "334") {
				t.Fatalf("%s: %q", tc.start, r)
			}
			if r := p.cmd(strings.Repeat("Q", tc.size)); !strings.HasPrefix(r, tc.want) {
				t.Fatalf("long line: got %q, want %s", r, tc.want)
			}
			if r := p.cmd("NOOP"); !strings.HasPrefix(r, "250") {
				t.Fatalf("NOOP after the long line: %q (the rest of the line was read as commands)", r)
			}
		})
	}
}
