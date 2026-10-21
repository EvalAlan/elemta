package smtp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/datasource"
	"github.com/stretchr/testify/require"
)

// AUTH LOGIN with the username as an initial response, as Python's smtplib
// sends it. The server used to prompt for a username regardless, read the
// password as the username, refuse the login, and log the password.
func TestAuthLoginInitialResponse(t *testing.T) {
	old := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = old })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(_ context.Context, u, p string) (bool, error) {
			return u == "dana@example.com" && p == "correct horse", nil
		}}, nil
	}
	cfg := createTestConfig(t)
	cfg.Auth = &AuthConfig{Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal"}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, flow := range []struct {
		name  string
		steps [][2]string // send, expected reply prefix
	}{
		{"initial response", [][2]string{{"AUTH LOGIN " + b64("dana@example.com"), "334"}, {b64("correct horse"), "235"}}},
		{"prompted", [][2]string{{"AUTH LOGIN", "334"}, {b64("dana@example.com"), "334"}, {b64("correct horse"), "235"}}},
	} {
		t.Run(flow.name, func(t *testing.T) {
			p := dialProbe(t, server.Addr().String())
			p.cmd("EHLO client.example")
			for _, step := range flow.steps {
				if got := p.cmd(step[0]); !strings.HasPrefix(got, step[1]) {
					t.Fatalf("%q -> %q, want %s", step[0], got, step[1])
				}
			}
		})
	}
}

func TestAuthArgumentsNeverReachTheLog(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("\x00dana@example.com\x00correct horse"))
	for _, line := range []string{"AUTH PLAIN " + secret, "auth plain " + secret, "AUTH LOGIN " + secret} {
		got := redactCommand(line) + (&CommandSecurityManager{}).SanitizeCommand(line)
		if strings.Contains(got, secret) {
			t.Errorf("credentials logged: %q", got)
		}
		if !strings.Contains(strings.ToUpper(got), "AUTH PLAIN") && !strings.Contains(strings.ToUpper(got), "AUTH LOGIN") {
			t.Errorf("mechanism lost: %q", got)
		}
	}
	if got := redactCommand("MAIL FROM:<a@example.com>"); got != "MAIL FROM:<a@example.com>" {
		t.Errorf("other commands changed: %q", got)
	}
}
