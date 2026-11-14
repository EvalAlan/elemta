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

// The MX port takes mail for local domains from anyone and relays for no
// one, so it takes no logins either: AUTH there only offered password
// guessing a port that can't be closed to it, and a login there skipped the
// blocklists and opened relaying. Logins belong on the submission listeners.
func TestMXListenerTakesNoLogins(t *testing.T) {
	old := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = old })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(_ context.Context, u, p string) (bool, error) {
			return u == "dana@example.com" && p == "correct horse", nil
		}}, nil
	}
	start := func(t *testing.T, mxAuth bool) *Server {
		cfg := createTestConfig(t)
		cfg.LocalDomains = []string{"example.com"}
		cfg.Auth = &AuthConfig{Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal"}
		cfg.SubmissionAddr = "127.0.0.1:0"
		cfg.MXAuth = mxAuth
		server, err := NewServer(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = server.Close() })
		go func() { _ = server.Start() }()
		time.Sleep(150 * time.Millisecond)
		return server
	}
	login := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00dana@example.com\x00correct horse"))

	t.Run("MX listener", func(t *testing.T) {
		server := start(t, false)
		p := dialProbe(t, server.Addr().String())
		if r := p.cmd("EHLO client.example"); strings.Contains(r, "AUTH") {
			t.Errorf("EHLO offers AUTH on the MX port:\n%s", r)
		}
		if r := p.cmd(login); !strings.HasPrefix(r, "503 5.5.1") {
			t.Fatalf("AUTH on the MX port: %q, want 503 5.5.1", r)
		}
		// Local mail still goes through, and a trusted network (the probe
		// connects from loopback) still relays. Anyone else can't relay
		// here now that no one can sign in (relay_policy_test.go covers that).
		require.True(t, strings.HasPrefix(p.cmd("MAIL FROM:<sender@remote.example>"), "250"))
		if r := p.cmd("RCPT TO:<dana@example.com>"); !strings.HasPrefix(r, "250") {
			t.Errorf("local recipient on the MX port: %q", r)
		}
		if r := p.cmd("RCPT TO:<someone@remote.example>"); !strings.HasPrefix(r, "250") {
			t.Errorf("trusted relay on the MX port: %q", r)
		}
	})
	t.Run("MX listener after STARTTLS", func(t *testing.T) {
		state := NewSessionState(quietLogger())
		state.SetTLSActive(context.Background(), true)
		cfg := &Config{LocalDomains: []string{"example.com"}, Auth: &AuthConfig{Enabled: true}}
		session := &Session{state: state, logger: quietLogger(), config: cfg}
		ch := &CommandHandler{session: session, state: state, config: cfg, logger: quietLogger()}
		if ch.takesLogins() {
			t.Error("the MX listener takes logins with TLS up")
		}
		cfg.MXAuth = true
		if !ch.takesLogins() {
			t.Error("mx_auth = true doesn't open logins on the MX listener")
		}
		session.submission, cfg.MXAuth = true, false
		if !ch.takesLogins() {
			t.Error("the submission listener refuses logins")
		}
	})
	t.Run("submission listener", func(t *testing.T) {
		server := start(t, false)
		p := dialProbe(t, server.getSubmissionListener().Addr().String())
		if r := p.cmd("EHLO client.example"); !strings.Contains(r, "AUTH") {
			t.Errorf("EHLO doesn't offer AUTH on the submission port:\n%s", r)
		}
		if r := p.cmd(login); !strings.HasPrefix(r, "235") {
			t.Fatalf("AUTH on the submission port: %q", r)
		}
		require.True(t, strings.HasPrefix(p.cmd("MAIL FROM:<dana@example.com>"), "250"))
		if r := p.cmd("RCPT TO:<someone@remote.example>"); !strings.HasPrefix(r, "250") {
			t.Errorf("signed-in relay on the submission port: %q", r)
		}
	})
	t.Run("mx_auth opt-in", func(t *testing.T) {
		server := start(t, true)
		p := dialProbe(t, server.Addr().String())
		p.cmd("EHLO client.example")
		if r := p.cmd(login); !strings.HasPrefix(r, "235") {
			t.Fatalf("AUTH on the MX port with mx_auth: %q", r)
		}
	})
}

// A login excuses a client from the blocklists on the submission port, where
// users sign in from listed residential addresses, but not on the MX port
// with mx_auth on.
func TestBlocklistsSkipOnlySubmissionLogins(t *testing.T) {
	old := newAuthDataSource
	t.Cleanup(func() { newAuthDataSource = old })
	newAuthDataSource = func(datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{authenticateFn: func(_ context.Context, u, p string) (bool, error) {
			return u == "dana@example.com" && p == "correct horse", nil
		}}, nil
	}
	cfg := createTestConfig(t)
	cfg.LocalDomains = []string{"example.com"}
	cfg.Auth = &AuthConfig{Enabled: true, DataSourceName: "ldap", DataSourceHost: "ldap.internal"}
	cfg.SubmissionAddr = "127.0.0.1:0"
	cfg.MXAuth = true
	cfg.RBL = &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	resolver := newFakeResolver()
	resolver.listEverythingIn = "bl.example.org"
	server.rblChecker.resolver = resolver
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	login := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00dana@example.com\x00correct horse"))
	for _, tc := range []struct {
		name, addr, want string
	}{
		{"submission", server.getSubmissionListener().Addr().String(), "250"},
		{"MX with mx_auth", server.Addr().String(), "554"},
	} {
		p := dialProbe(t, tc.addr)
		p.cmd("EHLO client.example")
		if r := p.cmd(login); !strings.HasPrefix(r, "235") {
			t.Fatalf("%s: AUTH %q", tc.name, r)
		}
		if r := p.cmd("MAIL FROM:<dana@example.com>"); !strings.HasPrefix(r, tc.want) {
			t.Errorf("%s: signed-in MAIL from a listed address got %q, want %s", tc.name, r, tc.want)
		}
	}
}
