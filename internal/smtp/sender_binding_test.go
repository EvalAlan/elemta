package smtp

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
)

func senderBindingHandler(t *testing.T, cfg *Config, login string) *CommandHandler {
	t.Helper()
	conn := fakeAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}}
	state := NewSessionState(slog.Default())
	if login != "" {
		state.SetAuthenticated(context.Background(), true, login)
	}
	session := &Session{config: cfg, logger: slog.Default(), state: state}
	return &CommandHandler{session: session, state: state, conn: conn, config: cfg, logger: slog.Default()}
}

func TestSenderBinding(t *testing.T) {
	cfg := &Config{
		LocalDomains: []string{"example.com", "Example.net"},
		Auth: &AuthConfig{
			Enabled: true,
			SenderAliases: map[string][]string{
				"Alice@example.com": {"sales@example.com", "@example.org"},
				"bob":               {"helpdesk@example.com"},
			},
		},
	}

	cases := []struct {
		login, from string
		ok          bool
	}{
		// Address logins own exactly themselves, case-insensitively.
		{"alice@example.com", "alice@example.com", true},
		{"alice@example.com", "ALICE@Example.com", true},
		{"alice@example.com", "ceo@example.com", false},
		{"alice@example.com", "alice@example.net", false},
		// Aliases: exact address and whole domain; keys match any case.
		{"alice@example.com", "sales@example.com", true},
		{"alice@example.com", "anyone@example.org", true},
		{"alice@example.com", "anyone@sub.example.org", false},
		// Bare logins own their local part at each local domain only.
		{"bob", "bob@example.com", true},
		{"bob", "bob@EXAMPLE.NET", true},
		{"bob", "bob@gmail.com", false},
		{"bob", "helpdesk@example.com", true},
		{"carol", "bob@example.com", false},
		// The null sender claims no one.
		{"alice@example.com", "", true},
	}
	for _, c := range cases {
		err := senderBindingHandler(t, cfg, c.login).checkSenderBinding(c.from)
		if (err == nil) != c.ok {
			t.Errorf("login %q MAIL FROM %q: err=%v, want ok=%v", c.login, c.from, err, c.ok)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "553 5.7.1") {
			t.Errorf("login %q MAIL FROM %q: want 553 5.7.1, got %q", c.login, c.from, err)
		}
	}
}

// Unauthenticated sessions (MX traffic, trusted-network relays) are not
// subject to the check: there is no login to compare against.
func TestSenderBindingSkipsUnauthenticated(t *testing.T) {
	cfg := &Config{LocalDomains: []string{"example.com"}, Auth: &AuthConfig{Enabled: true}}
	if err := senderBindingHandler(t, cfg, "").checkSenderBinding("anyone@elsewhere.test"); err != nil {
		t.Errorf("unauthenticated session checked: %v", err)
	}
}

func TestSenderBindingOptOut(t *testing.T) {
	cfg := &Config{LocalDomains: []string{"example.com"}, Auth: &AuthConfig{Enabled: true, AllowAnySender: true}}
	if err := senderBindingHandler(t, cfg, "alice@example.com").checkSenderBinding("ceo@example.com"); err != nil {
		t.Errorf("allow_any_sender did not disable the check: %v", err)
	}
}

// HandleMAIL refuses the mismatch before committing the envelope, so the
// session is still ready for a correct MAIL FROM.
func TestHandleMAILRefusesForeignSender(t *testing.T) {
	cfg := &Config{LocalDomains: []string{"example.com"}, Auth: &AuthConfig{Enabled: true}, MaxSize: 1 << 20}
	ch := senderBindingHandler(t, cfg, "alice@example.com")
	err := ch.HandleMAIL(context.Background(), "FROM:<ceo@example.com>")
	if err == nil || !strings.HasPrefix(err.Error(), "553 5.7.1") {
		t.Fatalf("foreign sender: got %v, want 553 5.7.1", err)
	}
	if got := ch.state.GetMailFrom(); got != "" {
		t.Errorf("refused sender left in session state: %q", got)
	}
}
