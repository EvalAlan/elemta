package smtp

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// headerFromHandler is a DataHandler for a session signed in as login (or
// not signed in, for ""), connecting from remote.
func headerFromHandler(t *testing.T, login, remote string) *DataHandler {
	t.Helper()
	cfg := &Config{LocalDomains: []string{"example.com", "other.example"}, AllowedRelays: []string{"10.0.0.0/8"}}
	ch := senderBindingHandler(t, cfg, login)
	ch.conn = fakeAddrConn{remote: &net.TCPAddr{IP: net.ParseIP(remote), Port: 40000}}
	ch.session.commandHandler = ch
	return &DataHandler{session: ch.session, state: ch.state, config: cfg, logger: slog.Default()}
}

// A signed-in user may only put addresses they own in From. Binding just the
// envelope let any user send as anyone in their domain, with a DKIM signature
// that aligned with the forged From.
func TestHeaderFromMustBeOwnedBySignedInUser(t *testing.T) {
	cases := []struct {
		name string
		head string
		ok   bool
	}{
		{"own address", "From: Alice <alice@example.com>\r\nSubject: hi\r\n\r\n", true},
		{"own address, no display name", "From: alice@example.com\r\n\r\n", true},
		{"no From at all", "Subject: hi\r\n\r\n", true},
		{"colleague", "From: CEO <ceo@example.com>\r\n\r\n", false},
		{"other hosted domain", "From: alice@other.example\r\n\r\n", false},
		{"second From field", "From: alice@example.com\r\nFrom: ceo@example.com\r\n\r\n", false},
		{"several addresses in one field", "From: alice@example.com, ceo@example.com\r\n\r\n", false},
		{"behind a malformed line", "Subject: hi\r\nnot a header line\r\nFrom: ceo@example.com\r\n\r\n", false},
		{"folded", "From: CEO\r\n <ceo@example.com>\r\n\r\n", false},
		{"unparseable", "From: <<<\r\n\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := headerFromHandler(t, "alice@example.com", "203.0.113.9").checkHeaderFrom(context.Background(), []byte(tc.head))
			if tc.ok && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.ok && (err == nil || !strings.HasPrefix(err.Error(), "5")) {
				t.Errorf("expected a 5xx refusal, got %v", err)
			}
		})
	}
}

// Mail from outside, and from the operator's own relays, isn't held to a
// login: it has none.
func TestHeaderFromIgnoredWithoutSignIn(t *testing.T) {
	dh := headerFromHandler(t, "", "203.0.113.9")
	if err := dh.checkHeaderFrom(context.Background(), []byte("From: ceo@example.com\r\n\r\n")); err != nil {
		t.Errorf("unauthenticated session checked: %v", err)
	}
}

// Delivery may sign a null-sender message by its From only when that From was
// vouched for: a signed-in user's (checked above), or the operator's own
// relays' auto-replies. Never a Sieve forward, which carries someone else's
// From, and never mail from outside.
func TestMayLaterSignFromHeader(t *testing.T) {
	plain := []byte("From: ceo@example.com\r\n\r\n")
	forwarded := []byte(sieveRedirectHeader + ": alice@example.com\r\nFrom: ceo@example.com\r\n\r\n")
	cases := []struct {
		name          string
		login, remote string
		mailFrom      string
		head          []byte
		want          bool
	}{
		{"signed-in user, null sender", "alice@example.com", "203.0.113.9", "", plain, true},
		{"outside sender, null sender", "", "203.0.113.9", "", plain, false},
		{"own relay, auto-reply", "", "10.0.0.5", "", plain, true},
		{"own relay, Sieve forward", "", "10.0.0.5", "", forwarded, false},
		{"envelope sender present", "alice@example.com", "203.0.113.9", "alice@example.com", plain, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := headerFromHandler(t, tc.login, tc.remote).mayLaterSignFromHeader(tc.head, tc.mailFrom); got != tc.want {
				t.Errorf("mayLaterSignFromHeader = %v, want %v", got, tc.want)
			}
		})
	}
}

// The verdict the MTA writes for the mailbox service: a signed-in user's
// single, already-bound From address; nothing for mail it didn't verify.
func TestSenderVerdict(t *testing.T) {
	head := []byte("From: Alice <Alice@Example.com>\r\n\r\n")
	if got := headerFromHandler(t, "alice@example.com", "203.0.113.9").senderVerdict(head); got != "auth alice@example.com" {
		t.Errorf("signed in: %q", got)
	}
	if got := headerFromHandler(t, "alice@example.com", "203.0.113.9").senderVerdict([]byte("From: a@example.com, b@example.com\r\n\r\n")); got != "none" {
		t.Errorf("two From addresses: %q", got)
	}
	if got := headerFromHandler(t, "", "203.0.113.9").senderVerdict(head); got != "none" {
		t.Errorf("not signed in, nothing verified: %q", got)
	}
}
