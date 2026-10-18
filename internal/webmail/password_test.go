package webmail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type fakePasswords struct {
	current string
	changed []string
}

func (f *fakePasswords) ChangePassword(_ context.Context, user, current, next string) error {
	if current != f.current {
		return errWrongPassword
	}
	if strings.Contains(next, "rejectme") {
		return errPolicyRejected
	}
	f.current = next
	f.changed = append(f.changed, user)
	return nil
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)
	fp := &fakePasswords{current: "secret"}
	h.server.passwords = fp
	csrf := h.login()

	_, page := h.get("/settings/account")
	if !strings.Contains(page, `action="/settings/password#password"`) {
		t.Fatal("no password form when changes are configured")
	}
	post := func(cur, next, confirm string) *http.Response {
		return h.post("/settings/password", url.Values{"csrf": {csrf}, "current": {cur}, "new": {next}, "confirm": {confirm}})
	}
	for _, c := range []struct {
		cur, next, confirm string
		status             int
	}{
		{"secret", "correct horse battery", "correct horse batteryX", http.StatusBadRequest}, // mismatch
		{"secret", "short", "short", http.StatusBadRequest},                                  // too short
		{"secret", "dana-is-my-name-1", "dana-is-my-name-1", http.StatusBadRequest},          // contains user name
		{"secret", "secret", "secret", http.StatusBadRequest},                                // unchanged (also short)
		{"secret", "rejectme please 1", "rejectme please 1", http.StatusBadRequest},          // directory policy
	} {
		if resp := post(c.cur, c.next, c.confirm); resp.StatusCode != c.status {
			t.Errorf("%q -> %q: status %d, want %d", c.cur, c.next, resp.StatusCode, c.status)
		}
	}
	if len(fp.changed) != 0 {
		t.Fatal("a rejected change reached the directory")
	}

	resp := post("secret", "correct horse battery", "correct horse battery")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "password-changed") {
		t.Fatalf("change = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The session now holds the new password, for redialling IMAP.
	sess := onlySession(t, h)
	if pw, _ := h.server.sessions.password(sess); pw != "correct horse battery" {
		t.Fatalf("session password = %q", pw)
	}

	// Guessing the current password through this form is throttled.
	for i := 0; i < maxFailuresPerUser; i++ {
		post("guess", "another good one 1", "another good one 1")
	}
	if resp := post("correct horse battery", "another good one 1", "another good one 1"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong current passwords: %d, want 429", maxFailuresPerUser, resp.StatusCode)
	}
}

func TestPasswordFormHiddenWithoutLDAP(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, page := h.get("/settings/account")
	if strings.Contains(page, `action="/settings/password#password"`) {
		t.Fatal("password form shown without a directory configured")
	}
	if resp := h.post("/settings/password", url.Values{"csrf": {csrf}, "current": {"secret"}, "new": {"x"}, "confirm": {"x"}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func onlySession(t *testing.T, h *harness) *Session {
	t.Helper()
	m := h.server.sessions
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) != 1 {
		t.Fatalf("%d sessions", len(m.sessions))
	}
	for _, s := range m.sessions {
		return s
	}
	return nil
}
