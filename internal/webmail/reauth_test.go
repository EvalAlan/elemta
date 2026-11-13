package webmail

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A webmail session alone mustn't be enough to set up access that outlives
// it: app passwords and forwarding need the current account password.
func TestLastingAccessNeedsTheCurrentPassword(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	fake := &fakeMailSettings{}
	h.server.mailSettings = fake
	csrf := h.login()

	for _, pw := range []string{"", "wrong", "app-pass"} {
		resp := h.post("/settings/app-passwords", url.Values{"csrf": {csrf}, "name": {"Phone"}, "current_password": {pw}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("app password with current_password %q: %d, want 403", pw, resp.StatusCode)
		}
		resp = h.post("/settings/forwarding", url.Values{"csrf": {csrf}, "forward": {"out@remote.example"}, "current_password": {pw}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("forwarding with current_password %q: %d, want 403", pw, resp.StatusCode)
		}
	}
	if len(f.created) != 0 || len(fake.mail.Forward) != 0 {
		t.Fatalf("saved without the password: app passwords %v, forwarding %v", f.created, fake.mail.Forward)
	}

	// Stopping forwarding never needs it.
	fake.mail.Forward = []string{"out@remote.example"}
	if resp := h.post("/settings/forwarding", url.Values{"csrf": {csrf}, "forward": {""}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("clearing forwarding: %d", resp.StatusCode)
	}
	if len(fake.mail.Forward) != 0 {
		t.Errorf("forwarding not cleared: %v", fake.mail.Forward)
	}
}

func TestNewRedirectTarget(t *testing.T) {
	existing := []FilterRule{{Actions: []FilterAction{{Type: "redirect", Arg: "Known@remote.example"}}}}
	if newRedirectTarget(existing, FilterRule{Actions: []FilterAction{{Type: "redirect", Arg: "known@remote.example"}}}) {
		t.Error("an address already forwarded to counted as new")
	}
	if !newRedirectTarget(existing, FilterRule{Actions: []FilterAction{{Type: "fileinto", Arg: "x"}, {Type: "redirect", Arg: "new@remote.example"}}}) {
		t.Error("a new redirect target wasn't noticed")
	}
	if newRedirectTarget(nil, FilterRule{Actions: []FilterAction{{Type: "fileinto", Arg: "x"}}}) {
		t.Error("a rule without a redirect counted as forwarding")
	}
}

// Changing the password revokes app passwords, so one someone else created
// doesn't survive the user's response.
func TestPasswordChangeRevokesAppPasswords(t *testing.T) {
	f := &fakeSecurity{newPassword: "correct horse battery"}
	h := newSecurityHarness(t, f)
	h.server.passwords = &fakePasswords{current: "secret"}
	csrf := h.login()

	resp := h.post("/settings/password", url.Values{"csrf": {csrf}, "current": {"secret"}, "new": {"correct horse battery"}, "confirm": {"correct horse battery"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=password-changed#") {
		t.Fatalf("change = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.revokeAll != 1 {
		t.Errorf("revoke-all called %d times, want 1", f.revokeAll)
	}
}
