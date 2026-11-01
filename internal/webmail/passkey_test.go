package webmail

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasskeySite(t *testing.T) {
	for in, want := range map[string][2]string{
		"mail.example.com":     {"mail.example.com", "https://mail.example.com"},
		"Mail.Example.com":     {"mail.example.com", "https://mail.example.com"},
		"localhost:8027":       {"localhost", "http://localhost:8027"},
		"mail.example.com:444": {"mail.example.com", "https://mail.example.com:444"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = in
		if host, origin := passkeySite(r); host != want[0] || origin != want[1] {
			t.Errorf("%s: %s %s", in, host, origin)
		}
	}
}

// Without the sign-in form's token, another site could start a passkey
// sign-in in someone's browser.
func TestPasskeySignInNeedsTheFormToken(t *testing.T) {
	h := newSecurityHarness(t, &fakeSecurity{})
	for _, path := range []string{"/login/passkey/begin", "/login/passkey/finish"} {
		resp := h.postJSON(path, `{"token":"forged"}`)
		if resp.StatusCode != 403 {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}
	}
}

func TestLoginOffersPasskeysOnlyWithTheSecurityService(t *testing.T) {
	if _, page := newHarness(t).get("/login"); strings.Contains(page, "data-passkey-signin") {
		t.Error("offered with nothing to check it")
	}
	h := newSecurityHarness(t, &fakeSecurity{})
	if _, page := h.get("/login"); !strings.Contains(page, "data-passkey-signin") {
		t.Error("not offered")
	}
}
