package webmail

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestJunkMailSettings(t *testing.T) {
	f := &fakeSecurity{maxSenders: 2, allow: []string{"friend@good.example"}}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	_, body := h.get("/settings/account")
	if !strings.Contains(body, `id="senders"`) || !strings.Contains(body, "friend@good.example") || !strings.Contains(body, "Up to 2 entries") {
		t.Fatalf("junk mail card:\n%s", body)
	}
	resp := h.post("/settings/senders", url.Values{"csrf": {csrf}, "allow": {"a@x.example\nb@x.example"}, "block": {"@spam.example"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("over the limit = %d", resp.StatusCode)
	}
	resp = h.post("/settings/senders", url.Values{"csrf": {csrf}, "allow": {"a@x.example"}, "block": {"@spam.example"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "senders-saved") {
		t.Fatalf("save = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if strings.Join(f.allow, ",") != "a@x.example" || strings.Join(f.block, ",") != "@spam.example" {
		t.Errorf("saved allow %v block %v", f.allow, f.block)
	}
}
