package webmail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// fakeMailSettings stands in for the directory, as the user.
type fakeMailSettings struct {
	mail     AccountMail
	user, pw string
}

func (f *fakeMailSettings) ReadMailSettings(_ context.Context, user, password string) (AccountMail, error) {
	f.user, f.pw = user, password
	return f.mail, nil
}

func (f *fakeMailSettings) SetForwarding(_ context.Context, user, password string, forward []string, keep bool) error {
	f.user, f.pw = user, password
	f.mail.Forward, f.mail.KeepCopy = forward, keep
	return nil
}

func TestForwardingSettings(t *testing.T) {
	h := newHarness(t)
	fake := &fakeMailSettings{mail: AccountMail{Forward: []string{"old@remote.example"}, SendAs: []string{"sales@example.com"}}}
	h.server.mailSettings = fake
	csrf := h.login()

	_, body := h.get("/settings/account")
	for _, want := range []string{`id="forwarding"`, `value="old@remote.example"`, "sales@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("account settings lack %q", want)
		}
	}
	resp := h.post("/settings/forwarding", url.Values{"csrf": {csrf}, "forward": {"A@Remote.example, b@remote.example\na@remote.example"}, "keep_copy": {"1"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "forwarding-saved") {
		t.Fatalf("save = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if strings.Join(fake.mail.Forward, ",") != "a@remote.example,b@remote.example" || !fake.mail.KeepCopy || fake.pw != "secret" {
		t.Errorf("saved %+v as %s", fake.mail, fake.user)
	}
	// Problems are explained, and nothing is saved.
	// Three is the default limit without a class saying otherwise.
	for _, bad := range []string{"not an address", h.server.sessionAddress(t, h), "a@x.example, b@x.example, c@x.example, d@x.example"} {
		resp = h.post("/settings/forwarding", url.Values{"csrf": {csrf}, "forward": {bad}})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("forward to %q = %d", bad, resp.StatusCode)
		}
	}
	if strings.Join(fake.mail.Forward, ",") != "a@remote.example,b@remote.example" {
		t.Errorf("a refused change was saved: %v", fake.mail.Forward)
	}
	// Clearing stops forwarding.
	h.post("/settings/forwarding", url.Values{"csrf": {csrf}, "forward": {""}})
	if len(fake.mail.Forward) != 0 || fake.mail.KeepCopy {
		t.Errorf("after clearing: %+v", fake.mail)
	}
}

func TestComposeSendAs(t *testing.T) {
	h := newHarness(t)
	h.server.mailSettings = &fakeMailSettings{mail: AccountMail{SendAs: []string{"sales@example.com", "@brand.example"}}}
	csrf := h.login()

	_, body := h.get("/compose")
	if !strings.Contains(body, `<select id="from" name="from">`) || !strings.Contains(body, `value="sales@example.com"`) || strings.Contains(body, "brand.example") {
		t.Fatalf("compose doesn't offer the send-as address:\n%s", body)
	}
	sendForm(t, h, csrf, map[string]string{"to": "x@remote.example", "subject": "hi", "body": "hello", "from": "Sales@Example.com"})
	if h.sub.from != "sales@example.com" || !strings.Contains(string(h.sub.raw), "From: ") || !strings.Contains(string(h.sub.raw), "sales@example.com") {
		t.Errorf("sent from %q", h.sub.from)
	}
	// A sender that isn't offered falls back to the user's own address.
	sendForm(t, h, csrf, map[string]string{"to": "x@remote.example", "subject": "hi", "body": "hello", "from": "ceo@example.com"})
	if h.sub.from == "ceo@example.com" {
		t.Error("compose sent as an address the user wasn't offered")
	}
}

// sessionAddress is the signed-in test user's address.
func (s *Server) sessionAddress(t *testing.T, h *harness) string {
	t.Helper()
	for _, c := range h.client.Jar.Cookies(mustURL(t, h.srv.URL)) {
		if sess, ok := s.sessions.Get(c.Value); ok {
			return sess.Address
		}
	}
	t.Fatal("no session")
	return ""
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
