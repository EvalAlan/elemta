package webmail

import (
	"bytes"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// composeOp posts a compose form with the given op ("send" or "save").
func composeOp(t *testing.T, h *harness, csrf, op string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range map[string]string{
		"csrf": csrf, "op": op, "to": "priya@northwind.example, jonas@example.com",
		"subject": "Kickoff", "body": "See you Tuesday.",
	} {
		_ = w.WriteField(k, v)
	}
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/compose", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: status %d", op, resp.StatusCode)
	}
}

func TestSendIsLoggedWithoutOriginatingIPByDefault(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.server.log = slog.New(slog.NewTextHandler(&logs, nil))
	composeOp(t, h, h.login(), "send")

	raw := string(h.sub.raw)
	if strings.Contains(raw, "X-Originating-Ip") || strings.Contains(raw, "X-Originating-IP") {
		t.Errorf("header added though not configured:\n%s", raw)
	}
	id := regexp.MustCompile(`(?m)^Message-Id: (<[^>]+>)`).FindStringSubmatch(raw)
	if id == nil {
		t.Fatalf("no Message-Id in:\n%s", raw)
	}
	line := ""
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `msg="webmail: sent"`) {
			line = l
		}
	}
	for _, want := range []string{"user=dana", "ip=127.0.0.1", "message_id=" + id[1], "recipients=2", "kind=message"} {
		if !strings.Contains(line, want) {
			t.Errorf("send log %q lacks %q", line, want)
		}
	}
}

func TestOriginatingIPHeaderWhenConfigured(t *testing.T) {
	h := newHarness(t)
	h.server.cfg.OriginatingIPHeader = true
	csrf := h.login()

	composeOp(t, h, csrf, "send")
	if !strings.Contains(string(h.sub.raw), "X-Originating-Ip: [127.0.0.1]") {
		t.Errorf("sent message lacks the header:\n%s", h.sub.raw)
	}

	// A saved draft hasn't been sent from anywhere.
	composeOp(t, h, csrf, "save")
	drafts := h.store.appended[RoleDrafts]
	if len(drafts) == 0 {
		t.Fatal("draft not saved")
	}
	if strings.Contains(string(drafts[len(drafts)-1]), "X-Originating-Ip") {
		t.Errorf("saved draft carries the header")
	}
}

// Invitations reach submission through submitDraft, deep in the calendar
// code, with only the request's context to go on.
func TestInvitationSendIsLoggedAndStamped(t *testing.T) {
	h := newHarness(t)
	h.server.cfg.OriginatingIPHeader = true
	var logs bytes.Buffer
	h.server.log = slog.New(slog.NewTextHandler(&logs, nil))
	csrf := h.login()

	resp := postForm(t, h, "/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "summary": {"Kickoff"}, "start_date": {"2026-10-20"}, "start_time": {"14:00"},
		"end_date": {"2026-10-20"}, "end_time": {"15:00"}, "attendees": {"priya@northwind.example"}, "notify": {"1"},
	})
	if !strings.Contains(resp.Header.Get("Location"), "invites-sent") {
		t.Fatalf("location = %q", resp.Header.Get("Location"))
	}
	if !strings.Contains(string(h.sub.raw), "X-Originating-Ip: [127.0.0.1]") {
		t.Errorf("invitation lacks the header:\n%s", h.sub.raw)
	}
	if !strings.Contains(logs.String(), `msg="webmail: sent"`) || !strings.Contains(logs.String(), "kind=calendar") || !strings.Contains(logs.String(), "ip=127.0.0.1") {
		t.Errorf("invitation send not logged:\n%s", logs.String())
	}
}
