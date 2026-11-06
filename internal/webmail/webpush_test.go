package webmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeviceLabel(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36":                   "Chrome on Android",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1": "Safari on iPhone",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0":           "Edge on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15":                   "Safari on macOS",
		"curl/8.10": "Browser",
	} {
		if got := deviceLabel(ua); got != want {
			t.Errorf("%s: %q, want %q", ua, got, want)
		}
	}
}

func TestPushRemindersFrom(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 11, 6, 9, 0, 0, 0, loc)
	events := []Event{
		{UID: "standup", Summary: "Standup", Location: "Room 4", Start: now.Add(time.Hour), End: now.Add(90 * time.Minute), Reminder: 15, RRule: "FREQ=DAILY"},
		{UID: "quiet", Summary: "No reminder", Start: now.Add(time.Hour), End: now.Add(2 * time.Hour), Reminder: -1},
	}
	got := pushRemindersFrom(events, now, loc, true, 3*24*time.Hour)
	if len(got) != 3 {
		t.Fatalf("%d reminders, want 3 (a daily event over three days): %+v", len(got), got)
	}
	r := got[0]
	if r.Title != "Standup" || r.Body != "10:00 · Room 4" || !r.At.Equal(now.Add(45*time.Minute)) || !r.Start.Equal(now.Add(time.Hour)) || !strings.HasPrefix(r.URL, "/calendar/") {
		t.Errorf("first = %+v", r)
	}
	if got[0].Key == got[1].Key {
		t.Error("occurrences share a key")
	}
}

func TestPushSettingsCard(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	h.login()
	// Push off at the mailbox service: no card.
	if _, body := h.get("/settings/devices"); strings.Contains(body, `id="notifications"`) {
		t.Fatal("the card shows with push off")
	}
	sent := time.Date(2026, 11, 6, 14, 30, 0, 0, time.UTC)
	f.mu.Lock()
	f.pushKey = "BEXAMPLEKEY"
	f.pushDevices = []pushDevice{{ID: 7, Endpoint: "https://fcm.googleapis.com/fcm/send/abc", Label: "Chrome on Android", Mail: "primary", Reminders: true, LastSent: &sent}}
	f.mu.Unlock()
	_, body := h.get("/settings/devices")
	for _, want := range []string{`data-push-key="BEXAMPLEKEY"`, "Chrome on Android", "New mail in Primary and reminders", `data-endpoint="https://fcm.googleapis.com/fcm/send/abc"`, `name="id" value="7"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	// The page links the app manifest and its icon.
	if !strings.Contains(body, `rel="manifest" href="/manifest.webmanifest"`) {
		t.Error("no manifest link")
	}
}

func TestPushSubscribeAndRemove(t *testing.T) {
	f := &fakeSecurity{pushKey: "BEXAMPLEKEY"}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	postJSON := func(path string, v any) *http.Response {
		t.Helper()
		b, _ := json.Marshal(v)
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	sub := map[string]any{"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/x", "p256dh": "BKEY", "auth": "AUTH", "mail": "all", "reminders": true, "preview": false}
	if resp := postJSON("/settings/push", sub); resp.StatusCode != http.StatusOK {
		t.Fatalf("subscribe: %d", resp.StatusCode)
	}
	if resp := postJSON("/settings/push/test", map[string]string{"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/x"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d", resp.StatusCode)
	}
	if resp := h.post("/settings/push/delete", url.Values{"csrf": {csrf}, "id": {"7"}}); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=push-removed") {
		t.Fatalf("remove: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Without the token, nothing is asked of the mailbox service.
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/settings/push", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := h.client.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF token: %v %v", resp, err)
	}

	f.mu.Lock()
	calls := f.pushCalls
	f.mu.Unlock()
	if len(calls) != 3 {
		t.Fatalf("calls = %v", calls)
	}
	if calls[0]["path"] != "PUT /v1/push/subscriptions" || calls[0]["label"] != "Firefox on Linux" || calls[0]["preview"] != false ||
		!strings.HasPrefix(calls[0]["contact"].(string), "https://") {
		t.Errorf("subscribe = %v", calls[0])
	}
	if calls[1]["path"] != "POST /v1/push/test" {
		t.Errorf("test = %v", calls[1])
	}
	if calls[2]["path"] != "POST /v1/push/subscriptions/delete" || calls[2]["id"] != float64(7) {
		t.Errorf("delete = %v", calls[2])
	}
}

func TestPublishSendsReminders(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:review\r\nDTSTAMP:20260101T000000Z\r\n" +
		"DTSTART:" + h.server.now().Add(48*time.Hour).UTC().Format("20060102T150405Z") + "\r\nDURATION:PT1H\r\nSUMMARY:Design review\r\n" +
		"BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if err := h.store.PutObject(context.Background(), CollCalendar, Object{ID: "review", ContentType: "text/calendar", Data: []byte(ics)}); err != nil {
		t.Fatal(err)
	}
	if err := h.server.publishFreeBusyNow(context.Background(), "dana", "secret", "dana@example.com"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got, _ := json.Marshal(f.pushReminders)
	f.mu.Unlock()
	if !strings.Contains(string(got), `"title":"Design review"`) || !strings.Contains(string(got), `"key":"review@`) {
		t.Errorf("reminders = %s", got)
	}
}

func TestServiceWorkerAndManifest(t *testing.T) {
	h := newHarness(t)
	resp, body := h.get("/sw.js")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(body, "showNotification") {
		t.Fatalf("sw.js: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, body = h.get("/manifest.webmanifest")
	var m map[string]any
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &m) != nil || m["start_url"] != "/mail" || m["display"] != "standalone" {
		t.Fatalf("manifest: %d %s", resp.StatusCode, body)
	}
	for _, icon := range m["icons"].([]any) {
		src := icon.(map[string]any)["src"].(string)
		if r, _ := h.get(src); r.StatusCode != http.StatusOK {
			t.Errorf("icon %s: %d", src, r.StatusCode)
		}
	}
}
