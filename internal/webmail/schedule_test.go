package webmail

import (
	"bytes"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skip(err)
	}
	return loc
}

func choiceLabels(cs []laterChoice) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Label+"="+c.Value)
	}
	return strings.Join(out, " ")
}

func TestLaterChoices(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	// Tuesday 10:20 in New York.
	tue := time.Date(2026, 11, 10, 10, 20, 0, 0, ny)
	if got, want := choiceLabels(laterChoices(tue, ny, false, true)),
		"Later today=2026-11-10T14:00:00-05:00 Tomorrow morning=2026-11-11T08:00:00-05:00 This weekend=2026-11-14T08:00:00-05:00 Next week=2026-11-16T08:00:00-05:00"; got != want {
		t.Errorf("snooze on a Tuesday:\n got %s\nwant %s", got, want)
	}
	if got, want := choiceLabels(laterChoices(tue, ny, false, false)),
		"Tomorrow morning=2026-11-11T08:00:00-05:00 Tomorrow afternoon=2026-11-11T13:00:00-05:00 Next week=2026-11-16T08:00:00-05:00"; got != want {
		t.Errorf("send later on a Tuesday:\n got %s\nwant %s", got, want)
	}
	// Sunday evening: no "later today", no weekend, and next week is
	// tomorrow morning, offered once.
	sun := time.Date(2026, 11, 15, 19, 0, 0, 0, ny)
	if got, want := choiceLabels(laterChoices(sun, ny, false, true)), "Tomorrow morning=2026-11-16T08:00:00-05:00"; got != want {
		t.Errorf("snooze on a Sunday evening:\n got %s\nwant %s", got, want)
	}
	// Times are the user's, whatever the server's zone: 8:00 in Tokyo.
	tokyo := mustZone(t, "Asia/Tokyo")
	c := laterChoices(time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC), tokyo, true, false)
	if c[0].Value != "2026-11-11T08:00:00+09:00" || c[0].When != "Wed 08:00" {
		t.Errorf("first choice in Tokyo = %+v", c[0])
	}
	// Across the end of daylight saving time, 8:00 is still 8:00.
	sat := time.Date(2026, 10, 31, 12, 0, 0, 0, ny)
	for _, ch := range laterChoices(sat, ny, false, false) {
		if ch.Label == "Tomorrow morning" && ch.Value != "2026-11-01T08:00:00-05:00" {
			t.Errorf("tomorrow morning across the change = %s", ch.Value)
		}
	}
}

func TestParseLater(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, ny)
	got, err := parseLater("custom", "2026-11-12T09:30", ny, now)
	if err != nil || !got.Equal(time.Date(2026, 11, 12, 9, 30, 0, 0, ny)) {
		t.Errorf("custom = %v, %v", got, err)
	}
	if _, err := parseLater("2026-11-12T14:30:00Z", "", ny, now); err != nil {
		t.Errorf("preset: %v", err)
	}
	for _, bad := range [][2]string{{"custom", "2026-11-09T09:30"}, {"custom", ""}, {"custom", "tomorrow"}, {"2028-01-01T00:00:00Z", ""}, {"", ""}} {
		if _, err := parseLater(bad[0], bad[1], ny, now); err == nil {
			t.Errorf("accepted %q %q", bad[0], bad[1])
		}
	}
}

func TestWhenText(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	now := time.Date(2026, 11, 10, 22, 0, 0, 0, ny)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 11, 10, 23, 15, 0, 0, ny), "today at 11:15 PM"},
		{time.Date(2026, 11, 11, 8, 0, 0, 0, ny), "tomorrow at 8:00 AM"},
		{time.Date(2026, 11, 16, 8, 0, 0, 0, ny), "Monday, November 16 at 8:00 AM"},
		{time.Date(2027, 2, 1, 8, 0, 0, 0, ny), "Monday, February 1, 2027 at 8:00 AM"},
	} {
		if got := whenText(ny, false, c.t, now); got != c.want {
			t.Errorf("whenText(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func (h *harness) postMultipart(path string, fields map[string]string) *http.Response {
	h.t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+path, w.FormDataContentType(), &buf)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func TestComposeScheduleSend(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	_, page := h.get("/compose")
	if !strings.Contains(page, "Send later") || !strings.Contains(page, `name="schedule" value="custom"`) {
		t.Fatal("compose doesn't offer Send later")
	}
	at := time.Now().Add(26 * time.Hour).UTC().Truncate(time.Minute)
	resp := h.postMultipart("/compose", map[string]string{
		"csrf": csrf, "to": "priya@northwind.example", "bcc": "archive@example.com",
		"subject": "Later", "body": "Morning.", "schedule": at.Format(time.RFC3339),
	})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=scheduled") {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if h.sub.raw != nil {
		t.Fatal("a scheduled message was sent at once")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.laterCalls) != 1 || f.laterCalls[0]["path"] != "/v1/scheduled" {
		t.Fatalf("API calls %v", f.laterCalls)
	}
	call := f.laterCalls[0]
	if call["from"] != "dana@example.com" || call["send_at"] != at.Format(time.RFC3339) {
		t.Errorf("scheduled from %v at %v", call["from"], call["send_at"])
	}
	if to, _ := call["to"].([]any); len(to) != 2 || to[0] != "priya@northwind.example" || to[1] != "archive@example.com" {
		t.Errorf("recipients %v (Bcc belongs in the envelope)", call["to"])
	}
	// The message is dated when it goes, and carries no Bcc header.
	raw, _ := call["raw"].(string)
	if raw == "" {
		t.Fatal("no message sent to the mailbox service")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(b)
	m, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if date, err := m.Header.Date(); err != nil || !date.Equal(at) {
		t.Errorf("message dated %v (%v), want its send time %v", date, err, at)
	}
	if strings.Contains(msg, "archive@example.com") {
		t.Error("the Bcc address is in the message")
	}
}

func TestComposeScheduleRefusesThePast(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	resp := h.postMultipart("/compose", map[string]string{
		"csrf": csrf, "to": "priya@northwind.example", "subject": "Late", "body": "x",
		"schedule": "custom", "schedule_at": "2020-01-01T08:00",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	if len(f.laterCalls) != 0 || h.sub.raw != nil {
		t.Error("a message for 2020 went somewhere")
	}
}

func TestSnoozeAction(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX&uid=7")
	if !strings.Contains(page, "Snooze until") {
		t.Fatal("the message page offers no snooze")
	}
	until := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"snooze"}, "until": {until.Format(time.RFC3339)}, "back": {"/mail?f=INBOX&uid=7"}})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "n=snoozed") || !strings.Contains(loc, "undo=") || strings.Contains(loc, "uid=7") {
		t.Fatalf("status %d location %q", resp.StatusCode, loc)
	}
	// The bulk bar's form posts the time inside op.
	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7,8"}, "op": {"snooze@" + until.Format(time.RFC3339)}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=snoozed-many") {
		t.Fatalf("bulk: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.laterCalls) != 2 {
		t.Fatalf("API calls %v", f.laterCalls)
	}
	for _, c := range f.laterCalls {
		if c["path"] != "/v1/snooze" || c["folder"] != "INBOX" || c["until"] != until.Format(time.RFC3339) {
			t.Errorf("snooze call %v", c)
		}
	}
	if uids, _ := f.laterCalls[1]["uids"].([]any); len(uids) != 2 {
		t.Errorf("bulk snooze sent uids %v", f.laterCalls[1]["uids"])
	}
}

// Undo after a snooze moves the message back out of Snoozed, which is
// what ends a snooze on the mailbox side.
func TestSnoozeUndoIsAMoveBack(t *testing.T) {
	h := newSecurityHarness(t, &fakeSecurity{})
	csrf := h.login()
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"snooze"}, "until": {time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
	u, _ := url.Parse(resp.Header.Get("Location"))
	undo, ok := decodeUndo(u.Query().Get("undo"), time.Now())
	if !ok || undo.From != "Snoozed" || undo.To != "INBOX" || len(undo.UIDs) != 1 || undo.UIDs[0] != 41 {
		t.Fatalf("undo = %+v, %v", undo, ok)
	}
}

func TestScheduledFolderShowsWhenAndActions(t *testing.T) {
	sendAt := time.Now().Add(20 * time.Hour)
	f := &fakeSecurity{scheduled: []scheduledItem{{UID: 7, SendAt: sendAt}}}
	h := newSecurityHarness(t, f)
	h.store.mu.Lock()
	h.store.folders = append(h.store.folders, Folder{Name: "Scheduled", Display: "Scheduled", Role: RoleScheduled, Selectable: true, Total: 1})
	h.store.messages["Scheduled"] = h.store.messages["INBOX"]
	h.store.mu.Unlock()
	csrf := h.login()
	_, list := h.get("/mail?f=Scheduled")
	if !strings.Contains(list, `class="mono later-time">Sends `) {
		t.Error("the Scheduled list doesn't say when each message sends")
	}
	if strings.Contains(list, "Snooze until") {
		t.Error("scheduled mail offers snooze")
	}
	_, page := h.get("/mail?f=Scheduled&uid=7")
	for _, want := range []string{"Sends today at", `value="send-now"`, `value="unschedule"`, "Change time"} {
		if !strings.Contains(page, want) && !(want == "Sends today at" && strings.Contains(page, "Sends tomorrow at")) {
			t.Errorf("the scheduled message page lacks %q", want)
		}
	}
	// Edit: stopped, and opened as the draft it became.
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"Scheduled"}, "uid": {"7"}, "op": {"unschedule"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/compose?f=Drafts&mode=draft&uid=52" {
		t.Errorf("edit: status %d location %q", resp.StatusCode, loc)
	}
	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"Scheduled"}, "uid": {"7"}, "op": {"send-now"}})
	if !strings.Contains(resp.Header.Get("Location"), "n=sending-now") {
		t.Errorf("send now: location %q", resp.Header.Get("Location"))
	}
	f.mu.Lock()
	last := f.laterCalls[len(f.laterCalls)-1]
	f.mu.Unlock()
	if last["path"] != "/v1/scheduled/reschedule" {
		t.Errorf("send now called %v", last)
	}
}

func TestSnoozedMessageShowsUntil(t *testing.T) {
	f := &fakeSecurity{snoozed: []snoozedItem{{UID: 7, Until: time.Now().Add(30 * time.Hour), ReturnTo: "INBOX"}}}
	h := newSecurityHarness(t, f)
	h.store.mu.Lock()
	h.store.folders = append(h.store.folders, Folder{Name: "Snoozed", Display: "Snoozed", Role: RoleSnoozed, Selectable: true, Total: 1})
	h.store.messages["Snoozed"] = h.store.messages["INBOX"]
	h.store.mu.Unlock()
	csrf := h.login()
	_, page := h.get("/mail?f=Snoozed&uid=7")
	if !strings.Contains(page, "Snoozed until") || !strings.Contains(page, `value="unsnooze"`) {
		t.Error("the snoozed message page doesn't say until when, or offer Unsnooze")
	}
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"Snoozed"}, "uid": {"7"}, "op": {"unsnooze"}})
	if !strings.Contains(resp.Header.Get("Location"), "n=unsnoozed") {
		t.Errorf("unsnooze: location %q", resp.Header.Get("Location"))
	}
}

// Reading a shared mailbox, snooze and schedule would act on the user's own
// account instead, so neither is offered.
func TestLaterNotOfferedWithoutTheAPI(t *testing.T) {
	h := newHarness(t) // no mailbox service API
	h.login()
	_, page := h.get("/mail?f=INBOX&uid=7")
	if strings.Contains(page, "Snooze until") {
		t.Error("snooze offered without the mailbox service")
	}
	_, page = h.get("/compose")
	if strings.Contains(page, "Send later") {
		t.Error("send later offered without the mailbox service")
	}
}
