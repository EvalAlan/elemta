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

func TestBusyFrom(t *testing.T) {
	loc := time.UTC
	day := time.Date(2026, 11, 2, 0, 0, 0, 0, loc)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	me := "dana@example.com"
	invite := func(uid string, h int, status string) Event {
		return Event{UID: uid, Start: at(h, 0), End: at(h+1, 0), Busy: true, Status: "CONFIRMED",
			Organizer: &Attendee{Email: "boss@example.com"}, Attendees: []Attendee{{Email: me, Status: status}}}
	}
	events := []Event{
		{UID: "standup", Start: at(9, 0), End: at(9, 15), Busy: true, Status: "CONFIRMED", RRule: "FREQ=DAILY;COUNT=3"},
		{UID: "overlap", Start: at(9, 10), End: at(9, 30), Busy: true, Status: "CONFIRMED"},
		{UID: "focus", Start: at(10, 0), End: at(11, 0), Busy: false, Status: "CONFIRMED"},
		{UID: "cancelled", Start: at(12, 0), End: at(13, 0), Busy: true, Status: "CANCELLED"},
		invite("declined", 13, "DECLINED"),
		invite("maybe", 14, "TENTATIVE"),
		invite("unanswered", 15, "NEEDS-ACTION"),
		invite("accepted", 16, "ACCEPTED"),
		{UID: "birthday", Start: day, End: day.AddDate(0, 0, 1), AllDay: true, Busy: true, ReadOnly: true},
		{UID: "holiday", Start: day, End: day.AddDate(0, 0, 1), AllDay: true, Busy: true, HolidayKey: "x"},
	}
	got := busyFrom(events, me, day, day.AddDate(0, 0, 1))
	want := []busyBlock{
		{Start: at(9, 0), End: at(9, 30)}, // the standup and the overlapping meeting, merged
		{Start: at(14, 0), End: at(16, 0), Tentative: true},
		{Start: at(16, 0), End: at(17, 0)},
	}
	if len(got) != len(want) {
		t.Fatalf("busy = %+v", got)
	}
	for i := range want {
		if !got[i].Start.Equal(want[i].Start) || !got[i].End.Equal(want[i].End) || got[i].Tentative != want[i].Tentative {
			t.Errorf("block %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The recurring standup appears on the following days too.
	if next := busyFrom(events, me, day.AddDate(0, 0, 1), day.AddDate(0, 0, 2)); len(next) != 1 || !next[0].Start.Equal(at(24+9, 0)) {
		t.Errorf("next day = %+v", next)
	}
}

func TestFreeBusyLookupAndPublish(t *testing.T) {
	f := &fakeSecurity{freeBusy: []map[string]any{
		{"address": "dana@example.com", "known": true, "busy": []map[string]any{}},
		{"address": "lee@example.com", "known": true, "busy": []map[string]any{
			{"start": "2026-11-02T13:00:00Z", "end": "2026-11-02T14:30:00Z"},
			{"start": "2026-11-01T22:00:00Z", "end": "2026-11-02T01:00:00Z", "tentative": true},
		}},
		{"address": "ext@other.example", "known": false, "busy": []map[string]any{}},
	}}
	h := newSecurityHarness(t, f)
	if resp, _ := h.submitLogin("secret"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in = %d", resp.StatusCode)
	}
	resp, js := h.get("/api/freebusy?date=2026-11-02&attendees=" + url.QueryEscape("Lee <lee@example.com>, ext@other.example"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lookup = %d %s", resp.StatusCode, js)
	}
	var out struct {
		Minutes int
		People  []freeBusyPerson
	}
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		t.Fatal(err)
	}
	if out.Minutes != 1440 || len(out.People) != 3 || out.People[2].Known {
		t.Fatalf("answer = %s", js)
	}
	lee := out.People[1].Busy
	if len(lee) != 2 || lee[0] != (freeBusyMin{From: 780, To: 870}) || lee[1] != (freeBusyMin{From: 0, To: 60, Tentative: true}) {
		t.Errorf("lee's busy minutes = %+v", lee)
	}
	q := f.lookups[len(f.lookups)-1]
	if !strings.Contains(q, "address=dana%40example.com") || !strings.Contains(q, "address=lee%40example.com") || !strings.Contains(q, "from=2026-11-02T00%3A00%3A00Z") {
		t.Errorf("lookup query = %s", q)
	}

	// Publishing sends the user's busy times, not their events.
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:secret-meeting\r\nDTSTAMP:20260101T000000Z\r\n" +
		"DTSTART:" + h.server.now().Add(48*time.Hour).UTC().Format("20060102T150405Z") + "\r\nDURATION:PT1H\r\nSUMMARY:Secret plans\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if err := h.store.PutObject(context.Background(), CollCalendar, Object{ID: "secret-meeting", ContentType: "text/calendar", Data: []byte(ics)}); err != nil {
		t.Fatal(err)
	}
	if err := h.server.publishFreeBusyNow(context.Background(), "dana", "secret", "dana@example.com"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	published, _ := json.Marshal(f.published)
	f.mu.Unlock()
	if !strings.Contains(string(published), `"busy":[{"end"`) || strings.Contains(string(published), "Secret") {
		t.Errorf("published = %s", published)
	}
}

func TestFreeBusyAtSignInIsThrottled(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	h.server.now = func() time.Time { return now }
	h.server.publishFreeBusyAtSignIn("dana", "secret", "dana@example.com")
	h.server.publishFreeBusyAtSignIn("dana", "secret", "dana@example.com")
	h.server.freeBusy.mu.Lock()
	pending := len(h.server.freeBusy.pending)
	first := h.server.freeBusy.atSignIn["dana"]
	h.server.freeBusy.mu.Unlock()
	if pending != 1 || !first.Equal(now) {
		t.Fatalf("pending %d, recorded %v", pending, first)
	}
	// A second sign-in within the hour schedules nothing new.
	h.server.freeBusy.mu.Lock()
	for _, timer := range h.server.freeBusy.pending {
		timer.Stop()
	}
	h.server.freeBusy.pending = map[string]*time.Timer{}
	h.server.freeBusy.mu.Unlock()
	now = now.Add(30 * time.Minute)
	h.server.publishFreeBusyAtSignIn("dana", "secret", "dana@example.com")
	if len(h.server.freeBusy.pending) != 0 {
		t.Error("republished within the hour")
	}
	now = now.Add(31 * time.Minute)
	h.server.publishFreeBusyAtSignIn("dana", "secret", "dana@example.com")
	if len(h.server.freeBusy.pending) != 1 {
		t.Error("didn't republish after an hour")
	}
}
