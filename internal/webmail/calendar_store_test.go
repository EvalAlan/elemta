package webmail

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A weekly series as a phone would sync it: a VTIMEZONE, a vendor
// property, two alarms, and one occurrence moved by an override.
const phoneSeries = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Phone//EN\r\n" +
	"BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n" +
	"BEGIN:VEVENT\r\nUID:series-1\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:20261005T090000Z\r\nDTEND:20261005T100000Z\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\nSUMMARY:Standup\r\nX-PHONE-COLOR:teal\r\n" +
	"BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Standup\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n" +
	"BEGIN:VALARM\r\nACTION:EMAIL\r\nDESCRIPTION:Standup\r\nSUMMARY:Standup\r\nATTENDEE:mailto:user@example.com\r\nTRIGGER:-PT1H\r\nEND:VALARM\r\n" +
	"END:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:series-1\r\nDTSTAMP:20261001T000000Z\r\nRECURRENCE-ID:20261012T090000Z\r\nDTSTART:20261012T110000Z\r\nDTEND:20261012T120000Z\r\nSUMMARY:Standup (moved)\r\nEND:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

func storedPhoneSeries(t *testing.T, uid string) (*storedEvent, Event) {
	t.Helper()
	objs := []Object{{ID: "series-1", Data: []byte(phoneSeries)}}
	stored := findStoredEvent(objs, uid)
	if stored == nil {
		t.Fatalf("%s not found", uid)
	}
	cal, err := decodeCalendar([]byte(phoneSeries), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cal.Events {
		if e.UID == uid {
			return stored, e
		}
	}
	t.Fatalf("decode has no %s", uid)
	return nil, Event{}
}

func TestEditSeriesKeepsWhatTheWebmailDoesntShow(t *testing.T) {
	stored, e := storedPhoneSeries(t, "series-1")
	e.Summary = "Daily standup"
	data, id, err := mergeEvent(stored, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if id != "series-1" {
		t.Errorf("written to %q", id)
	}
	for _, want := range []string{"SUMMARY:Daily standup", "X-PHONE-COLOR:teal", "ACTION:EMAIL", "TRIGGER:-PT15M", "BEGIN:VTIMEZONE", "RECURRENCE-ID:20261012T090000Z", "SUMMARY:Standup (moved)"} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q:\n%s", want, out)
		}
	}
	// The EXDATE decodeCalendar adds for the override must not be stored,
	// or the moved occurrence would vanish in other clients.
	if strings.Contains(out, "EXDATE") {
		t.Errorf("synthetic EXDATE written:\n%s", out)
	}
}

func TestEditSeriesReminderReplacesAlarms(t *testing.T) {
	stored, e := storedPhoneSeries(t, "series-1")
	e.Reminder = 5
	data, _, err := mergeEvent(stored, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if strings.Count(out, "BEGIN:VALARM") != 1 || strings.Contains(out, "ACTION:EMAIL") || strings.Contains(out, "TRIGGER:-PT15M") {
		t.Errorf("a changed reminder should replace the alarms:\n%s", out)
	}
}

func TestChangingTheRuleDropsOverrides(t *testing.T) {
	stored, e := storedPhoneSeries(t, "series-1")
	e.RRule = "FREQ=DAILY;COUNT=5"
	data, _, err := mergeEvent(stored, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "RECURRENCE-ID") {
		t.Errorf("overrides of the old rule were kept:\n%s", data)
	}
}

func TestEditOverrideStaysInItsSeries(t *testing.T) {
	uid := overrideUID("series-1", time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	stored, e := storedPhoneSeries(t, uid)
	e.Summary = "Standup (moved again)"
	data, id, err := mergeEvent(stored, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if id != "series-1" {
		t.Fatalf("override written to its own object %q", id)
	}
	if !strings.Contains(out, "SUMMARY:Standup (moved again)") || !strings.Contains(out, "RECURRENCE-ID:20261012T090000Z") || !strings.Contains(out, "SUMMARY:Standup\r\n") {
		t.Errorf("override not updated in place:\n%s", out)
	}
	if strings.Count(out, "UID:series-1") != 2 || strings.Contains(out, uid) {
		t.Errorf("override UID changed:\n%s", out)
	}
}

func TestDeleteOverrideBecomesExdate(t *testing.T) {
	uid := overrideUID("series-1", time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	stored, _ := storedPhoneSeries(t, uid)
	data, err := deleteOverride(stored)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if strings.Contains(out, "Standup (moved)") || !strings.Contains(out, "EXDATE:20261012T090000Z") {
		t.Errorf("override not turned into an EXDATE:\n%s", out)
	}
}

// End to end through the webmail form: editing a synced override must not
// create a second event.
func TestWebmailEditOfSyncedOverride(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.PutObject(ctx, CollCalendar, Object{ID: "series-1", ContentType: "text/calendar", Data: []byte(phoneSeries), Name: "phone-name.ics"}); err != nil {
		t.Fatal(err)
	}
	csrf := h.login()
	uid := overrideUID("series-1", time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	resp := h.post("/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "uid": {uid}, "summary": {"Edited in browser"},
		"start_date": {"2026-10-12"}, "start_time": {"11:00"}, "end_date": {"2026-10-12"}, "end_time": {"12:00"},
		"busy": {"1"}, "reminder": {"-1"},
	})
	if resp.StatusCode != 303 {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if n := len(h.store.objects[CollCalendar]); n != 1 {
		t.Fatalf("%d objects after editing an override, want 1", n)
	}
	o := h.store.objects[CollCalendar]["series-1"]
	if !strings.Contains(string(o.Data), "SUMMARY:Edited in browser") || o.Name != "phone-name.ics" {
		t.Fatalf("stored = %s %q", o.Data, o.Name)
	}
}
