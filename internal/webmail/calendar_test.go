package webmail

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestEventRoundTrip(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	e := Event{
		UID: "abc@example.com", Summary: "Weekly sync, Q4", Location: "Room 4B; floor 2", Description: "Line one\nLine two",
		Start: time.Date(2026, 10, 19, 9, 0, 0, 0, ny), End: time.Date(2026, 10, 19, 9, 30, 0, 0, ny),
		RRule: "FREQ=WEEKLY;BYDAY=MO,WE", ExDates: []time.Time{time.Date(2026, 10, 21, 9, 0, 0, 0, ny)},
		Calendar: "Work", Organizer: &Attendee{Email: "dana@example.com", Name: "Dana Okafor"},
		Attendees: []Attendee{{Email: "priya@northwind.example", Name: "Priya Shah", Status: "ACCEPTED"}, {Email: "marcus@example.com", Optional: true}},
		Sequence:  2, Status: "CONFIRMED", Busy: true, Reminder: 15, URL: "https://meet.example.com/x",
	}
	data, err := encodeCalendar("", time.Now(), e.toComponent(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	cal, err := decodeCalendar(data, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	got := cal.Events[0]
	if got.Summary != e.Summary || got.Location != e.Location || got.Description != e.Description || got.Calendar != "Work" || got.URL != e.URL {
		t.Errorf("text fields = %+v", got)
	}
	if !got.Start.Equal(e.Start) || !got.End.Equal(e.End) || got.Start.Location().String() != "America/New_York" {
		t.Errorf("times = %v..%v", got.Start, got.End)
	}
	if got.RRule != e.RRule || len(got.ExDates) != 1 || !got.ExDates[0].Equal(e.ExDates[0]) {
		t.Errorf("recurrence = %q %v", got.RRule, got.ExDates)
	}
	if got.Organizer == nil || got.Organizer.Name != "Dana Okafor" || len(got.Attendees) != 2 || got.Attendees[0].Status != "ACCEPTED" || !got.Attendees[1].Optional || got.Attendees[1].Status != "NEEDS-ACTION" {
		t.Errorf("people = %+v %+v", got.Organizer, got.Attendees)
	}
	if got.Sequence != 2 || got.Reminder != 15 || !got.Busy {
		t.Errorf("sequence %d reminder %d busy %v", got.Sequence, got.Reminder, got.Busy)
	}
}

func TestRecurrenceKeepsLocalTimeAcrossDST(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	e := Event{UID: "x", Start: time.Date(2026, 10, 26, 9, 0, 0, 0, ny), End: time.Date(2026, 10, 26, 10, 0, 0, 0, ny), RRule: "FREQ=WEEKLY"}
	occ := e.occurrences(time.Date(2026, 10, 25, 0, 0, 0, 0, ny), time.Date(2026, 11, 10, 0, 0, 0, 0, ny))
	if len(occ) != 3 {
		t.Fatalf("occurrences = %d", len(occ))
	}
	for _, o := range occ {
		if o.Start.In(ny).Hour() != 9 || o.End.Sub(o.Start) != time.Hour {
			t.Errorf("occurrence at %v (DST ends Nov 1)", o.Start.In(ny))
		}
	}
}

func TestAllDayAndExDates(t *testing.T) {
	loc := time.UTC
	e := Event{UID: "o", AllDay: true, Start: time.Date(2026, 10, 21, 0, 0, 0, 0, loc), End: time.Date(2026, 10, 23, 0, 0, 0, 0, loc)}
	if o := e.occurrences(time.Date(2026, 10, 22, 0, 0, 0, 0, loc), time.Date(2026, 10, 23, 0, 0, 0, 0, loc)); len(o) != 1 {
		t.Fatalf("multi-day event missing from its second day: %v", o)
	}
	if o := e.occurrences(time.Date(2026, 10, 23, 0, 0, 0, 0, loc), time.Date(2026, 10, 24, 0, 0, 0, 0, loc)); len(o) != 0 {
		t.Fatalf("all-day end is exclusive, got %v", o)
	}
	d := Event{UID: "d", Start: time.Date(2026, 10, 1, 8, 0, 0, 0, loc), End: time.Date(2026, 10, 1, 9, 0, 0, 0, loc), RRule: "FREQ=DAILY;COUNT=5", ExDates: []time.Time{time.Date(2026, 10, 3, 8, 0, 0, 0, loc)}}
	if o := d.occurrences(time.Date(2026, 9, 1, 0, 0, 0, 0, loc), time.Date(2026, 11, 1, 0, 0, 0, 0, loc)); len(o) != 4 {
		t.Fatalf("COUNT=5 minus one EXDATE = %d occurrences", len(o))
	}
}

const outlookInvite = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nPRODID:Microsoft Exchange Server 2010\r\nVERSION:2.0\r\n" +
	"BEGIN:VEVENT\r\nORGANIZER;CN=Priya Shah:mailto:priya@northwind.example\r\n" +
	"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=dana@example.com:mailto:dana@example.com\r\n" +
	"SUMMARY;LANGUAGE=en-US:Contract review\r\nDTSTART;TZID=Eastern Standard Time:20261020T140000\r\n" +
	"DTEND;TZID=Eastern Standard Time:20261020T150000\r\nUID:040000008200E00074C5B7101A82E008\r\n" +
	"RRULE:FREQ=WEEKLY;COUNT=3;BYDAY=TU\r\nSEQUENCE:0\r\nDTSTAMP:20261017T120000Z\r\nLOCATION:Teams\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:040000008200E00074C5B7101A82E008\r\nRECURRENCE-ID;TZID=Eastern Standard Time:20261027T140000\r\n" +
	"DTSTART;TZID=Eastern Standard Time:20261027T160000\r\nDTEND;TZID=Eastern Standard Time:20261027T170000\r\n" +
	"SUMMARY:Contract review (moved)\r\nDTSTAMP:20261017T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

func TestDecodeWindowsZoneAndOverride(t *testing.T) {
	cal, err := decodeCalendar([]byte(outlookInvite), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if cal.Method != "REQUEST" || len(cal.Events) != 2 {
		t.Fatalf("method %q, %d events", cal.Method, len(cal.Events))
	}
	series := cal.Events[0]
	if series.Start.Location().String() != "America/New_York" || series.Start.Hour() != 14 {
		t.Errorf("Windows zone not mapped: %v", series.Start)
	}
	if len(series.ExDates) != 1 {
		t.Fatalf("override should exclude its date from the series: %v", series.ExDates)
	}
	occ := series.occurrences(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if len(occ) != 2 {
		t.Errorf("series occurrences = %d, want 2 of 3 (one moved)", len(occ))
	}
	moved := cal.Events[1]
	if moved.Summary != "Contract review (moved)" || moved.RRule != "" || moved.UID == series.UID || moved.Start.Hour() != 16 {
		t.Errorf("override = %+v", moved)
	}
}

func TestBuildRuleRoundTrip(t *testing.T) {
	loc := time.UTC
	start := time.Date(2026, 10, 19, 9, 0, 0, 0, loc) // a Monday
	f := &eventForm{Repeat: "weekly", Interval: 2, Days: map[int]bool{0: true, 2: true}, Ends: "until", Until: "2026-12-31"}
	rule, err := buildRule(f, start, loc)
	if err != nil {
		t.Fatal(err)
	}
	if rule != "FREQ=WEEKLY;BYDAY=MO,WE;INTERVAL=2;UNTIL=20261231T235959Z" {
		t.Fatalf("rule = %q", rule)
	}
	back := formFromEvent(&Event{Start: start, End: start.Add(time.Hour), RRule: rule, Reminder: -1}, start, loc)
	if back.Repeat != "weekly" || back.Interval != 2 || !back.Days[0] || !back.Days[2] || back.Ends != "until" || back.Until != "2026-12-31" {
		t.Fatalf("form = %+v", back)
	}
	if got := ruleSummary(rule, start); got != "Every 2 weeks on Mon, Wed, until Dec 31, 2026" {
		t.Errorf("summary = %q", got)
	}
	if got := ruleSummary("FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR", start); got != "Every weekday" {
		t.Errorf("weekday summary = %q", got)
	}
	if _, err := buildRule(&eventForm{Repeat: "daily", Ends: "count", Count: 0}, start, loc); err == nil {
		t.Error("COUNT=0 accepted")
	}
}

func TestLayoutDayLanes(t *testing.T) {
	day := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	mk := func(h, m, mins int) calItem {
		s := day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
		return calItem{Occ: Occurrence{Event: &Event{}, Start: s, End: s.Add(time.Duration(mins) * time.Minute)}}
	}
	items := []calItem{mk(10, 0, 60), mk(10, 30, 60), mk(13, 0, 15)}
	layoutDay(items, day)
	if items[0].PosClass != "q40 d4 lanes2 lane0" || items[1].PosClass != "q42 d4 lanes2 lane1" || items[2].PosClass != "q52 d2 short" {
		t.Fatalf("positions = %q %q %q", items[0].PosClass, items[1].PosClass, items[2].PosClass)
	}
	// Every class the layout can produce must exist in the stylesheet.
	css, _ := staticFS.ReadFile("static/tidewater.css")
	for _, c := range []string{".q95 ", ".d96 ", ".lanes4.lane3 "} {
		if !bytes.Contains(css, []byte(c)) {
			t.Errorf("stylesheet lacks %s", c)
		}
	}
}

func postForm(t *testing.T, h *harness, path string, form url.Values) *http.Response {
	t.Helper()
	return h.post(path, form)
}

func TestCalendarPagesAndExport(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := postForm(t, h, "/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "summary": {"Team standup"}, "start_date": {"2026-10-19"}, "start_time": {"09:30"},
		"end_date": {"2026-10-19"}, "end_time": {"09:45"}, "repeat": {"weekdays"}, "ends": {"never"}, "interval": {"1"},
		"calendar": {"Work"}, "reminder": {"5"}, "busy": {"busy"},
	})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "event-saved") {
		t.Fatalf("save = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, view := range []string{"month", "week", "day", "agenda"} {
		r, body := h.get("/calendar?view=" + view + "&date=2026-10-21")
		if r.StatusCode != http.StatusOK || !strings.Contains(body, "Team standup") {
			t.Errorf("%s view: status %d, event shown %v", view, r.StatusCode, strings.Contains(body, "Team standup"))
		}
	}
	_, body := h.get("/calendar?view=day&date=2026-10-24") // a Saturday
	if strings.Contains(body, "Team standup") {
		t.Error("weekday event shown on a Saturday")
	}
	_, ics := h.get("/calendar/export")
	if !strings.Contains(ics, "RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR") || !strings.Contains(ics, "BEGIN:VALARM") {
		t.Fatalf("export:\n%s", ics)
	}

	// Delete one occurrence; the series stays.
	uid := regexp.MustCompile(`UID:(\S+)`).FindStringSubmatch(ics)[1]
	occ := time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC).Unix()
	resp = postForm(t, h, "/calendar/event", url.Values{"csrf": {csrf}, "op": {"delete-occurrence"}, "uid": {uid}, "occ": {itoa64(occ)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete occurrence = %d", resp.StatusCode)
	}
	_, body = h.get("/calendar?view=day&date=2026-10-21")
	if strings.Contains(body, "Team standup") {
		t.Error("deleted occurrence still shown")
	}
	_, body = h.get("/calendar?view=day&date=2026-10-22")
	if !strings.Contains(body, "Team standup") {
		t.Error("series lost after deleting one occurrence")
	}

	// Edit only one occurrence: it splits out of the series.
	occ = time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC).Unix()
	resp = postForm(t, h, "/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "uid": {uid}, "occ": {itoa64(occ)}, "scope": {"this"}, "summary": {"Standup (moved)"},
		"start_date": {"2026-10-22"}, "start_time": {"11:00"}, "end_date": {"2026-10-22"}, "end_time": {"11:15"}, "repeat": {""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit occurrence = %d", resp.StatusCode)
	}
	_, body = h.get("/calendar?view=day&date=2026-10-22")
	if !strings.Contains(body, "Standup (moved)") || strings.Contains(body, ">Team standup<") {
		t.Errorf("split occurrence:\n%s", body)
	}
	if objs, _ := h.store.Objects(context.Background(), CollCalendar); len(objs) != 2 {
		t.Errorf("objects after split = %d", len(objs))
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func TestCalendarImport(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf", csrf)
	fw, _ := w.CreateFormFile("file", "invite.ics")
	_, _ = io.WriteString(fw, outlookInvite)
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/calendar/import", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("import = %d", resp.StatusCode)
	}
	if objs, _ := h.store.Objects(context.Background(), CollCalendar); len(objs) != 2 {
		t.Fatalf("imported %d objects, want series + override", len(objs))
	}
}

func TestEventFormValidation(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := postForm(t, h, "/calendar/event", url.Values{"csrf": {csrf}, "op": {"save"}, "summary": {"x"}, "start_date": {"2026-10-19"}, "start_time": {"10:00"}, "end_date": {"2026-10-19"}, "end_time": {"09:00"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("end before start = %d", resp.StatusCode)
	}
	resp = postForm(t, h, "/calendar/event", url.Values{"csrf": {csrf}, "op": {"save"}, "summary": {"x"}, "start_date": {"2026-10-19"}, "allday": {"1"}, "url": {"javascript:alert(1)"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("javascript: link = %d", resp.StatusCode)
	}
}

func TestInvitationsEndToEnd(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()

	// Organizer side: inviting a guest sends an iMIP REQUEST.
	resp := postForm(t, h, "/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "summary": {"Kickoff"}, "start_date": {"2026-10-20"}, "start_time": {"14:00"},
		"end_date": {"2026-10-20"}, "end_time": {"15:00"}, "attendees": {"Priya Shah <priya@northwind.example>"}, "notify": {"1"},
	})
	if !strings.Contains(resp.Header.Get("Location"), "invites-sent") {
		t.Fatalf("location = %q", resp.Header.Get("Location"))
	}
	inv, _ := parseMessage(h.sub.raw)
	raw := string(h.sub.raw) + string(inv.Calendar)
	if h.sub.rcpts[0] != "priya@northwind.example" || !strings.Contains(raw, "method=REQUEST") || !strings.Contains(raw, "Subject: Invitation: Kickoff") || !strings.Contains(raw, "ORGANIZER") {
		t.Fatalf("invitation:\n%s", raw)
	}

	// Guest side: an invitation arrives; the reader shows it; answering
	// stores the event and replies to the organizer.
	h.store.raw[9] = []byte("From: Priya Shah <priya@northwind.example>\r\nTo: dana@example.com\r\nSubject: Invitation: Contract review\r\n" +
		"Message-Id: <inv@northwind.example>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nYou're invited.\r\n--b\r\nContent-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
		outlookInvite + "--b--\r\n")
	_, page := h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, "Invitation: Contract review") || !strings.Contains(page, `value="ACCEPTED"`) {
		t.Fatalf("no invitation card:\n%s", page)
	}
	h.sub.raw = nil
	resp = postForm(t, h, "/calendar/rsvp", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"9"}, "op": {"ACCEPTED"}, "back": {"/mail?f=INBOX&uid=9"}})
	if !strings.Contains(resp.Header.Get("Location"), "rsvp-sent") {
		t.Fatalf("rsvp location = %q", resp.Header.Get("Location"))
	}
	parsed, err := parseMessage(h.sub.raw)
	if err != nil {
		t.Fatal(err)
	}
	reply := string(h.sub.raw) + string(parsed.Calendar)
	if h.sub.rcpts[0] != "priya@northwind.example" || !strings.Contains(reply, "method=REPLY") || !strings.Contains(reply, "PARTSTAT=ACCEPTED") || !strings.Contains(reply, "Subject: Accepted: Contract review") {
		t.Fatalf("reply:\n%s", reply)
	}
	if strings.Count(string(parsed.Calendar), "ATTENDEE") != 1 {
		t.Errorf("a REPLY carries only the replying attendee:\n%s", reply)
	}
	_, page = h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, "Your answer:") || !strings.Contains(page, "Going") {
		t.Errorf("card doesn't show the stored answer")
	}

	// Declining removes it from the calendar again.
	postForm(t, h, "/calendar/rsvp", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"9"}, "op": {"DECLINED"}})
	objs, _ := h.store.Objects(context.Background(), CollCalendar)
	for _, o := range objs {
		if strings.Contains(string(o.Data), "040000008200E00074C5B7101A82E008") {
			t.Fatal("declined event still in the calendar")
		}
	}
}

func TestTasks(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	postForm(t, h, "/tasks", url.Values{"csrf": {csrf}, "op": {"add"}, "summary": {"File expenses"}, "due": {"2020-01-01"}})
	postForm(t, h, "/tasks", url.Values{"csrf": {csrf}, "op": {"add"}, "summary": {"Book flights"}, "list_filter": {"Travel"}})
	_, body := h.get("/tasks")
	if !strings.Contains(body, "File expenses") || !strings.Contains(body, "overdue") || !strings.Contains(body, "Travel") {
		t.Fatalf("tasks page:\n%s", body)
	}
	objs, _ := h.store.Objects(context.Background(), CollTasks)
	var id string
	for _, o := range objs {
		if strings.Contains(string(o.Data), "File expenses") {
			id = o.ID
			if !strings.Contains(string(o.Data), "BEGIN:VTODO") || !strings.Contains(string(o.Data), "DUE;VALUE=DATE:20200101") {
				t.Fatalf("stored task:\n%s", o.Data)
			}
		}
	}
	postForm(t, h, "/tasks", url.Values{"csrf": {csrf}, "op": {"toggle"}, "id": {id}})
	_, body = h.get("/tasks")
	if strings.Contains(body, "File expenses") {
		t.Error("finished task shown under Open")
	}
	_, body = h.get("/tasks?show=done")
	if !strings.Contains(body, "File expenses") {
		t.Error("finished task missing from Done")
	}
	postForm(t, h, "/tasks", url.Values{"csrf": {csrf}, "op": {"clear-done"}, "show": {"done"}})
	if objs, _ := h.store.Objects(context.Background(), CollTasks); len(objs) != 1 {
		t.Fatalf("after clearing finished tasks: %d left", len(objs))
	}
}
