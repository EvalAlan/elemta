package webmail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/go-webdav/carddav"
)

func davRequest(t *testing.T, h *harness, method, path, user, pw, body string, header map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, pw)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func davEvent(uid, summary string, start time.Time) *ical.Calendar {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	ev := ical.NewEvent()
	ev.Props.SetText(ical.PropUID, uid)
	ev.Props.SetDateTime(ical.PropDateTimeStamp, start)
	ev.Props.SetDateTime(ical.PropDateTimeStart, start)
	ev.Props.SetDateTime(ical.PropDateTimeEnd, start.Add(time.Hour))
	ev.Props.SetText(ical.PropSummary, summary)
	cal.Children = append(cal.Children, ev.Component)
	return cal
}

func TestDAVAuth(t *testing.T) {
	h := newHarness(t)
	resp := davRequest(t, h, "PROPFIND", "/dav/", "", "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no credentials = %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp := davRequest(t, h, "PROPFIND", "/dav/", "user@example.com", "wrong", "", map[string]string{"Depth": "0"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", resp.StatusCode)
	}
	// Failures count toward the same limit as the sign-in page.
	for i := 0; i < maxFailuresPerUser; i++ {
		davRequest(t, h, "PROPFIND", "/dav/", "user@example.com", "wrong", "", nil)
	}
	if resp := davRequest(t, h, "PROPFIND", "/dav/", "user@example.com", "secret", "", map[string]string{"Depth": "0"}); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after repeated failures = %d, want 429", resp.StatusCode)
	}
	for _, p := range []string{"/.well-known/caldav", "/.well-known/carddav"} {
		if resp := davRequest(t, h, "PROPFIND", p, "", "", "", nil); resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != davRoot {
			t.Fatalf("%s = %d %q", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestDAVCachedConnectionRechecksSecurityPolicy(t *testing.T) {
	security := &fakeSecurity{}
	h := newSecurityHarness(t, security)
	request := func() int {
		r := httptest.NewRequest(http.MethodGet, "/dav/", nil)
		r.SetBasicAuth("dana", "secret")
		w := httptest.NewRecorder()
		if _, ok := h.server.davAuth(w, r); ok {
			return http.StatusOK
		}
		return w.Code
	}
	if got := request(); got != http.StatusOK {
		t.Fatalf("initial DAV request = %d", got)
	}
	security.mu.Lock()
	security.appRequired = true
	security.mu.Unlock()
	if got := request(); got != http.StatusUnauthorized {
		t.Fatalf("cached account password after policy change = %d", got)
	}
}

func TestCalDAV(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	hc := webdav.HTTPClientWithBasicAuth(http.DefaultClient, "user@example.com", "secret")
	cl, err := caldav.NewClient(hc, h.srv.URL+davRoot)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := cl.FindCurrentUserPrincipal(ctx)
	if err != nil || principal != davRoot {
		t.Fatalf("principal = %q, %v", principal, err)
	}
	home, err := cl.FindCalendarHomeSet(ctx, principal)
	if err != nil || home != davCalendarHome {
		t.Fatalf("home = %q, %v", home, err)
	}
	cals, err := cl.FindCalendars(ctx, home)
	if err != nil || len(cals) != 2 {
		t.Fatalf("calendars = %+v, %v", cals, err)
	}

	// A client's own resource name is kept; the object is stored by UID,
	// which is how the webmail finds it.
	start := time.Now().UTC().Truncate(time.Hour).Add(24 * time.Hour)
	evPath := davCalendarHome + "events/client-name.ics"
	co, err := cl.PutCalendarObject(ctx, evPath, davEvent("uid-1@test", "Planning from phone", start))
	if err != nil {
		t.Fatal(err)
	}
	if co.ETag == "" {
		t.Error("PUT returned no ETag")
	}
	stored := h.store.objects[CollCalendar]["uid-1@test"]
	if stored.Name != "client-name.ics" {
		t.Fatalf("stored object = %+v", stored)
	}
	got, err := cl.GetCalendarObject(ctx, evPath)
	if err != nil || got.Data.Events()[0].Props.Get(ical.PropSummary).Value != "Planning from phone" {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// The webmail shows it.
	h.login()
	if _, page := h.get("/calendar?view=agenda&date=" + start.Format("2006-01-02")); !strings.Contains(page, "Planning from phone") {
		t.Fatal("event made over CalDAV isn't in the webmail calendar")
	}

	// An edit that doesn't know the name (as the webmail's) keeps it.
	stored.Name = ""
	stored.Title = "edited"
	if err := h.store.PutObject(ctx, CollCalendar, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.GetCalendarObject(ctx, evPath); err != nil {
		t.Fatalf("resource name lost after an edit: %v", err)
	}

	// Conditional requests protect concurrent edits.
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nBEGIN:VEVENT\r\nUID:uid-1@test\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260101T100000Z\r\nSUMMARY:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	ct := map[string]string{"Content-Type": "text/calendar"}
	withHeader := func(k, v string) map[string]string { return map[string]string{"Content-Type": "text/calendar", k: v} }
	if resp := davRequest(t, h, "PUT", evPath, "user@example.com", "secret", ics, withHeader("If-Match", `"stale"`)); resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match = %d", resp.StatusCode)
	}
	if resp := davRequest(t, h, "PUT", evPath, "user@example.com", "secret", ics, withHeader("If-None-Match", "*")); resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("If-None-Match on an existing resource = %d", resp.StatusCode)
	}
	// One UID can't live under two names, and a calendar takes only its
	// own component type.
	if resp := davRequest(t, h, "PUT", davCalendarHome+"events/other.ics", "user@example.com", "secret", ics, ct); resp.StatusCode < 400 {
		t.Errorf("duplicate UID = %d", resp.StatusCode)
	}
	todo := strings.ReplaceAll(strings.ReplaceAll(ics, "VEVENT", "VTODO"), "uid-1@test", "todo-1")
	if resp := davRequest(t, h, "PUT", davCalendarHome+"events/todo.ics", "user@example.com", "secret", todo, ct); resp.StatusCode < 400 {
		t.Errorf("VTODO in the events calendar = %d", resp.StatusCode)
	}
	if resp := davRequest(t, h, "PUT", davCalendarHome+"tasks/todo-1.ics", "user@example.com", "secret", todo, ct); resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		t.Errorf("VTODO in the tasks calendar = %d", resp.StatusCode)
	}
	if _, ok := h.store.objects[CollTasks]["todo-1"]; !ok {
		t.Error("task wasn't stored with the webmail's tasks")
	}

	// Queries filter by component.
	objs, err := cl.QueryCalendar(ctx, davCalendarHome+"events/", &caldav.CalendarQuery{CompFilter: caldav.CompFilter{Name: ical.CompCalendar, Comps: []caldav.CompFilter{{Name: ical.CompEvent}}}})
	if err != nil || len(objs) != 1 || objs[0].Path != evPath {
		t.Fatalf("query = %+v, %v", objs, err)
	}

	if resp := davRequest(t, h, "DELETE", evPath, "user@example.com", "secret", "", withHeader("If-Match", `"stale"`)); resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale conditional delete = %d", resp.StatusCode)
	}
	if _, ok := h.store.objects[CollCalendar]["uid-1@test"]; !ok {
		t.Fatal("stale conditional delete removed the object")
	}
	if resp := davRequest(t, h, "DELETE", evPath, "user@example.com", "secret", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if _, ok := h.store.objects[CollCalendar]["uid-1@test"]; ok {
		t.Fatal("delete left the object")
	}
	if resp := davRequest(t, h, "GET", evPath, "user@example.com", "secret", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d", resp.StatusCode)
	}
}

func TestCalDAVServesWebmailEvents(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	e := Event{UID: "web-1", Summary: "Made in the webmail", Start: now, End: now.Add(time.Hour), Busy: true, Reminder: -1}
	data, err := encodeCalendar("", now, e.toComponent(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutObject(ctx, CollCalendar, Object{ID: e.UID, Title: e.Summary, ContentType: "text/calendar", Data: data}); err != nil {
		t.Fatal(err)
	}
	cl, err := caldav.NewClient(webdav.HTTPClientWithBasicAuth(http.DefaultClient, "user@example.com", "secret"), h.srv.URL+davRoot)
	if err != nil {
		t.Fatal(err)
	}
	co, err := cl.GetCalendarObject(ctx, davCalendarHome+"events/web-1.ics")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := caldav.ValidateCalendarObject(co.Data); err != nil {
		t.Fatalf("webmail event isn't valid for CalDAV clients: %v", err)
	}
}

func TestCardDAV(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cl, err := carddav.NewClient(webdav.HTTPClientWithBasicAuth(http.DefaultClient, "user@example.com", "secret"), h.srv.URL+davRoot)
	if err != nil {
		t.Fatal(err)
	}
	home, err := cl.FindAddressBookHomeSet(ctx, davRoot)
	if err != nil || home != davContactsHome {
		t.Fatalf("home = %q, %v", home, err)
	}
	books, err := cl.FindAddressBooks(ctx, home)
	if err != nil || len(books) != 1 {
		t.Fatalf("books = %+v, %v", books, err)
	}
	card := vcard.Card{}
	card.SetValue(vcard.FieldVersion, "3.0")
	card.SetValue(vcard.FieldUID, "card-1")
	card.SetValue(vcard.FieldFormattedName, "Ana Phone")
	card.SetValue(vcard.FieldEmail, "ana@example.com")
	p := books[0].Path + "card-1.vcf"
	if _, err := cl.PutAddressObject(ctx, p, card); err != nil {
		t.Fatal(err)
	}
	if o := h.store.objects[CollContacts]["card-1"]; o.Name != "" || o.Title != "Ana Phone" {
		t.Fatalf("stored = %+v", o)
	}
	h.login()
	if _, page := h.get("/settings/devices"); !strings.Contains(page, h.srv.URL+davRoot) {
		t.Error("settings don't show the sync address")
	}
	if _, page := h.get("/contacts"); !strings.Contains(page, "Ana Phone") {
		t.Fatal("contact made over CardDAV isn't in the webmail")
	}
	// Listing the address book with an empty filter, as clients do on
	// first sync, returns every card.
	if all, err := cl.QueryAddressBook(ctx, books[0].Path, &carddav.AddressBookQuery{}); err != nil || len(all) != 1 {
		t.Fatalf("query with no filter = %+v, %v", all, err)
	}
	got, err := cl.GetAddressObject(ctx, p)
	if err != nil || got.Card.PreferredValue(vcard.FieldEmail) != "ana@example.com" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	// A card without a UID is refused rather than stored unaddressable.
	bad := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:No UID\r\nEND:VCARD\r\n"
	if resp := davRequest(t, h, "PUT", books[0].Path+"x.vcf", "user@example.com", "secret", bad, map[string]string{"Content-Type": "text/vcard"}); resp.StatusCode < 400 {
		t.Errorf("card without UID = %d", resp.StatusCode)
	}
	if resp := davRequest(t, h, "DELETE", p, "user@example.com", "secret", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
}
