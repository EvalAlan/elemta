package webmail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	sharedOwner = "priya@example.com"
	sharedLogin = "dana|" + sharedOwner + calendarLoginSuffix
)

func sharedEventObject(uid, summary, extra string) Object {
	start := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Hour)
	data := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\nUID:" + uid +
		"\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:" + start.Format("20060102T150405Z") +
		"\r\nDTEND:" + start.Add(time.Hour).Format("20060102T150405Z") + "\r\nSUMMARY:" + summary +
		"\r\nLOCATION:Room of secrets\r\nDESCRIPTION:Hidden notes\r\nX-ELEMTA-CALENDAR:Work\r\n" + extra +
		"END:VEVENT\r\nEND:VCALENDAR\r\n"
	return Object{ID: uid, Title: summary, ContentType: "text/calendar", Data: []byte(data)}
}

// sharedRig signs dana in with priya's calendar shared at level, and records
// every login that reaches the store.
type sharedRig struct {
	h        *harness
	csrf     string
	owner    *fakeStore
	security *fakeSecurity
	dialed   []string
}

func newSharedRig(t *testing.T, level string) *sharedRig {
	t.Helper()
	security := &fakeSecurity{}
	if level != "" {
		security.calendars.Received = []calendarShare{{Owner: sharedOwner, OwnerID: "priya-id", Member: "dana@example.com", Level: level}}
	}
	h := newSecurityHarness(t, security)
	r := &sharedRig{h: h, security: security, owner: newFakeStore()}
	own := h.server.dial
	h.server.dial = func(ctx context.Context, user, password string) (Mailstore, error) {
		r.dialed = append(r.dialed, user)
		if isCalendarLogin(user) {
			if user != sharedLogin || level == "" {
				return nil, ErrAuthFailed
			}
			return r.owner, nil
		}
		return own(ctx, user, password)
	}
	r.csrf = h.login()
	return r
}

func (r *sharedRig) put(t *testing.T, objs ...Object) {
	t.Helper()
	for _, o := range objs {
		if err := r.owner.PutObject(context.Background(), CollCalendar, o); err != nil {
			t.Fatal(err)
		}
	}
}

func (r *sharedRig) save(form url.Values) *http.Response {
	form.Set("csrf", r.csrf)
	form.Set("op", "save")
	form.Set("summary", "Booked by Dana")
	form.Set("start_date", "2026-12-01")
	form.Set("start_time", "09:00")
	form.Set("end_date", "2026-12-01")
	form.Set("end_time", "10:00")
	form.Set("busy", "busy")
	return r.h.post("/calendar/event", form)
}

func TestSharedCalendarAppearsBesideTheUsers(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	_, page := r.h.get("/calendar?view=agenda")
	for _, want := range []string{"Board review", "Shared with you", "owner=priya%40example.com"} {
		if !strings.Contains(page, want) {
			t.Errorf("calendar page lacks %q", want)
		}
	}
}

// The page is what crosses to the browser, so a private event's details must
// not be anywhere in it, hidden or not.
func TestViewAccessNeverSeesPrivateDetails(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("secret-1", "Surgery consult", "CLASS:PRIVATE\r\n"),
		sharedEventObject("secret-2", "Job interview", "CLASS:CONFIDENTIAL\r\n"))
	pages := []string{"/calendar?view=agenda", "/calendar/event?uid=secret-1&owner=" + url.QueryEscape(sharedOwner)}
	for _, path := range pages {
		_, page := r.h.get(path)
		for _, leak := range []string{"Surgery consult", "Job interview", "Room of secrets", "Hidden notes"} {
			if strings.Contains(page, leak) {
				t.Errorf("%s shows %q", path, leak)
			}
		}
		if !strings.Contains(page, "Busy") {
			t.Errorf("%s doesn't show the time as busy", path)
		}
	}
}

func TestEditAccessSeesPrivateEvents(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.put(t, sharedEventObject("secret-1", "Surgery consult", "CLASS:PRIVATE\r\n"))
	_, page := r.h.get("/calendar/event?uid=secret-1&owner=" + url.QueryEscape(sharedOwner))
	if !strings.Contains(page, "Surgery consult") {
		t.Fatal("someone editing a calendar could double-book what they can't see")
	}
}

func TestViewAccessCantChangeAnything(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	if resp := r.save(url.Values{"owner": {sharedOwner}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("save: status %d", resp.StatusCode)
	}
	if resp := r.save(url.Values{"owner": {sharedOwner}, "uid": {"open-1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("edit: status %d", resp.StatusCode)
	}
	resp := r.h.post("/calendar/event", url.Values{"csrf": {r.csrf}, "op": {"delete"}, "uid": {"open-1"}, "owner": {sharedOwner}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete: status %d", resp.StatusCode)
	}
	if got, _ := r.h.get("/calendar/event?new=1&owner=" + url.QueryEscape(sharedOwner)); got.StatusCode == http.StatusOK {
		t.Error("offered a new event form")
	}
	_, page := r.h.get("/calendar/event?uid=open-1&edit=1&owner=" + url.QueryEscape(sharedOwner))
	if strings.Contains(page, `name="summary"`) {
		t.Error("offered the edit form")
	}
	objs, _ := r.owner.Objects(context.Background(), CollCalendar)
	if len(objs) != 1 {
		t.Fatalf("the calendar holds %d objects", len(objs))
	}
}

func TestEditGoesToTheOwnersCalendar(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	ctx := context.Background()
	resp := r.save(url.Values{"owner": {sharedOwner}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "owner=") {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	theirs, _ := r.owner.Objects(ctx, CollCalendar)
	if len(theirs) != 1 || !strings.Contains(string(theirs[0].Data), "Booked by Dana") {
		t.Fatalf("owner's calendar: %d objects", len(theirs))
	}
	mine, _ := r.h.store.Objects(ctx, CollCalendar)
	if len(mine) != 0 {
		t.Fatalf("the event also landed on the editor's own calendar: %d", len(mine))
	}
}

// The event is shown under the owner's name, which mustn't be saved over
// the label they gave it.
func TestEditKeepsTheOwnersLabel(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	_, form := r.h.get("/calendar/event?uid=open-1&edit=1&owner=" + url.QueryEscape(sharedOwner))
	if !strings.Contains(form, `value="Work"`) {
		t.Fatal("the form lost the event's own label")
	}
	if strings.Contains(form, `value="priya"`) {
		t.Fatal("the form offers the owner's name as the label")
	}
}

func TestGuestsStayOffSharedEvents(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	guests := "ORGANIZER:mailto:" + sharedOwner + "\r\nATTENDEE:mailto:guest@example.org\r\n"
	r.put(t, sharedEventObject("meeting-1", "Client call", guests))
	if resp := r.save(url.Values{"owner": {sharedOwner}, "attendees": {"guest@example.org"}, "notify": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("adding guests: status %d", resp.StatusCode)
	}
	if resp := r.save(url.Values{"owner": {sharedOwner}, "uid": {"meeting-1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("changing a meeting: status %d", resp.StatusCode)
	}
	resp := r.h.post("/calendar/event", url.Values{"csrf": {r.csrf}, "op": {"delete"}, "uid": {"meeting-1"}, "owner": {sharedOwner}, "notify": {"1"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cancelling a meeting: status %d", resp.StatusCode)
	}
	if r.h.sub.from != "" {
		t.Fatalf("mail went out from %q", r.h.sub.from)
	}
	objs, _ := r.owner.Objects(context.Background(), CollCalendar)
	if len(objs) != 1 {
		t.Fatalf("the calendar holds %d objects", len(objs))
	}
}

func TestNoShareNoCalendar(t *testing.T) {
	r := newSharedRig(t, "")
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	resp, page := r.h.get("/calendar/event?uid=open-1&owner=" + url.QueryEscape(sharedOwner))
	if resp.StatusCode == http.StatusOK || strings.Contains(page, "Board review") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := r.save(url.Values{"owner": {sharedOwner}}); got.StatusCode != http.StatusForbidden {
		t.Fatalf("save: status %d", got.StatusCode)
	}
	for _, user := range r.dialed {
		if isCalendarLogin(user) {
			t.Fatalf("tried a calendar login without a share: %s", user)
		}
	}
}

func TestHidingASharedCalendar(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	r.h.post("/calendar/shared", url.Values{"csrf": {r.csrf}, "owner": {sharedOwner}, "hide": {"1"}})
	r.dialed = nil
	_, page := r.h.get("/calendar?view=agenda")
	if strings.Contains(page, "Board review") {
		t.Fatal("a hidden calendar still shows")
	}
	if !strings.Contains(page, "Shared with you") {
		t.Fatal("a hidden calendar can't be turned back on")
	}
	for _, user := range r.dialed {
		if isCalendarLogin(user) {
			t.Fatal("opened a calendar that's hidden")
		}
	}
	r.h.post("/calendar/shared", url.Values{"csrf": {r.csrf}, "owner": {sharedOwner}, "hide": {"0"}})
	if _, page := r.h.get("/calendar?view=agenda"); !strings.Contains(page, "Board review") {
		t.Fatal("showing it again didn't work")
	}
}

// A calendar someone can't reach is theirs to lose, not the user's whole page.
func TestUnreadableSharedCalendarDoesntBreakTheUsers(t *testing.T) {
	r := newSharedRig(t, accessView)
	inner := r.h.server.dial
	r.h.server.dial = func(ctx context.Context, user, password string) (Mailstore, error) {
		if isCalendarLogin(user) {
			return nil, ErrAuthFailed
		}
		return inner(ctx, user, password)
	}
	resp, page := r.h.get("/calendar?view=agenda")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "unavailable") {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestSharingFromSettings(t *testing.T) {
	r := newSharedRig(t, "")
	r.security.calendars.Granted = []calendarShare{{Owner: "dana@example.com", Member: "sam@example.com", Level: accessEdit}}
	_, page := r.h.get("/settings/account")
	if !strings.Contains(page, "sam@example.com") || !strings.Contains(page, "Share calendar") {
		t.Fatal("the settings page doesn't show who can see the calendar")
	}
	resp := r.h.post("/settings/calendar-shares", url.Values{"csrf": {r.csrf}, "member": {" Lee@Example.com "}, "level": {accessView}})
	if !strings.Contains(resp.Header.Get("Location"), "calendar-shared") {
		t.Fatalf("location %q", resp.Header.Get("Location"))
	}
	r.h.post("/settings/calendar-shares", url.Values{"csrf": {r.csrf}, "op": {"remove"}, "member": {"sam@example.com"}})
	calls := strings.Join(r.security.calendarCalls, "\n")
	if !strings.Contains(calls, "PUT /v1/calendar-shares/lee@example.com view") || !strings.Contains(calls, "DELETE /v1/calendar-shares/sam@example.com") {
		t.Fatalf("calls:\n%s", calls)
	}
	// Delegate isn't offered yet, whatever a form posts.
	r.security.calendarCalls = nil
	resp = r.h.post("/settings/calendar-shares", url.Values{"csrf": {r.csrf}, "member": {"lee@example.com"}, "level": {"owner"}})
	if len(r.security.calendarCalls) != 0 || !strings.Contains(resp.Header.Get("Location"), "invalid") {
		t.Fatalf("accepted a level: %v", r.security.calendarCalls)
	}
	r.security.calendarDenied = true
	resp = r.h.post("/settings/calendar-shares", url.Values{"csrf": {r.csrf}, "member": {"gone@example.com"}, "level": {accessView}})
	if !strings.Contains(resp.Header.Get("Location"), "failed") {
		t.Fatalf("location %q", resp.Header.Get("Location"))
	}
}

// Hiding private events is decided here rather than by the mailbox, so the
// level has to be read fresh: nothing may keep showing them after a cut.
func TestCutBackToViewHidesPrivateEventsAtOnce(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.put(t, sharedEventObject("secret-1", "Surgery consult", "CLASS:PRIVATE\r\n"))
	if _, page := r.h.get("/calendar?view=agenda"); !strings.Contains(page, "Surgery consult") {
		t.Fatal("edit access should show it")
	}
	r.security.mu.Lock()
	r.security.calendars.Received[0].Level = accessView
	r.security.mu.Unlock()
	if _, page := r.h.get("/calendar?view=agenda"); strings.Contains(page, "Surgery consult") {
		t.Fatal("still shown after the cut")
	}
}

func TestNewShareShowsAtOnce(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	r.security.mu.Lock()
	received := r.security.calendars.Received
	r.security.calendars.Received = nil
	r.security.mu.Unlock()
	if _, page := r.h.get("/calendar?view=agenda"); strings.Contains(page, "Board review") {
		t.Fatal("shown without a share")
	}
	r.security.mu.Lock()
	r.security.calendars.Received = received
	r.security.mu.Unlock()
	if _, page := r.h.get("/calendar?view=agenda"); !strings.Contains(page, "Board review") {
		t.Fatal("a new share waited for a cache")
	}
}
