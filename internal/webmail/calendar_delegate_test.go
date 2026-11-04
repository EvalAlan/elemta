package webmail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
)

// sentCalendar decodes the calendar in the last message submitted.
func sentCalendar(t *testing.T, r *sharedRig) calendarDoc {
	t.Helper()
	msg, err := parseMessage(r.h.sub.raw)
	if err != nil || len(msg.Calendar) == 0 {
		t.Fatalf("no calendar in %q: %v", r.h.sub.raw, err)
	}
	cal, err := decodeCalendar(msg.Calendar, time.UTC)
	if err != nil || len(cal.Events) == 0 {
		t.Fatalf("decode: %v", err)
	}
	return calendarDoc{Method: cal.Method, Event: cal.Events[0], Reply: msg}
}

type calendarDoc struct {
	Method string
	Event  Event
	Reply  *Message
}

// A delegate's invitation names the owner as organizer and comes from the
// delegate: no mail is ever sent as the owner.
func TestDelegateInvitesForTheOwner(t *testing.T) {
	r := newSharedRig(t, accessDelegate)
	resp := r.save(url.Values{"owner": {sharedOwner}, "attendees": {"guest@example.org"}, "notify": {"1"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "invites-sent") {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if strings.EqualFold(r.h.sub.from, sharedOwner) {
		t.Fatal("the envelope is in the owner's name")
	}
	got := sentCalendar(t, r)
	if got.Event.Organizer == nil || got.Event.Organizer.Email != sharedOwner || got.Event.Organizer.SentBy == "" {
		t.Fatalf("organizer %+v", got.Event.Organizer)
	}
	if !strings.Contains(string(r.h.sub.raw), "Reply-To: "+sharedOwner) && !strings.Contains(string(r.h.sub.raw), "<"+sharedOwner+">") {
		t.Fatalf("answers wouldn't reach the owner:\n%s", r.h.sub.raw)
	}
	objs, _ := r.owner.Objects(context.Background(), CollCalendar)
	if len(objs) != 1 {
		t.Fatalf("owner's calendar: %d objects", len(objs))
	}
	stored := string(objs[0].Data)
	if !strings.Contains(stored, sharedOwner) || strings.Contains(stored, paramSentBy) {
		t.Fatalf("stored event:\n%s", stored)
	}
}

// Edit access is what it was: guests still need delegate access.
func TestEditCantInviteOrCancelGuests(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.put(t, sharedEventObject("meeting-1", "Standup", "ORGANIZER:mailto:"+sharedOwner+"\r\nATTENDEE:mailto:guest@example.org\r\n"))
	if resp := r.save(url.Values{"owner": {sharedOwner}, "attendees": {"guest@example.org"}, "notify": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("invite: status %d", resp.StatusCode)
	}
	resp := r.h.post("/calendar/event", url.Values{"csrf": {r.csrf}, "op": {"delete"}, "uid": {"meeting-1"}, "owner": {sharedOwner}, "notify": {"1"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete: status %d", resp.StatusCode)
	}
	if r.h.sub.raw != nil {
		t.Error("mail was sent")
	}
}

func TestDelegateCancelsForTheOwner(t *testing.T) {
	r := newSharedRig(t, accessDelegate)
	r.put(t, sharedEventObject("meeting-1", "Standup", "ORGANIZER:mailto:"+sharedOwner+"\r\nATTENDEE:mailto:guest@example.org\r\n"))
	_, page := r.h.get("/calendar/event?uid=meeting-1&owner=" + url.QueryEscape(sharedOwner))
	if !strings.Contains(page, "edit=1") || !strings.Contains(page, `name="notify"`) {
		t.Fatal("a delegate isn't offered edit and cancel")
	}
	r.h.post("/calendar/event", url.Values{"csrf": {r.csrf}, "op": {"delete"}, "uid": {"meeting-1"}, "owner": {sharedOwner}, "notify": {"1"}})
	if got := sentCalendar(t, r); got.Method != "CANCEL" || got.Event.Organizer.SentBy == "" {
		t.Fatalf("cancellation %+v", got)
	}
	if objs, _ := r.owner.Objects(context.Background(), CollCalendar); len(objs) != 0 {
		t.Fatalf("%d objects left", len(objs))
	}
}

const delegatedInvite = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:inv-1@example.org\r\n" +
	"DTSTAMP:20261001T000000Z\r\nDTSTART:20261201T090000Z\r\nDTEND:20261201T100000Z\r\nSUMMARY:Vendor call\r\n" +
	"ORGANIZER:mailto:vendor@example.org\r\nATTENDEE:mailto:" + sharedOwner + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

func delegatedInviteMessage() []byte {
	return []byte("From: <vendor@example.org>\r\nTo: " + sharedOwner + "\r\nSubject: Invitation\r\nMessage-Id: <i@example.org>\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" + delegatedInvite)
}

// The invitation reaches a delegate's inbox addressed to someone else, and
// the answer lands in the owner's calendar and speaks for the owner.
func TestDelegateAnswersAnInvitation(t *testing.T) {
	r := newSharedRig(t, accessDelegate)
	r.h.store.raw[9] = delegatedInviteMessage()
	_, page := r.h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, "as their delegate") || !strings.Contains(page, `name="owner" value="`+sharedOwner+`"`) {
		t.Fatalf("no delegate card:\n%s", page)
	}
	resp := r.h.post("/calendar/rsvp", url.Values{"csrf": {r.csrf}, "f": {"INBOX"}, "uid": {"9"}, "owner": {sharedOwner}, "op": {"ACCEPTED"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", resp.StatusCode)
	}
	mine, _ := r.h.store.Objects(context.Background(), CollCalendar)
	theirs, _ := r.owner.Objects(context.Background(), CollCalendar)
	if len(mine) != 0 || len(theirs) != 1 {
		t.Fatalf("mine %d, theirs %d", len(mine), len(theirs))
	}
	got := sentCalendar(t, r)
	if got.Method != "REPLY" || len(got.Event.Attendees) != 1 {
		t.Fatalf("reply %+v", got)
	}
	a := got.Event.Attendees[0]
	if a.Email != sharedOwner || a.SentBy == "" || a.Status != "ACCEPTED" {
		t.Fatalf("attendee %+v", a)
	}
}

// Someone with edit access reads such a message like any other, and a forged
// form gets nowhere.
func TestOnlyDelegatesAnswerForSomeoneElse(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.h.store.raw[9] = delegatedInviteMessage()
	if _, page := r.h.get("/mail?f=INBOX&uid=9"); strings.Contains(page, "as their delegate") {
		t.Fatal("edit access offered a delegate's card")
	}
	resp := r.h.post("/calendar/rsvp", url.Values{"csrf": {r.csrf}, "f": {"INBOX"}, "uid": {"9"}, "owner": {sharedOwner}, "op": {"ACCEPTED"}})
	if resp.StatusCode != http.StatusForbidden || r.h.sub.raw != nil {
		t.Fatalf("status %d, sent %v", resp.StatusCode, r.h.sub.raw != nil)
	}
}

func TestApplyReplyTrustsSentByOnlyInsideTheDomain(t *testing.T) {
	stored := func() *Event {
		return &Event{Attendees: []Attendee{{Email: "priya@example.com", Status: "NEEDS-ACTION"}}}
	}
	reply := func(sentBy string) Event {
		return Event{Attendees: []Attendee{{Email: "priya@example.com", Status: "ACCEPTED", SentBy: sentBy}}}
	}
	if !applyReply(stored(), reply("dana@example.com"), "dana@example.com") {
		t.Error("a colleague's answer for the guest was dropped")
	}
	if applyReply(stored(), reply("mallory@evil.example"), "mallory@evil.example") {
		t.Error("anyone can answer for a guest by writing SENT-BY")
	}
	if applyReply(stored(), reply("dana@example.com"), "mallory@example.com") {
		t.Error("SENT-BY naming someone other than the sender counted")
	}
}

func TestSentByRoundTrips(t *testing.T) {
	now := time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)
	e := Event{UID: "u", Summary: "s", Start: now, End: now.Add(time.Hour), Busy: true, Reminder: -1,
		Organizer: &Attendee{Email: "o@example.com", SentBy: "d@example.com"},
		Attendees: []Attendee{{Email: "a@example.com", Status: "ACCEPTED", SentBy: "d@example.com"}}}
	data, err := encodeCalendar("REQUEST", now, e.toComponent(now))
	if err != nil {
		t.Fatal(err)
	}
	cal, err := decodeCalendar(data, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	got := cal.Events[0]
	if got.Organizer.SentBy != "d@example.com" || got.Attendees[0].SentBy != "d@example.com" {
		t.Fatalf("%+v %+v\n%s", got.Organizer, got.Attendees, data)
	}
}

// ---- CalDAV ----------------------------------------------------------------

func sharedDAV(t *testing.T, r *sharedRig) *caldav.Client {
	t.Helper()
	cl, err := caldav.NewClient(webdav.HTTPClientWithBasicAuth(http.DefaultClient, "dana", "secret"), r.h.srv.URL+davRoot)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

var sharedDAVPath = davSharedHome + sharedOwner + "/"

func TestSharedCalendarIsListedInCalDAV(t *testing.T) {
	r := newSharedRig(t, accessView)
	cals, err := sharedDAV(t, r).FindCalendars(context.Background(), davCalendarHome)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cals {
		found = found || c.Path == sharedDAVPath
	}
	if len(cals) != 3 || !found {
		t.Fatalf("calendars %+v", cals)
	}
}

func TestCalDAVNoShareNoCalendar(t *testing.T) {
	r := newSharedRig(t, "")
	cl := sharedDAV(t, r)
	cals, err := cl.FindCalendars(context.Background(), davCalendarHome)
	if err != nil || len(cals) != 2 {
		t.Fatalf("calendars %+v, %v", cals, err)
	}
	if _, err := cl.GetCalendarObject(context.Background(), sharedDAVPath+"x.ics"); err == nil {
		t.Fatal("reached a calendar with no share")
	}
	if _, err := cl.PutCalendarObject(context.Background(), sharedDAVPath+"x.ics", davEvent("x@t", "s", time.Now().UTC())); err == nil {
		t.Fatal("wrote to a calendar with no share")
	}
}

// A client gets raw objects, so nothing of a private event may survive in one:
// not the summary, not the location, not an unknown property.
func TestCalDAVViewNeverSeesPrivateDetails(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("secret-1", "Surgery consult", "CLASS:PRIVATE\r\nX-NOTES:unknown leak\r\nATTENDEE:mailto:doctor@example.org\r\n"),
		sharedEventObject("open-1", "Board review", ""))
	objs, err := sharedDAV(t, r).QueryCalendar(context.Background(), sharedDAVPath, &caldav.CalendarQuery{
		CompFilter:  caldav.CompFilter{Name: ical.CompCalendar},
		CompRequest: caldav.CalendarCompRequest{Name: ical.CompCalendar, AllProps: true, AllComps: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 {
		t.Fatalf("%d objects", len(objs))
	}
	var private, open strings.Builder
	for _, o := range objs {
		text := &open
		if strings.Contains(o.Path, "secret-1") {
			text = &private
		}
		if err := ical.NewEncoder(text).Encode(o.Data); err != nil {
			t.Fatal(err)
		}
	}
	for _, leak := range []string{"Surgery consult", "Room of secrets", "Hidden notes", "unknown leak", "doctor@example.org", "X-ELEMTA-CALENDAR"} {
		if strings.Contains(private.String(), leak) {
			t.Errorf("leaked %q:\n%s", leak, private.String())
		}
	}
	if !strings.Contains(private.String(), "SUMMARY:Busy") || !strings.Contains(private.String(), "DTSTART") {
		t.Fatalf("the busy time is gone:\n%s", private.String())
	}
	if !strings.Contains(open.String(), "Board review") {
		t.Fatalf("an open event was changed:\n%s", open.String())
	}
}

func TestRedactionChangesTheETag(t *testing.T) {
	o := sharedEventObject("secret-1", "Surgery consult", "CLASS:PRIVATE\r\n")
	share := calendarShare{Owner: sharedOwner, Level: accessView}
	got, err := davCalendarObject(sharedDAVCalendar(share), o)
	if err != nil {
		t.Fatal(err)
	}
	if got.ETag == davETag(o.Data) || got.ContentLength == int64(len(o.Data)) {
		t.Fatal("the ETag and length describe the private original")
	}
}

func TestCalDAVViewCantWrite(t *testing.T) {
	r := newSharedRig(t, accessView)
	r.put(t, sharedEventObject("open-1", "Board review", ""))
	cl := sharedDAV(t, r)
	if _, err := cl.PutCalendarObject(context.Background(), sharedDAVPath+"new.ics", davEvent("new@t", "Mine", time.Now().UTC())); err == nil {
		t.Error("put succeeded")
	}
	if err := cl.RemoveAll(context.Background(), sharedDAVPath+"open-1.ics"); err == nil {
		t.Error("delete succeeded")
	}
	if objs, _ := r.owner.Objects(context.Background(), CollCalendar); len(objs) != 1 {
		t.Fatalf("%d objects", len(objs))
	}
}

func TestCalDAVEditWritesButNotGuests(t *testing.T) {
	r := newSharedRig(t, accessEdit)
	r.put(t, sharedEventObject("meeting-1", "Standup", "ATTENDEE:mailto:guest@example.org\r\n"))
	cl := sharedDAV(t, r)
	ctx := context.Background()
	if _, err := cl.PutCalendarObject(ctx, sharedDAVPath+"plain.ics", davEvent("plain@t", "Plain", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	theirs, _ := r.owner.Objects(ctx, CollCalendar)
	mine, _ := r.h.store.Objects(ctx, CollCalendar)
	if len(theirs) != 2 || len(mine) != 0 {
		t.Fatalf("theirs %d mine %d", len(theirs), len(mine))
	}
	guests := davEvent("g@t", "With guest", time.Now().UTC())
	att := ical.NewProp(ical.PropAttendee)
	att.Value = "mailto:guest@example.org"
	guests.Children[0].Props.Add(att)
	if _, err := cl.PutCalendarObject(ctx, sharedDAVPath+"g.ics", guests); err == nil {
		t.Error("added a guest")
	}
	if err := cl.RemoveAll(ctx, sharedDAVPath+"meeting-1.ics"); err == nil {
		t.Error("deleted a meeting with guests")
	}
}

func TestCalDAVDelegateMayChangeMeetings(t *testing.T) {
	r := newSharedRig(t, accessDelegate)
	r.put(t, sharedEventObject("meeting-1", "Standup", "ATTENDEE:mailto:guest@example.org\r\n"))
	if err := sharedDAV(t, r).RemoveAll(context.Background(), sharedDAVPath+"meeting-1.ics"); err != nil {
		t.Fatal(err)
	}
}
