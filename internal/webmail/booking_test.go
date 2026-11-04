package webmail

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRoomReplyReachesTheOrganizersEvent(t *testing.T) {
	now := time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)
	invite := Event{UID: "a@t", Summary: "Planning", Start: now, End: now.Add(time.Hour), Busy: true, Reminder: -1,
		Organizer: &Attendee{Email: "dana@example.com"},
		Attendees: []Attendee{{Email: "room@example.com", Resource: true}}}
	data, err := encodeCalendar("REQUEST", now, invite.toComponent(now))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BookingReply("room@example.com", "Boardroom", data, "ACCEPTED", now)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parseMessage(raw)
	if err != nil || len(msg.Calendar) == 0 {
		t.Fatalf("%v", err)
	}
	cal, err := decodeCalendar(msg.Calendar, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if cal.Method != "REPLY" || len(cal.Events) != 1 {
		t.Fatalf("%+v", cal)
	}
	stored := invite
	if !applyReply(&stored, cal.Events[0], msg.From[0].Email) || stored.Attendees[0].Status != "ACCEPTED" {
		t.Fatalf("the organizer's event didn't record it: %+v", stored.Attendees)
	}
}

// A room is told apart from a person, in the invitation and the form.
func TestRoomIsOfferedAndMarked(t *testing.T) {
	r := newSharedRig(t, "")
	r.security.resources = []bookable{{Address: "room@example.com", Name: "Boardroom", Kind: "room", Location: "Floor 3", Capacity: 8}}
	_, page := r.h.get("/calendar/event?new=1")
	if !strings.Contains(page, "data-room-picker") || !strings.Contains(page, "Boardroom (8), Floor 3") {
		t.Fatal("the form doesn't offer the room")
	}
	form := url.Values{"attendees": {"room@example.com"}, "notify": {"1"}}
	if resp := r.save(form); resp.StatusCode != 303 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := sentCalendar(t, r)
	if len(got.Event.Attendees) != 1 || !got.Event.Attendees[0].Resource {
		t.Fatalf("attendees %+v", got.Event.Attendees)
	}
	if got.Event.Location != "Boardroom, Floor 3" {
		t.Fatalf("location %q", got.Event.Location)
	}
}

func TestDecideBookingAllDayBlocksTheDay(t *testing.T) {
	stored := []Object{{ID: "x", Data: []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTAMP:20261001T000000Z\r\n" +
		"DTSTART;VALUE=DATE:20261201\r\nDTEND;VALUE=DATE:20261202\r\nSUMMARY:Refit\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")}}
	request := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:y\r\nDTSTAMP:20261001T000000Z\r\n" +
		"DTSTART:20261201T090000Z\r\nDTEND:20261201T100000Z\r\nSUMMARY:Meeting\r\nORGANIZER:mailto:d@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	got, err := DecideBooking(request, stored)
	if err != nil || got != BookingDecline {
		t.Fatalf("%v %v", got, err)
	}
}
