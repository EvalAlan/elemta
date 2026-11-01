package webmail

// The calendar work behind rooms and other resources. A resource has nobody
// signed in to answer its invitations, so the mailbox service does it as they
// are delivered (internal/mailbox/booking.go). Everything that needs to read
// iCalendar stays here, with the parser that already knows time zones,
// recurrences and what other calendar software sends.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

// BookingRequest is an invitation addressed to a resource.
type BookingRequest struct {
	UID, Summary, Organizer string
	Sequence                int
	// Occurrence is set when the message is about one occurrence of a
	// series, which has no object of its own to book.
	Occurrence bool
}

// BookingDecision is what a resource does with an invitation.
type BookingDecision int

const (
	// BookingAccept books it.
	BookingAccept BookingDecision = iota
	// BookingDecline turns it down: the time is taken, or the booking
	// belongs to someone else.
	BookingDecline
	// BookingStale ignores it: the stored booking is newer.
	BookingStale
)

// bookingWindow is how far ahead a recurring booking is checked for conflicts.
const bookingWindow = 366 * 24 * time.Hour

// ParseBooking reads the first event of an invitation.
func ParseBooking(data []byte) (BookingRequest, error) {
	cal, err := decodeCalendar(data, time.UTC)
	if err != nil {
		return BookingRequest{}, err
	}
	if len(cal.Events) == 0 {
		return BookingRequest{}, errors.New("webmail: no event in the invitation")
	}
	e := cal.Events[0]
	r := BookingRequest{UID: e.UID, Summary: e.Summary, Sequence: e.Sequence}
	if e.Organizer != nil {
		r.Organizer = e.Organizer.Email
	}
	raw, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return BookingRequest{}, err
	}
	for _, comp := range raw.Children {
		if comp.Name == ical.CompEvent && comp.Props.Get(ical.PropRecurrenceID) != nil {
			r.Occurrence = true
		}
	}
	return r, nil
}

// DecideBooking checks an invitation against the resource's stored bookings.
func DecideBooking(data []byte, stored []Object) (BookingDecision, error) {
	cal, err := decodeCalendar(data, time.UTC)
	if err != nil {
		return BookingDecline, err
	}
	if len(cal.Events) == 0 {
		return BookingDecline, errors.New("webmail: no event in the invitation")
	}
	request := cal.Events[0]
	existing := eventsFrom(stored, time.UTC)
	others := make([]Event, 0, len(existing))
	for _, e := range existing {
		if e.UID != request.UID {
			others = append(others, e)
			continue
		}
		if e.Sequence > request.Sequence {
			return BookingStale, nil
		}
		// Only the person who booked it can move it: UIDs are in every
		// invitation, so anyone who saw one could otherwise take the slot.
		if e.Organizer == nil || request.Organizer == nil || !strings.EqualFold(e.Organizer.Email, request.Organizer.Email) {
			return BookingDecline, nil
		}
	}
	from := request.Start.Add(-24 * time.Hour)
	to := from.Add(bookingWindow)
	busy := expand(others, from, to)
	for _, wanted := range expand([]Event{request}, from, to) {
		for _, taken := range busy {
			if strings.EqualFold(taken.Event.Status, "CANCELLED") {
				continue
			}
			if wanted.Start.Before(taken.End) && taken.Start.Before(wanted.End) {
				return BookingDecline, nil
			}
		}
	}
	return BookingAccept, nil
}

// BookingOwnedBy reports whether stored holds uid booked by organizer, so that
// a cancellation is only taken from the person who booked.
func BookingOwnedBy(stored []Object, uid, organizer string) bool {
	for _, e := range eventsFrom(stored, time.UTC) {
		if e.UID == uid {
			return e.Organizer != nil && strings.EqualFold(e.Organizer.Email, organizer)
		}
	}
	return false
}

// BookingObject turns an invitation into the object a calendar stores, and
// returns its message form and object ID.
func BookingObject(data []byte, now time.Time) ([]byte, string, error) {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return nil, "", err
	}
	cal.Props.Del(ical.PropMethod) // a stored object is not an iTIP message
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, "", err
	}
	r, err := ParseBooking(data)
	if err != nil {
		return nil, "", err
	}
	id := objectID(r.UID)
	raw, err := encodeObject(Object{ID: id, Title: r.Summary, ContentType: "text/calendar", Data: buf.Bytes()}, now)
	return raw, id, err
}

// BookingObjectID is the object ID an event's UID is stored under.
func BookingObjectID(uid string) string { return objectID(uid) }

// DecodeBookingObject reads a stored object.
func DecodeBookingObject(raw []byte) (Object, error) { return decodeObject(raw) }

// BookingReply builds the iTIP REPLY a resource sends its organizer.
func BookingReply(address, name string, data []byte, status string, now time.Time) ([]byte, error) {
	cal, err := decodeCalendar(data, time.UTC)
	if err != nil {
		return nil, err
	}
	if len(cal.Events) == 0 || cal.Events[0].Organizer == nil {
		return nil, errors.New("webmail: the invitation has no organizer")
	}
	e := cal.Events[0]
	wire := forWire(e)
	wire.Attendees = []Attendee{{Email: address, Name: name, Status: status, Resource: true}}
	wire.Description = ""
	comp := wire.toComponent(now)
	body, err := encodeCalendar("REPLY", now, comp)
	if err != nil {
		return nil, err
	}
	verb := "Accepted"
	text := fmt.Sprintf("%s is booked for %s.\n", name, e.Summary)
	if status != "ACCEPTED" {
		verb = "Declined"
		text = fmt.Sprintf("%s is already booked at that time, so it can't take %s.\n", name, e.Summary)
	}
	d := &Draft{
		From:     Address{Name: name, Email: address},
		To:       []Address{{Name: e.Organizer.Name, Email: e.Organizer.Email}},
		Subject:  verb + ": " + e.Summary,
		Text:     text,
		Calendar: &CalendarPart{Method: "REPLY", Data: body},
	}
	return d.Build(now)
}

// BookingBusy is the busy time a resource publishes.
func BookingBusy(stored []Object, address string, now time.Time) (from, to time.Time, busy []BookingBlock) {
	from, to = now.Add(-freeBusyBack), now.Add(freeBusyAhead)
	for _, b := range busyFrom(eventsFrom(stored, time.UTC), address, from, to) {
		busy = append(busy, BookingBlock{Start: b.Start, End: b.End})
	}
	return from, to, busy
}

// BookingBlock is a time a resource is booked.
type BookingBlock struct{ Start, End time.Time }
