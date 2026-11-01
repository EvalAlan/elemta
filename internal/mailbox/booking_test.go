package mailbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// bookingRig is a room, with a colleague's address to book it from.
type bookingRig struct {
	*sieveRig
	domain, organizer string
}

func newBookingRig(t *testing.T, booking string) *bookingRig {
	t.Helper()
	r := newSieveRig(t)
	domain := r.a.Address[strings.LastIndexByte(r.a.Address, '@')+1:]
	t.Cleanup(func() { _, _ = r.e.DB.Exec(`DELETE FROM mailbox_freebusy WHERE account=$1`, r.a.ID) })
	if _, err := r.e.PutResource(context.Background(), r.a, mailpolicy.Resource{Name: "Boardroom", Capacity: 8, Booking: booking}); err != nil {
		t.Fatal(err)
	}
	return &bookingRig{sieveRig: r, domain: domain, organizer: "dana@" + domain}
}

const bookingStart = "20261201T090000Z"

func invitation(method, uid, organizer, start, end, extra string) string {
	cal := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nMETHOD:" + method + "\r\nBEGIN:VEVENT\r\nUID:" + uid +
		"\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:" + start + "\r\nDTEND:" + end + "\r\nSUMMARY:Planning\r\nORGANIZER:mailto:" + organizer +
		"\r\nATTENDEE;CUTYPE=ROOM:mailto:room@example.com\r\n" + extra + "END:VEVENT\r\nEND:VCALENDAR\r\n"
	return "From: " + organizer + "\r\nSubject: Invitation\r\nMIME-Version: 1.0\r\nContent-Type: text/calendar; method=" + method + "; charset=utf-8\r\n\r\n" + cal
}

func (r *bookingRig) send(sender, raw string) {
	r.t.Helper()
	if err := r.deliver(sender, "", raw); err != nil {
		r.t.Fatal(err)
	}
}

func (r *bookingRig) booked() int {
	r.t.Helper()
	entries, err := r.e.bookings(context.Background(), r.a.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return len(entries)
}

// lastAnswer is the PARTSTAT of the last reply sent.
func (r *bookingRig) lastAnswer() string {
	r.t.Helper()
	sent := r.submit.messages()
	if len(sent) == 0 {
		return ""
	}
	return strings.ToUpper(string(sent[len(sent)-1].data))
}

func TestRoomBooksAndAnswers(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	if r.booked() != 1 {
		t.Fatalf("%d bookings", r.booked())
	}
	if n := r.count("INBOX"); n != 0 {
		t.Fatalf("the invitation also landed in the inbox: %d", n)
	}
	sent := r.submit.messages()
	if len(sent) != 1 || sent[0].to[0] != r.organizer || !strings.EqualFold(sent[0].from, r.a.Address) {
		t.Fatalf("sent %+v", sent)
	}
	if !strings.Contains(r.lastAnswer(), "ACCEPTED") || !strings.Contains(r.lastAnswer(), "METHOD=REPLY") {
		t.Fatalf("reply:\n%s", r.lastAnswer())
	}
	var published int
	if err := r.e.DB.QueryRow(`SELECT jsonb_array_length(busy) FROM mailbox_freebusy WHERE account=$1`, r.a.ID).Scan(&published); err != nil || published != 1 {
		t.Fatalf("free/busy: %d, %v", published, err)
	}
}

func TestRoomDeclinesWhenTaken(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	other := "lee@" + r.domain
	r.send(other, invitation("REQUEST", "b@t", other, "20261201T093000Z", "20261201T103000Z", ""))
	if r.booked() != 1 {
		t.Fatalf("%d bookings", r.booked())
	}
	if !strings.Contains(r.lastAnswer(), "DECLINED") {
		t.Fatalf("reply:\n%s", r.lastAnswer())
	}
	// Touching is not overlapping: back-to-back meetings are normal.
	r.send(other, invitation("REQUEST", "c@t", other, "20261201T100000Z", "20261201T110000Z", ""))
	if r.booked() != 2 {
		t.Fatalf("%d bookings", r.booked())
	}
}

func TestRoomDeclinesARecurringClash(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, invitation("REQUEST", "single@t", r.organizer, "20261215T090000Z", "20261215T100000Z", ""))
	other := "lee@" + r.domain
	r.send(other, invitation("REQUEST", "weekly@t", other, bookingStart, "20261201T100000Z", "RRULE:FREQ=WEEKLY;COUNT=5\r\n"))
	if r.booked() != 1 || !strings.Contains(r.lastAnswer(), "DECLINED") {
		t.Fatalf("%d bookings, reply:\n%s", r.booked(), r.lastAnswer())
	}
}

// Two invitations at once, on two connections: there is one room.
func TestRoomCantBeDoubleBooked(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.send(r.organizer, invitation("REQUEST", fmt.Sprintf("race-%d@t", i), r.organizer, bookingStart, "20261201T100000Z", ""))
		}()
	}
	wg.Wait()
	if r.booked() != 1 {
		t.Fatalf("%d bookings for one slot", r.booked())
	}
}

func TestOrganizerMovesTheirBooking(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, "20261201T093000Z", "20261201T103000Z", "SEQUENCE:1\r\n"))
	if r.booked() != 1 || !strings.Contains(r.lastAnswer(), "ACCEPTED") {
		t.Fatalf("%d bookings, reply:\n%s", r.booked(), r.lastAnswer())
	}
	entries, _ := r.e.bookings(context.Background(), r.a.ID)
	if !strings.Contains(string(entries[0].obj.Data), "093000Z") {
		t.Fatalf("not moved:\n%s", entries[0].obj.Data)
	}
	if strings.Contains(string(entries[0].obj.Data), "METHOD") {
		t.Fatalf("a stored object isn't an iTIP message:\n%s", entries[0].obj.Data)
	}
	before := len(r.submit.messages())
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, "20261201T140000Z", "20261201T150000Z", ""))
	entries, _ = r.e.bookings(context.Background(), r.a.ID)
	if strings.Contains(string(entries[0].obj.Data), "140000Z") || len(r.submit.messages()) != before {
		t.Fatal("an old copy of the invitation changed the booking")
	}
}

// A UID travels in every invitation, so knowing one proves nothing.
func TestOnlyTheOrganizerChangesABooking(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	other := "lee@" + r.domain
	r.send(other, invitation("REQUEST", "a@t", other, "20261202T090000Z", "20261202T100000Z", "SEQUENCE:5\r\n"))
	if !strings.Contains(r.lastAnswer(), "DECLINED") {
		t.Fatalf("reply:\n%s", r.lastAnswer())
	}
	r.send(other, invitation("CANCEL", "a@t", other, bookingStart, "20261201T100000Z", ""))
	if r.booked() != 1 {
		t.Fatal("someone else cancelled the booking")
	}
	r.send(r.organizer, invitation("CANCEL", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	if r.booked() != 0 {
		t.Fatal("the organizer couldn't cancel")
	}
	var published int
	if err := r.e.DB.QueryRow(`SELECT jsonb_array_length(busy) FROM mailbox_freebusy WHERE account=$1`, r.a.ID).Scan(&published); err != nil || published != 0 {
		t.Fatalf("free/busy after cancelling: %d, %v", published, err)
	}
}

// Outsiders can mail a room, but can't take its time or make it send mail.
func TestOutsidersCantBook(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	for _, tc := range [][2]string{
		{"mallory@evil.example", "mallory@evil.example"},
		{"mallory@evil.example", "dana@" + r.domain},
		{"dana@" + r.domain, "mallory@evil.example"},
		{"", "dana@" + r.domain},
	} {
		r.send(tc[0], invitation("REQUEST", "x@t", tc[1], bookingStart, "20261201T100000Z", ""))
	}
	if r.booked() != 0 || len(r.submit.messages()) != 0 {
		t.Fatalf("%d bookings, %d replies", r.booked(), len(r.submit.messages()))
	}
	if n := r.count("INBOX"); n != 4 {
		t.Fatalf("mail to a room must not vanish: %d in the inbox", n)
	}
}

func TestManualRoomWaitsForItsDelegate(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingManual)
	r.send(r.organizer, invitation("REQUEST", "a@t", r.organizer, bookingStart, "20261201T100000Z", ""))
	if r.booked() != 0 || r.count("INBOX") != 1 || len(r.submit.messages()) != 0 {
		t.Fatalf("%d bookings, %d in the inbox, %d replies", r.booked(), r.count("INBOX"), len(r.submit.messages()))
	}
}

func TestAPersonIsntBooked(t *testing.T) {
	r := newSieveRig(t)
	organizer := "dana@" + r.a.Address[strings.LastIndexByte(r.a.Address, '@')+1:]
	if err := r.deliver(organizer, "", invitation("REQUEST", "a@t", organizer, bookingStart, "20261201T100000Z", "")); err != nil {
		t.Fatal(err)
	}
	if n := r.count("INBOX"); n != 1 || len(r.submit.messages()) != 0 {
		t.Fatalf("%d in the inbox, %d replies", n, len(r.submit.messages()))
	}
}

func TestMailToARoomStaysMail(t *testing.T) {
	r := newBookingRig(t, mailpolicy.BookingAuto)
	r.send(r.organizer, "From: "+r.organizer+"\r\nSubject: The projector\r\n\r\nIs broken.\r\n")
	if n := r.count("INBOX"); n != 1 {
		t.Fatalf("%d in the inbox", n)
	}
}

func TestPutResourceRules(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	for _, bad := range []mailpolicy.Resource{{}, {Name: "x", Kind: "boat"}, {Name: "x", Booking: "maybe"}, {Name: "x", Capacity: -1}} {
		if _, err := e.PutResource(ctx, a, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	saved, err := e.PutResource(ctx, a, mailpolicy.Resource{Name: " Lab ", Kind: mailpolicy.ResourceEquipment})
	if err != nil || saved.Name != "Lab" || saved.Booking != mailpolicy.BookingAuto {
		t.Fatalf("%+v %v", saved, err)
	}
	domain := a.Address[strings.LastIndexByte(a.Address, '@')+1:]
	if list, err := e.Resources(ctx, domain); err != nil || len(list) == 0 {
		t.Fatalf("listed %v, %v", list, err)
	}
	if err := e.DeleteResource(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := e.Resource(ctx, a.ID); err != nil || got != nil {
		t.Fatalf("%+v %v", got, err)
	}
}
