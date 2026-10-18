package webmail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

// Invitations travel as email with an iCalendar part (iMIP, RFC 6047): the
// organizer sends a REQUEST, each guest answers with a REPLY carrying their
// participation status, and a CANCEL withdraws the event. Every calendar
// client speaks this, so meetings work with people on any mail system.

// inviteView is an invitation, reply or cancellation found in a message,
// as the reading pane shows it.
type inviteView struct {
	Method     string // REQUEST, REPLY, CANCEL (or PUBLISH)
	Event      Event
	When       string
	Repeat     string
	MyStatus   string // this user's answer as stored in their calendar
	InCalendar bool
	Outdated   bool // the calendar already has a newer version
	Reply      *Attendee
	Conflicts  []Occurrence
	Folder     string
	UID        uint32
	Back       string
	CSRF       string
}

// Self reports whether the invitation came from this user.
func (iv *inviteView) Self(addr string) bool { return iv.Event.IsOrganizer(addr) }

func init() {
	messageDecorators = append(messageDecorators, decorateInvite)
}

// decorateInvite parses the calendar part of an open message and works out
// where it stands against the user's calendar.
func decorateInvite(s *Server, ctx context.Context, sess *Session, v *view) {
	m := v.Message
	if m == nil || len(m.Calendar) == 0 {
		return
	}
	loc := s.loc(sess)
	cal, err := decodeCalendar(m.Calendar, loc)
	if err != nil || len(cal.Events) == 0 {
		return
	}
	method := cal.Method
	if method == "" {
		method = "PUBLISH"
	}
	e := cal.Events[0]
	iv := &inviteView{Method: method, Event: e, Folder: m.Folder, UID: m.UID, Repeat: ruleSummary(e.RRule, e.Start), CSRF: sess.CSRF}
	if v.List != nil {
		iv.Back = v.List.MessageURL(m.UID)
	}
	iv.When = describeWhen(e, loc, s.prefsCached(sess).Uses24h())
	if method == "REPLY" {
		for i := range e.Attendees {
			iv.Reply = &e.Attendees[i]
			break
		}
	}
	events, err := s.events(ctx, sess, loc)
	if err == nil {
		if stored := findEvent(events, e.UID); stored != nil {
			iv.InCalendar = true
			iv.Outdated = stored.Sequence > e.Sequence
			for _, a := range stored.Attendees {
				if strings.EqualFold(a.Email, sess.Address) {
					iv.MyStatus = a.Status
				}
			}
		}
		if method == "REQUEST" && e.Busy && !e.AllDay {
			for _, o := range expand(events, e.Start, e.End) {
				if o.Event.UID != e.UID && o.Event.Busy && !o.Event.AllDay {
					iv.Conflicts = append(iv.Conflicts, o)
				}
			}
		}
	}
	m.Invite = iv
}

// describeWhen is an event's time in words, in the user's zone.
func describeWhen(e Event, loc *time.Location, h24 bool) string {
	if e.AllDay {
		last := e.End.AddDate(0, 0, -1)
		if sameDay(e.Start, last) || !last.After(e.Start) {
			return e.Start.Format("Monday, January 2, 2006") + " (all day)"
		}
		return e.Start.Format("Mon, Jan 2") + " – " + last.Format("Mon, Jan 2, 2006") + " (all day)"
	}
	s, end := e.Start.In(loc), e.End.In(loc)
	if sameDay(s, end) || end.Equal(s) {
		return s.Format("Monday, January 2, 2006") + ", " + clock(h24, s) + " – " + clock(h24, end) + " " + zoneLabel(s)
	}
	return s.Format("Mon, Jan 2") + " " + clock(h24, s) + " – " + end.Format("Mon, Jan 2, 2006") + " " + clock(h24, end) + " " + zoneLabel(s)
}

func zoneLabel(t time.Time) string {
	name, _ := t.Zone()
	return "(" + name + ")"
}

// forWire returns the event as sent to other people: a single event in
// UTC, which every client reads the same way. A recurring one keeps its
// zone, since the rule only expands correctly across daylight saving in it.
func forWire(e Event) Event {
	if !e.AllDay && e.RRule == "" {
		e.Start, e.End = e.Start.UTC(), e.End.UTC()
	}
	e.Calendar = ""
	e.Reminder = -1
	return e
}

// sendInvites mails an iTIP message about e to the given attendees.
func (s *Server) sendInvites(ctx context.Context, sess *Session, e Event, method string, to []Attendee) error {
	if len(to) == 0 {
		return nil
	}
	prefs := s.prefsCached(sess)
	wire := forWire(e)
	if method == "CANCEL" {
		wire.Status = "CANCELLED"
	}
	data, err := encodeCalendar(method, s.now(), wire.toComponent(s.now()))
	if err != nil {
		return err
	}
	d := &Draft{From: prefs.fromAddress(sess.Address), Calendar: &CalendarPart{Method: method, Data: data}}
	for _, a := range to {
		if !strings.EqualFold(a.Email, sess.Address) {
			d.To = append(d.To, Address{Name: a.Name, Email: a.Email})
		}
	}
	if len(d.To) == 0 {
		return nil
	}
	when := describeWhen(e, s.loc(sess), prefs.Uses24h())
	switch {
	case method == "CANCEL":
		d.Subject = "Cancelled: " + e.Summary
		d.Text = "This event has been cancelled.\n\n" + e.Summary + "\n" + when + "\n"
	case e.Sequence > 0:
		d.Subject = "Updated invitation: " + e.Summary
		d.Text = "This event has changed.\n\n" + inviteText(e, when)
	default:
		d.Subject = "Invitation: " + e.Summary
		d.Text = inviteText(e, when)
	}
	return s.submitDraft(ctx, sess, d)
}

func inviteText(e Event, when string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nWhen: %s\n", e.Summary, when)
	if r := ruleSummary(e.RRule, e.Start); r != "" {
		fmt.Fprintf(&b, "Repeats: %s\n", r)
	}
	if e.Location != "" {
		fmt.Fprintf(&b, "Where: %s\n", e.Location)
	}
	if e.URL != "" {
		fmt.Fprintf(&b, "Link: %s\n", e.URL)
	}
	if e.Organizer != nil {
		fmt.Fprintf(&b, "Organizer: %s\n", formatAddress(Address{Name: e.Organizer.Name, Email: e.Organizer.Email}))
	}
	if len(e.Attendees) > 0 {
		var names []string
		for _, a := range e.Attendees {
			names = append(names, a.Label())
		}
		fmt.Fprintf(&b, "Guests: %s\n", strings.Join(names, ", "))
	}
	if e.Description != "" {
		fmt.Fprintf(&b, "\n%s\n", e.Description)
	}
	b.WriteString("\nYour calendar program can add this event from the attached invitation.\n")
	return b.String()
}

// submitDraft builds and sends a message as the session's user.
func (s *Server) submitDraft(ctx context.Context, sess *Session, d *Draft) error {
	raw, err := d.Build(s.now())
	if err != nil {
		return err
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return s.submit.Submit(ctx, sess.User, pw, sess.Address, d.Recipients(), raw)
}

// rsvpSubmit acts on the invitation card in the reading pane: answering an
// invitation, recording a guest's reply, or removing a cancelled event.
func (s *Server) rsvpSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx := r.Context()
	loc := s.loc(sess)
	folder := r.PostFormValue("f")
	uid, ok := parseUID(r.PostFormValue("uid"))
	back := localBack(r.PostFormValue("back"), folderURL(folder, 1, ""))
	if folder == "" || !ok {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	var raw []byte
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		var err error
		raw, err = st.Raw(ctx, folder, uid, s.maxMessage())
		return err
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil || len(msg.Calendar) == 0 {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	cal, err := decodeCalendar(msg.Calendar, loc)
	if err != nil {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "The invitation in this message couldn't be read.")
		return
	}
	incoming := cal.Events[0]
	events, err := s.events(ctx, sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	stored := findEvent(events, incoming.UID)

	notice := ""
	switch op := r.PostFormValue("op"); op {
	case "ACCEPTED", "TENTATIVE", "DECLINED":
		notice, err = s.answerInvite(ctx, sess, incoming, stored, op)
	case "apply-reply":
		if stored == nil {
			err = ErrNotFound
			break
		}
		for _, a := range incoming.Attendees {
			for i := range stored.Attendees {
				if strings.EqualFold(stored.Attendees[i].Email, a.Email) {
					stored.Attendees[i].Status = a.Status
				}
			}
		}
		notice = "rsvp-updated"
		err = s.putEvent(ctx, sess, *stored)
	case "apply-cancel", "remove":
		if stored != nil {
			err = s.deleteEvent(ctx, sess, stored.UID)
		}
		notice = "event-deleted"
	case "add":
		// A PUBLISH (an event someone shared, not a meeting) goes straight
		// into the calendar.
		notice = "event-saved"
		err = s.putEvent(ctx, sess, incoming)
	default:
		err = errors.New("webmail: unknown invitation action")
	}
	if err != nil && notice != "rsvp-saved" {
		s.fail(w, r, sess, err)
		return
	}
	redirectLocal(w, r, setParam(back, "n", notice))
}

// answerInvite records the user's answer in their calendar and tells the
// organizer. A declined invitation is removed from the calendar.
func (s *Server) answerInvite(ctx context.Context, sess *Session, incoming Event, stored *Event, status string) (string, error) {
	e := incoming
	if stored != nil && stored.Sequence > incoming.Sequence {
		e = *stored // answering an old copy of the invitation
	}
	found := false
	for i := range e.Attendees {
		if strings.EqualFold(e.Attendees[i].Email, sess.Address) {
			e.Attendees[i].Status = status
			found = true
		}
	}
	if !found {
		// Invited through a list or an alias: answer as ourselves.
		e.Attendees = append(e.Attendees, Attendee{Email: sess.Address, Name: s.prefsCached(sess).DisplayName, Status: status})
	}
	if stored != nil && stored.Calendar != "" {
		e.Calendar = stored.Calendar
	}
	if status == "DECLINED" {
		if stored != nil {
			if err := s.deleteEvent(ctx, sess, e.UID); err != nil {
				return "", err
			}
		}
	} else if err := s.putEvent(ctx, sess, e); err != nil {
		return "", err
	}
	if e.Organizer == nil || e.IsOrganizer(sess.Address) {
		return "event-saved", nil
	}
	if err := s.sendReply(ctx, sess, e, status); err != nil {
		s.log.Warn("webmail: send invitation reply", "user", sess.User, "error", err)
		return "rsvp-saved", err
	}
	return "rsvp-sent", nil
}

// sendReply tells the organizer the user's answer. The REPLY carries only
// the user's own ATTENDEE line, as iTIP requires.
func (s *Server) sendReply(ctx context.Context, sess *Session, e Event, status string) error {
	prefs := s.prefsCached(sess)
	wire := forWire(e)
	wire.Attendees = []Attendee{{Email: sess.Address, Name: prefs.DisplayName, Status: status}}
	wire.Description, wire.Location = "", e.Location
	comp := wire.toComponent(s.now())
	comp.Props.Del(ical.PropRecurrenceRule)
	comp.Props.Del(ical.PropExceptionDates)
	if e.RRule != "" {
		// The reply covers the whole series; the rule itself isn't repeated.
		rp := ical.NewProp(ical.PropRecurrenceRule)
		rp.SetValueType(ical.ValueRecurrence)
		rp.Value = e.RRule
		comp.Props.Set(rp)
	}
	data, err := encodeCalendar("REPLY", s.now(), comp)
	if err != nil {
		return err
	}
	verb := map[string]string{"ACCEPTED": "Accepted", "TENTATIVE": "Tentative", "DECLINED": "Declined"}[status]
	who := prefs.DisplayName
	if who == "" {
		who = sess.Address
	}
	d := &Draft{
		From:     prefs.fromAddress(sess.Address),
		To:       []Address{{Name: e.Organizer.Name, Email: e.Organizer.Email}},
		Subject:  verb + ": " + e.Summary,
		Text:     fmt.Sprintf("%s has %s the invitation to %s.\n", who, strings.ToLower(map[string]string{"ACCEPTED": "accepted", "TENTATIVE": "tentatively accepted", "DECLINED": "declined"}[status]), e.Summary),
		Calendar: &CalendarPart{Method: "REPLY", Data: data},
	}
	return s.submitDraft(ctx, sess, d)
}
