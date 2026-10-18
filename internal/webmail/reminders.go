package webmail

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Reminders are delivered by the open webmail page: it asks for the
// reminders due in the next while, and shows each one (in the page, and as
// a desktop notification if the user allowed them) when its time comes.
// A reminder for a closed browser is not delivered; the calendar invitation
// emails cover meetings for people who aren't looking.

// reminderWindow is how far ahead the page is told about reminders. It
// polls more often than this, so a newly added event is picked up.
const reminderWindow = 2 * time.Hour

type reminderJSON struct {
	Key     string `json:"key"`   // stable per occurrence, so the page shows each once
	FireAt  int64  `json:"at"`    // Unix seconds
	StartAt int64  `json:"start"` // Unix seconds
	Title   string `json:"title"`
	When    string `json:"when"`
	Where   string `json:"where,omitempty"`
	URL     string `json:"url"`
}

func (s *Server) remindersAPI(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	h24 := s.prefsCached(sess).Uses24h()
	events, err := s.events(r.Context(), sess, loc)
	if err != nil {
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	now := s.now()
	out := []reminderJSON{}
	// Look back a little so a reminder due while the page was loading
	// isn't missed, and far enough ahead for week-long reminders.
	horizon := now.Add(reminderWindow + 7*24*time.Hour)
	for _, o := range expand(events, now.Add(-10*time.Minute), horizon) {
		e := o.Event
		if e.Reminder < 0 {
			continue
		}
		fire := o.Start.Add(-time.Duration(e.Reminder) * time.Minute)
		if fire.Before(now.Add(-10*time.Minute)) || fire.After(now.Add(reminderWindow)) {
			continue
		}
		when := clock(h24, o.Start.In(loc))
		if e.AllDay {
			when = "All day " + o.Start.Format("Mon Jan 2")
		} else if !sameDay(o.Start.In(loc), now.In(loc)) {
			when = o.Start.In(loc).Format("Mon Jan 2") + " " + when
		}
		out = append(out, reminderJSON{
			Key: e.UID + "@" + strconv.FormatInt(o.Start.Unix(), 10), FireAt: fire.Unix(), StartAt: o.Start.Unix(),
			Title: e.Summary, When: when, Where: e.Location, URL: eventURL(e.UID, o.Start),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// birthdayCalendar holds the read-only events made from contacts' birthdays.
const birthdayCalendar = "Birthdays"

// calendarEvents is what the calendar shows: the stored events plus a
// yearly all-day event for each contact with a birthday.
func (s *Server) calendarEvents(ctx context.Context, sess *Session, loc *time.Location) ([]Event, error) {
	events, err := s.events(ctx, sess, loc)
	if err != nil {
		return nil, err
	}
	contacts, err := s.contacts(ctx, sess)
	if err != nil {
		return events, nil // birthdays are a nicety; the calendar still works
	}
	for _, c := range contacts {
		start, ok := birthdayDate(c.Birthday, loc)
		if !ok {
			continue
		}
		events = append(events, Event{
			UID: "birthday-" + c.ID, Summary: c.Display() + "'s birthday", Calendar: birthdayCalendar,
			Start: start, End: start.AddDate(0, 0, 1), AllDay: true, RRule: "FREQ=YEARLY", Reminder: -1,
			ReadOnly: true, Description: "From your contacts.",
		})
	}
	return events, nil
}

// birthdayDate reads YYYY-MM-DD or --MM-DD. A birthday without a year is
// anchored in a leap year, so 29 February still recurs.
func birthdayDate(b string, loc *time.Location) (time.Time, bool) {
	b = strings.TrimSpace(b)
	if strings.HasPrefix(b, "--") {
		b = "2000" + b[1:]
	}
	t, err := time.ParseInLocation("2006-01-02", b, loc)
	return t, err == nil
}
