package webmail

// Free/busy. The webmail is the only part of the system that can read and
// expand a calendar (recurrences, exceptions, all-day dates in the user's
// zone), so it publishes each user's busy times to the mailbox service
// whenever their calendar changes: from the calendar pages, invitations,
// imports and CalDAV, and at sign-in to catch anything else. Colleagues
// scheduling a meeting read them back (/api/freebusy), and see only when
// someone is busy, never what they are doing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// busyBlock is one busy interval, in UTC on the wire.
type busyBlock struct {
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Tentative bool      `json:"tentative,omitempty"`
}

// The published window: a day back, so a meeting today is covered, and half
// a year ahead, which is as far as anyone schedules.
const (
	freeBusyBack  = 24 * time.Hour
	freeBusyAhead = 183 * 24 * time.Hour
	// freeBusyDelay gathers a burst of changes (a CalDAV client syncing
	// many events) into one publication.
	freeBusyDelay = 2 * time.Second
)

// busyFrom returns the times events make self busy between from and to,
// with overlapping times of the same kind merged. Events shown as free,
// cancelled, declined, holidays and contact birthdays don't count.
func busyFrom(events []Event, self string, from, to time.Time) []busyBlock {
	var out []busyBlock
	for _, o := range expand(events, from, to) {
		e := o.Event
		if !e.Busy || e.ReadOnly || e.HolidayKey != "" || strings.EqualFold(e.Status, "CANCELLED") {
			continue
		}
		tentative := strings.EqualFold(e.Status, "TENTATIVE")
		if !e.IsOrganizer(self) {
			// An invitation counts by the user's own answer: declined is
			// free, not yet answered or maybe is tentative.
			switch strings.ToUpper(selfStatus(e, self)) {
			case "DECLINED":
				continue
			case "TENTATIVE", "NEEDS-ACTION":
				tentative = true
			}
		}
		out = append(out, busyBlock{Start: o.Start.UTC(), End: o.End.UTC(), Tentative: tentative})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	merged := out[:0]
	for _, b := range out {
		if n := len(merged); n > 0 && merged[n-1].Tentative == b.Tentative && !b.Start.After(merged[n-1].End) {
			if b.End.After(merged[n-1].End) {
				merged[n-1].End = b.End
			}
			continue
		}
		merged = append(merged, b)
	}
	return merged
}

// selfStatus is self's reply to an invitation, "" when not listed.
func selfStatus(e *Event, self string) string {
	for _, a := range e.Attendees {
		if strings.EqualFold(a.Email, self) {
			if a.Status == "" {
				return "NEEDS-ACTION"
			}
			return a.Status
		}
	}
	return "ACCEPTED" // on the calendar but not listed: treat as attending
}

// freeBusyPublisher coalesces publications per user.
type freeBusyPublisher struct {
	mu      sync.Mutex
	pending map[string]*time.Timer
	// atSignIn is when each user's busy times were last published because
	// they signed in (signInRepublish).
	atSignIn map[string]time.Time
}

// signInRepublish is how often signing in republishes a user's busy times.
// Changes made in the webmail or over CalDAV publish at once; signing in
// only catches changes made another way (a mail app writing the Calendar
// folder over IMAP), and doing it on every sign-in cost a second IMAP
// login, a calendar read and an API call each time, which the load suite
// showed in the webmail's sign-in latency.
const signInRepublish = time.Hour

// publishFreeBusyAtSignIn publishes at sign-in unless this replica did so
// for the user within signInRepublish.
func (s *Server) publishFreeBusyAtSignIn(user, password, self string) {
	key := strings.ToLower(user)
	now := s.now()
	s.freeBusy.mu.Lock()
	if s.freeBusy.atSignIn == nil {
		s.freeBusy.atSignIn = map[string]time.Time{}
	}
	if last, ok := s.freeBusy.atSignIn[key]; ok && now.Sub(last) < signInRepublish {
		s.freeBusy.mu.Unlock()
		return
	}
	s.freeBusy.atSignIn[key] = now
	if len(s.freeBusy.atSignIn) > 100000 {
		// Bounded: forgetting everyone only means one extra publication each.
		s.freeBusy.atSignIn = map[string]time.Time{key: now}
	}
	s.freeBusy.mu.Unlock()
	s.publishFreeBusy(user, password, self)
}

// publishFreeBusy publishes a user's busy times shortly, in the background.
// The credentials are the user's own; they are held only until then, as the
// session holds them anyway.
func (s *Server) publishFreeBusy(user, password, self string) {
	if s.security == nil || password == "" {
		return
	}
	key := strings.ToLower(user)
	s.freeBusy.mu.Lock()
	defer s.freeBusy.mu.Unlock()
	if s.freeBusy.pending == nil {
		s.freeBusy.pending = map[string]*time.Timer{}
	}
	if t, ok := s.freeBusy.pending[key]; ok {
		t.Stop()
	}
	s.freeBusy.pending[key] = time.AfterFunc(freeBusyDelay, func() {
		s.freeBusy.mu.Lock()
		delete(s.freeBusy.pending, key)
		s.freeBusy.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := s.publishFreeBusyNow(ctx, user, password, self); err != nil {
			s.log.Warn("webmail: free/busy not published", "user", user, "error", err)
		}
	})
}

func (s *Server) publishFreeBusyNow(ctx context.Context, user, password, self string) error {
	st, err := s.dial(ctx, user, password)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	loc := s.defaultLoc
	if objs, err := st.Objects(ctx, CollSettings); err == nil {
		for _, o := range objs {
			var p Settings
			if o.ID == settingsID && json.Unmarshal(o.Data, &p) == nil && p.Timezone != "" {
				if l, err := time.LoadLocation(p.Timezone); err == nil {
					loc = l
				}
			}
		}
	}
	objs, err := st.Objects(ctx, CollCalendar)
	if err != nil {
		return err
	}
	now := s.now()
	from, to := now.Add(-freeBusyBack), now.Add(freeBusyAhead)
	body := map[string]any{"from": from.UTC(), "to": to.UTC(), "busy": busyFrom(eventsFrom(objs, loc), self, from, to)}
	return s.security.call(ctx, http.MethodPut, "/v1/freebusy", user, password, body, nil)
}

// calendarChanged republishes a signed-in user's busy times.
func (s *Server) calendarChanged(sess *Session) {
	if s.security == nil {
		return
	}
	if password, err := s.sessions.password(sess); err == nil {
		s.publishFreeBusy(sess.User, password, sess.Address)
	}
}

// freeBusyPerson is one row of the availability shown on the event form:
// busy times on the chosen day, in minutes from its midnight in the
// viewer's zone.
type freeBusyPerson struct {
	Address string        `json:"address"`
	Known   bool          `json:"known"`
	Busy    []freeBusyMin `json:"busy"`
}

type freeBusyMin struct {
	From      int  `json:"from"`
	To        int  `json:"to"`
	Tentative bool `json:"tentative,omitempty"`
}

// freeBusyAPI answers the event form: ?date=2026-10-20&attendees=a,b.
func (s *Server) freeBusyAPI(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.security == nil {
		http.Error(w, "free/busy is not available", http.StatusNotFound)
		return
	}
	loc := s.loc(sess)
	day, err := time.ParseInLocation("2006-01-02", r.URL.Query().Get("date"), loc)
	if err != nil {
		http.Error(w, "date must be YYYY-MM-DD", http.StatusBadRequest)
		return
	}
	people, _ := parseList(r.URL.Query().Get("attendees"))
	addresses := []string{strings.ToLower(sess.Address)}
	seen := map[string]bool{addresses[0]: true}
	for _, p := range people {
		a := strings.ToLower(p.Email)
		if !seen[a] && len(addresses) < 50 {
			seen[a] = true
			addresses = append(addresses, a)
		}
	}
	password, err := s.sessions.password(sess)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	end := day.AddDate(0, 0, 1)
	q := url.Values{"address": addresses, "from": {day.UTC().Format(time.RFC3339)}, "to": {end.UTC().Format(time.RFC3339)}}
	var found []struct {
		Address string      `json:"address"`
		Known   bool        `json:"known"`
		Busy    []busyBlock `json:"busy"`
	}
	if err := s.security.call(r.Context(), http.MethodGet, "/v1/freebusy?"+q.Encode(), sess.User, password, nil, &found); err != nil {
		s.log.Warn("webmail: free/busy lookup failed", "error", err)
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	minutes := func(t time.Time) int {
		m := int(t.Sub(day).Minutes())
		return max(0, min(m, int(end.Sub(day).Minutes())))
	}
	out := make([]freeBusyPerson, 0, len(found))
	for _, f := range found {
		p := freeBusyPerson{Address: f.Address, Known: f.Known, Busy: []freeBusyMin{}}
		for _, b := range f.Busy {
			p.Busy = append(p.Busy, freeBusyMin{From: minutes(b.Start), To: minutes(b.End), Tentative: b.Tentative})
		}
		out = append(out, p)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"date": day.Format("2006-01-02"), "minutes": int(end.Sub(day).Minutes()), "people": out})
}
