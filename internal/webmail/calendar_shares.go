package webmail

// Other people's calendars. The mailbox service keeps who may see what and
// enforces it on the connection (internal/mailbox/calendar_sharing.go): a
// calendar login opens that one folder, read-only for view access. The checks
// here decide what to show and offer, and hide private events from view access,
// which only this code can do because it's what reads the events.
//
// An editor's connection writes as the owner, so nothing here may send mail.
// Invitations come from the organizer, and telling guests about a change needs
// delegate access, so guests can't be added to or changed on someone else's
// events from here.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	accessView     = "view"
	accessEdit     = "edit"
	accessDelegate = "delegate"

	calendarLoginSuffix = "|calendar"
)

type calendarShare struct {
	Owner   string `json:"owner"`
	OwnerID string `json:"owner_id"`
	Member  string `json:"member"`
	Level   string `json:"level"`
}

// CanEdit reports whether the member may change the owner's events.
func (c calendarShare) CanEdit() bool {
	return c.Level == accessEdit || c.Level == accessDelegate
}

type calendarShares struct {
	Granted  []calendarShare `json:"granted"`
	Received []calendarShare `json:"received"`
}

func calendarLogin(user, owner string) string { return user + "|" + owner + calendarLoginSuffix }

// isCalendarLogin reports a store opened for someone else's calendar.
func isCalendarLogin(user string) bool { return strings.HasSuffix(user, calendarLoginSuffix) }

// calendarOwnerID finds the account a calendar login opens. Writers lock by
// account, so an editor has to take the lock the owner takes, or their writes
// would race.
func calendarOwnerID(ctx context.Context, security *securityClient, user, password string) (string, error) {
	member, rest, ok := strings.Cut(strings.TrimSuffix(user, calendarLoginSuffix), "|")
	if !ok || security == nil {
		return "", errors.New("webmail: not a calendar login")
	}
	var shares calendarShares
	if err := security.call(ctx, http.MethodGet, "/v1/calendar-shares", member, password, nil, &shares); err != nil {
		return "", err
	}
	for _, c := range shares.Received {
		if strings.EqualFold(c.Owner, rest) && c.OwnerID != "" {
			return c.OwnerID, nil
		}
	}
	return "", errors.New("webmail: no such calendar share")
}

// calendarShareList is read fresh, unlike the shared mailbox list. The mailbox
// enforces most of a share itself, but what view access hides is decided here,
// so someone cut back to view must not keep seeing private events from a cache.
func (s *Server) calendarShareList(ctx context.Context, sess *Session) (calendarShares, error) {
	var out calendarShares
	// An administrator's access token opens one mailbox and nothing beyond it.
	if s.security == nil || sess.AdminActor != "" {
		return out, nil
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return out, err
	}
	if err := s.security.call(ctx, http.MethodGet, "/v1/calendar-shares", sess.User, pw, nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

// calendarShareFor returns the user's access to owner's calendar, or nil.
func (s *Server) calendarShareFor(ctx context.Context, sess *Session, owner string) (*calendarShare, error) {
	shares, err := s.calendarShareList(ctx, sess)
	if err != nil {
		return nil, err
	}
	for i := range shares.Received {
		if strings.EqualFold(shares.Received[i].Owner, owner) {
			return &shares.Received[i], nil
		}
	}
	return nil, nil
}

// withSharedCalendar opens owner's calendar with the user's own password, so a
// revoked grant stops working at once.
func (s *Server) withSharedCalendar(ctx context.Context, sess *Session, owner string, fn func(Mailstore) error) error {
	pw, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	st, err := s.dial(ctx, calendarLogin(sess.User, owner), pw)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return fn(st)
}

// withCalendarStore runs fn on the user's calendar, or on owner's.
func (s *Server) withCalendarStore(ctx context.Context, sess *Session, owner string, fn func(Mailstore) error) error {
	if owner != "" {
		return s.withSharedCalendar(ctx, sess, owner, fn)
	}
	return s.sessions.withStore(ctx, sess, s.dial, fn)
}

// sharedName is how an owner appears: the part of the address people recognise.
func sharedName(owner string) string {
	if local, _, ok := strings.Cut(owner, "@"); ok {
		return local
	}
	return owner
}

// redactPrivate leaves only what free/busy already tells a colleague. It runs
// here rather than in a template, so private details are never in the page.
func redactPrivate(e Event) Event {
	return Event{
		UID: e.UID, Summary: "Busy", Start: e.Start, End: e.End, AllDay: e.AllDay,
		RRule: e.RRule, ExDates: e.ExDates, Busy: true, Reminder: -1, Status: e.Status,
		Private: true, Modified: e.Modified,
	}
}

// sharedEventsOf returns owner's events as the user may see them.
func (s *Server) sharedEventsOf(ctx context.Context, sess *Session, share calendarShare, loc *time.Location) ([]Event, error) {
	var objs []Object
	err := s.withSharedCalendar(ctx, sess, share.Owner, func(st Mailstore) error {
		var err error
		objs, err = st.Objects(ctx, CollCalendar)
		return err
	})
	if err != nil {
		return nil, err
	}
	return sharedEvents(objs, share, loc), nil
}

func sharedEvents(objs []Object, share calendarShare, loc *time.Location) []Event {
	events := eventsFrom(objs, loc)
	out := make([]Event, 0, len(events))
	for _, e := range events {
		if e.Private && !share.CanEdit() {
			e = redactPrivate(e)
		}
		e.Owner, e.OwnerCalendar = share.Owner, e.Calendar
		e.Calendar = sharedName(share.Owner)
		e.ReadOnly = !share.CanEdit()
		out = append(out, e)
	}
	return out
}

// overlayEvents adds the calendars the user hasn't hidden. One that can't be
// read is left out rather than failing the user's own calendar.
func (s *Server) overlayEvents(ctx context.Context, sess *Session, loc *time.Location) ([]Event, []sharedCalendar) {
	shares, err := s.calendarShareList(ctx, sess)
	if err != nil {
		s.log.Warn("webmail: calendar shares unavailable", "user", sess.User, "error", err)
		return nil, nil
	}
	hidden := s.prefsCached(sess).HiddenCalendars
	var events []Event
	var list []sharedCalendar
	for _, c := range shares.Received {
		entry := sharedCalendar{Owner: c.Owner, Name: sharedName(c.Owner), CanEdit: c.CanEdit()}
		if slices.Contains(hidden, c.Owner) {
			entry.Hidden = true
			list = append(list, entry)
			continue
		}
		owned, err := s.sharedEventsOf(ctx, sess, c, loc)
		if err != nil {
			s.log.Warn("webmail: shared calendar unavailable", "user", sess.User, "owner", c.Owner, "error", err)
			entry.Failed = true
		}
		events = append(events, owned...)
		list = append(list, entry)
	}
	return events, list
}

// sharedCalendar is one calendar in the sidebar.
type sharedCalendar struct {
	Owner, Name             string
	CanEdit, Hidden, Failed bool
}

// sharedCalendarChanged republishes the owner's busy times after an edit.
func (s *Server) sharedCalendarChanged(sess *Session, owner string) {
	if s.security == nil {
		return
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := s.publishSharedFreeBusy(ctx, sess.User, pw, owner); err != nil {
			s.log.Warn("webmail: free/busy not published", "user", sess.User, "owner", owner, "error", err)
		}
	}()
}

func (s *Server) publishSharedFreeBusy(ctx context.Context, user, password, owner string) error {
	st, err := s.dial(ctx, calendarLogin(user, owner), password)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	objs, err := st.Objects(ctx, CollCalendar)
	if err != nil {
		return err
	}
	now := s.now()
	from, to := now.Add(-freeBusyBack), now.Add(freeBusyAhead)
	// The editor can't read the owner's zone from here, but busy times are
	// instants; only all-day events lean on it, as they do for a sign-in.
	body := map[string]any{"from": from.UTC(), "to": to.UTC(), "busy": busyFrom(eventsFrom(objs, s.defaultLoc), owner, from, to)}
	return s.security.call(ctx, http.MethodPut, "/v1/calendar-shares/"+url.PathEscape(owner)+"/freebusy", user, password, body, nil)
}

func (s *Server) calendarShareSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func(n string) { http.Redirect(w, r, "/settings/account?n="+n+"#calendar-sharing", http.StatusSeeOther) }
	if s.security == nil || sess.AdminActor != "" {
		http.Error(w, "Calendar sharing can't be changed here.", http.StatusForbidden)
		return
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	member := strings.ToLower(strings.TrimSpace(r.PostFormValue("member")))
	if member == "" || !strings.Contains(member, "@") {
		back("calendar-share-invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	path := "/v1/calendar-shares/" + url.PathEscape(member)
	notice := "calendar-shared"
	if r.PostFormValue("op") == "remove" {
		err = s.security.call(ctx, http.MethodDelete, path, sess.User, pw, nil, nil)
		notice = "calendar-unshared"
	} else {
		level := r.PostFormValue("level")
		if level != accessView && level != accessEdit {
			back("calendar-share-invalid")
			return
		}
		err = s.security.call(ctx, http.MethodPut, path, sess.User, pw, map[string]string{"level": level}, nil)
	}
	if err != nil {
		s.log.Warn("webmail: calendar share", "user", sess.User, "error", err)
		back("calendar-share-failed")
		return
	}
	back(notice)
}

// calendarOverlaySubmit shows or hides a shared calendar.
func (s *Server) calendarOverlaySubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	owner := strings.ToLower(strings.TrimSpace(r.PostFormValue("owner")))
	p := s.prefsCached(sess)
	p.HiddenCalendars = slices.DeleteFunc(slices.Clone(p.HiddenCalendars), func(o string) bool { return o == owner })
	if r.PostFormValue("hide") == "1" {
		p.HiddenCalendars = append(p.HiddenCalendars, owner)
	}
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	back := r.PostFormValue("back")
	if !strings.HasPrefix(back, "/calendar") {
		back = "/calendar"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
