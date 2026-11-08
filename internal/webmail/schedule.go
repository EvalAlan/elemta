package webmail

// Scheduled send and snooze, the webmail's half.
//
// The mailbox service keeps both and acts on them when they come due
// (internal/mailbox/scheduled.go): a send hours from now happens when nobody
// is signed in, and the webmail holds a password only while a session lasts.
// What this side does is offer the times, hand a message or a snooze over
// through the account API, and show what is waiting in the Scheduled and
// Snoozed folders, which are ordinary folders a mail app sees too.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	RoleScheduled Role = "scheduled"
	RoleSnoozed   Role = "snoozed"
)

// laterChoice is one preset in a "send later" or "snooze until" menu.
type laterChoice struct {
	Label string // "Tomorrow morning"
	When  string // "Tue 8:00 AM"
	Value string // RFC 3339, posted back
}

// laterChoices are the presets for now in the user's zone. Snoozing offers
// "later today", which a send rarely wants; sending offers an afternoon.
func laterChoices(now time.Time, loc *time.Location, clock24, snooze bool) []laterChoice {
	now = now.In(loc)
	day := func(d time.Time, h int) time.Time {
		return time.Date(d.Year(), d.Month(), d.Day(), h, 0, 0, 0, loc)
	}
	tomorrow := now.AddDate(0, 0, 1)
	var out []laterChoice
	add := func(label string, t time.Time) {
		if !t.After(now) {
			return
		}
		for _, c := range out {
			if c.Value == t.Format(time.RFC3339) {
				return
			}
		}
		out = append(out, laterChoice{Label: label, When: shortWhen(t, now, clock24), Value: t.Format(time.RFC3339)})
	}
	if snooze && now.Hour() < 17 {
		later := now.Add(3 * time.Hour).Truncate(time.Hour).Add(time.Hour)
		add("Later today", later)
	}
	add("Tomorrow morning", day(tomorrow, 8))
	if !snooze {
		add("Tomorrow afternoon", day(tomorrow, 13))
	}
	// The coming weekend, from a weekday; Monday for both.
	if wd := now.Weekday(); snooze && wd >= time.Monday && wd <= time.Thursday {
		add("This weekend", day(now.AddDate(0, 0, int(time.Saturday-wd)), 8))
	}
	daysToMonday := (int(time.Monday) - int(now.Weekday()) + 7) % 7
	if daysToMonday == 0 {
		daysToMonday = 7
	}
	add("Next week", day(now.AddDate(0, 0, daysToMonday), 8))
	return out
}

// shortWhen is a time near now as a menu shows it: "Tue 8:00 AM".
func shortWhen(t, now time.Time, clock24 bool) string {
	clock := "3:04 PM"
	if clock24 {
		clock = "15:04"
	}
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format(clock)
	}
	if t.Sub(now) < 6*24*time.Hour {
		return t.Format("Mon " + clock)
	}
	return t.Format("Jan 2, " + clock)
}

// whenText is a time as a sentence wants it: "today at 3:00 PM", "tomorrow at
// 8:00 AM", "Tuesday, November 10 at 8:00 AM".
func whenText(loc *time.Location, clock24 bool, t, now time.Time) string {
	t, now = t.In(loc), now.In(loc)
	clock := "3:04 PM"
	if clock24 {
		clock = "15:04"
	}
	y1, m1, d1 := now.Date()
	y2, m2, d2 := t.Date()
	today := time.Date(y1, m1, d1, 0, 0, 0, 0, loc)
	that := time.Date(y2, m2, d2, 0, 0, 0, 0, loc)
	switch days := int(that.Sub(today).Hours()/24 + 0.5); {
	case days == 0:
		return "today at " + t.Format(clock)
	case days == 1:
		return "tomorrow at " + t.Format(clock)
	case y1 == y2:
		return t.Format("Monday, January 2 at " + clock)
	}
	return t.Format("Monday, January 2, 2006 at " + clock)
}

var errLaterTime = errors.New("pick a time in the future, within a year")

// parseLater reads a menu's choice: a preset's RFC 3339 value, or "custom"
// with the date-time picker's local value, read in the user's zone.
func parseLater(value, local string, loc *time.Location, now time.Time) (time.Time, error) {
	var t time.Time
	var err error
	if value == "custom" {
		t, err = time.ParseInLocation("2006-01-02T15:04", strings.TrimSpace(local), loc)
	} else {
		t, err = time.Parse(time.RFC3339, value)
	}
	if err != nil || !t.After(now.Add(-time.Minute)) || t.After(now.AddDate(1, 0, 0)) {
		return time.Time{}, errLaterTime
	}
	return t, nil
}

// laterOffered reports whether this session can schedule or snooze: the
// mailbox service keeps them for the signed-in account, so not while reading
// a shared mailbox or under administrator access.
func (s *Server) laterOffered(sess *Session) bool {
	return s.security != nil && sess.AdminActor == "" && s.sessions.SelectedMailbox(sess) == ""
}

// laterProblem turns a mailbox service refusal into something to show.
func laterProblem(err error, what string) string {
	switch {
	case errors.Is(err, errSecurityOff):
		return what + " isn't available on this server."
	case errors.Is(err, errSecurityInput):
		msg := strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":"))
		if msg != "" && msg != "bad request" && msg != "not found" {
			return strings.ToUpper(msg[:1]) + msg[1:] + "."
		}
	}
	return what + " didn't work. Try again in a moment."
}

func (s *Server) scheduleSend(ctx context.Context, sess *Session, from string, rcpts []string, at time.Time, raw []byte) error {
	in := struct {
		From   string    `json:"from"`
		To     []string  `json:"to"`
		SendAt time.Time `json:"send_at"`
		Raw    []byte    `json:"raw"`
	}{from, rcpts, at.UTC(), raw}
	return s.pushCall(ctx, sess, http.MethodPost, "/v1/scheduled", in, nil)
}

type scheduledItem struct {
	UID       uint32    `json:"uid"`
	SendAt    time.Time `json:"send_at"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error"`
}

type snoozedItem struct {
	UID      uint32    `json:"uid"`
	Until    time.Time `json:"until"`
	ReturnTo string    `json:"return_to"`
}

// laterView is what the mail page shows about waiting messages.
type laterView struct {
	// Snooze and Schedule are the menus' presets.
	Snooze, Schedule []laterChoice
	// Times are the list's send or return times by UID, in Scheduled or
	// Snoozed; Verb says which ("Sends", "Back").
	Times map[uint32]string
	Verb  string
	// The open message, in Scheduled or Snoozed.
	When    string
	Problem string
	Kind    Role
}

// composeLater is the compose page's "send later" menu, or nil.
func (s *Server) composeLater(ctx context.Context, sess *Session) *laterView {
	if !s.laterOffered(sess) {
		return nil
	}
	return &laterView{Schedule: laterChoices(s.now(), s.loc(sess), s.prefs(ctx, sess).Uses24h(), false)}
}

// decorateLater fills v.Later for the mail page.
func (s *Server) decorateLater(ctx context.Context, sess *Session, v *view) {
	if !s.laterOffered(sess) {
		return
	}
	now := s.now()
	loc := s.loc(sess)
	clock24 := s.prefs(ctx, sess).Uses24h()
	lv := &laterView{
		Snooze:   laterChoices(now, loc, clock24, true),
		Schedule: laterChoices(now, loc, clock24, false),
	}
	v.Later = lv
	role := RoleNone
	for _, f := range v.Folders {
		if f.Name == v.Folder {
			role = f.Role
		}
	}
	if role != RoleScheduled && role != RoleSnoozed {
		return
	}
	lv.Kind, lv.Times = role, map[uint32]string{}
	at := map[uint32]time.Time{}
	notes := map[uint32]string{}
	if role == RoleScheduled {
		lv.Verb = "Sends"
		var out struct {
			Scheduled []scheduledItem `json:"scheduled"`
		}
		if err := s.pushCall(ctx, sess, http.MethodGet, "/v1/scheduled", nil, &out); err != nil {
			s.log.Warn("webmail: scheduled list", "user", sess.User, "error", err)
			return
		}
		for _, it := range out.Scheduled {
			at[it.UID] = it.SendAt
			if it.LastError != "" {
				// The detail is for the server's log, not for the reader.
				notes[it.UID] = "The last try didn't go through. Trying again."
			}
		}
	} else {
		lv.Verb = "Back"
		var out struct {
			Snoozed []snoozedItem `json:"snoozed"`
		}
		if err := s.pushCall(ctx, sess, http.MethodGet, "/v1/snooze", nil, &out); err != nil {
			s.log.Warn("webmail: snoozed list", "user", sess.User, "error", err)
			return
		}
		for _, it := range out.Snoozed {
			at[it.UID] = it.Until
		}
	}
	for uid, t := range at {
		lv.Times[uid] = shortWhen(t.In(loc), now.In(loc), clock24)
	}
	if v.Message != nil {
		if t, ok := at[v.Message.UID]; ok {
			lv.When = whenText(loc, clock24, t, now)
			lv.Problem = notes[v.Message.UID]
		}
	}
}

// snoozable reports whether messages in a folder can be snoozed: not drafts
// or scheduled mail, which are waiting for something else.
func snoozable(name string, folders []Folder) bool {
	for _, f := range folders {
		if f.Name == name {
			return f.Role != RoleDrafts && f.Role != RoleScheduled
		}
	}
	return false
}

// laterAction handles the mail page's scheduled-send and snooze buttons.
// They're calls to the mailbox service, not IMAP, so they don't go through
// the store. It reports false for an op that isn't one of them.
func (s *Server) laterAction(w http.ResponseWriter, r *http.Request, sess *Session, folder, op string, uids []uint32, back string) bool {
	// A button in a shared form (the bulk bar, the More menu) can post only
	// one value, so a preset there arrives as "snooze@<time>".
	until := r.PostFormValue("until")
	if t, ok := strings.CutPrefix(op, "snooze@"); ok {
		op, until = "snooze", t
	}
	switch op {
	case "snooze", "unsnooze", "send-now", "reschedule", "unschedule":
	default:
		return false
	}
	if !s.laterOffered(sess) {
		s.renderProblem(w, r, sess, http.StatusForbidden, "Snooze and scheduled send aren't available here.")
		return true
	}
	ctx := r.Context()
	now := s.now()
	what := "Snooze"
	var err error
	notice, leaves := "", true
	var undo *undoMove
	switch op {
	case "snooze":
		var at time.Time
		if at, err = parseLater(until, r.PostFormValue("until_local"), s.loc(sess), now); err != nil {
			break
		}
		var out struct {
			Folder string   `json:"folder"`
			UIDs   []uint32 `json:"uids"`
		}
		err = s.pushCall(ctx, sess, http.MethodPost, "/v1/snooze", map[string]any{"folder": folder, "uids": uids, "until": at.UTC()}, &out)
		notice = plural("snoozed", len(uids))
		if err == nil && out.Folder != folder && len(out.UIDs) > 0 {
			// Undo is a move back out of Snoozed, which ends the snooze.
			undo = &undoMove{From: out.Folder, To: folder, UIDs: out.UIDs}
		}
		if out.Folder == folder {
			leaves = false // a new time for something already snoozed
		}
	case "unsnooze":
		err = s.pushCall(ctx, sess, http.MethodPost, "/v1/snooze/cancel", map[string]any{"uids": uids}, nil)
		notice = plural("unsnoozed", len(uids))
	case "send-now", "reschedule":
		what = "Scheduling"
		at := now
		if op == "reschedule" {
			if at, err = parseLater(until, r.PostFormValue("until_local"), s.loc(sess), now); err != nil {
				break
			}
		}
		if len(uids) != 1 {
			err = errSecurityInput
			break
		}
		err = s.pushCall(ctx, sess, http.MethodPost, "/v1/scheduled/reschedule", map[string]any{"uid": uids[0], "send_at": at.UTC()}, nil)
		notice, leaves = "rescheduled", false
		if op == "send-now" {
			notice = "sending-now"
		}
	case "unschedule":
		what = "Editing"
		if len(uids) != 1 {
			err = errSecurityInput
			break
		}
		var out struct {
			Folder string `json:"folder"`
			UID    uint32 `json:"uid"`
		}
		if err = s.pushCall(ctx, sess, http.MethodPost, "/v1/scheduled/cancel", map[string]any{"uid": uids[0]}, &out); err == nil {
			redirectLocal(w, r, composeURL("draft", out.Folder, out.UID))
			return true
		}
	}
	if errors.Is(err, errLaterTime) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Pick a time in the future, within a year.")
		return true
	}
	if errors.Is(err, errSecurityInput) && strings.Contains(err.Error(), "not found") {
		s.renderProblem(w, r, sess, http.StatusConflict, "That message isn't waiting any more: it may have just been sent or moved.")
		return true
	}
	if err != nil {
		s.log.Warn("webmail: "+op, "user", sess.User, "error", err)
		s.renderProblem(w, r, sess, http.StatusBadGateway, laterProblem(err, what))
		return true
	}
	if leaves {
		back = dropParam(back, "uid")
	}
	back = setParam(back, "n", notice)
	if undo != nil {
		back = setParam(back, "undo", undo.encode(now))
	} else {
		back = dropParam(back, "undo")
	}
	redirectLocal(w, r, back)
	return true
}
