package webmail

// The out-of-office reply has its own settings page and a banner across the
// webmail while it's on. It used to be only the first card on the Filters
// page, where people looking for "out of office" didn't find it, and once
// set nothing said it was still answering mail. The reply itself is still
// the vacation action in the user's Sieve script (filters.go).

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// awayRefresh is how long a session trusts the reply's state it read. The
// webmail's own saves update it at once; this only bounds how long a change
// made elsewhere (another device, another webmail pod) takes to show.
const awayRefresh = 10 * time.Minute

// awayState is what a session knows of the user's out-of-office reply.
type awayState struct {
	vac Vacation
	at  time.Time
}

// awayView is the banner: the reply is on, or will be.
type awayView struct {
	// Starts is the first day, set while the reply hasn't started yet.
	Starts string
	// Until is the last day, or empty when it runs until turned off.
	Until string
}

// awayBanner says whether the reply is on today, or will be, in loc.
func awayBanner(v Vacation, now time.Time, loc *time.Location) *awayView {
	if !v.Enabled {
		return nil
	}
	today := now.In(loc).Format("2006-01-02")
	if v.End != "" && today > v.End {
		return nil
	}
	out := &awayView{}
	if v.End != "" {
		out.Until = friendlyDay(v.End)
	}
	if v.Start != "" && today < v.Start {
		out.Starts = friendlyDay(v.Start)
	}
	return out
}

// friendlyDay shows a YYYY-MM-DD date as "Wed 3 Dec".
func friendlyDay(day string) string {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return day
	}
	return t.Format("Mon 2 Jan")
}

// awayApplies is whether this session should know about the reply: the
// user's own mailbox, read by the user, with filters available.
func (s *Server) awayApplies(sess *Session) bool {
	return s.sieve != nil && sess.AdminActor == "" && s.sessions.SelectedMailbox(sess) == ""
}

// awayCached is the reply's state as last read, without asking the server.
func (s *Server) awayCached(sess *Session) (Vacation, bool) {
	sess.awayMu.Lock()
	defer sess.awayMu.Unlock()
	if sess.away == nil {
		return Vacation{}, false
	}
	return sess.away.vac, true
}

func (s *Server) setAway(sess *Session, v Vacation) {
	sess.awayMu.Lock()
	sess.away = &awayState{vac: v, at: time.Now()}
	sess.awayMu.Unlock()
}

// refreshAway reads the reply's state when the session has none yet, and
// in the background when what it has is old. The first read waits briefly
// so the banner is there on the first page; later ones never hold a page
// up on the filter server.
func (s *Server) refreshAway(ctx context.Context, sess *Session) {
	if !s.awayApplies(sess) {
		return
	}
	sess.awayMu.Lock()
	known, stale := sess.away != nil, sess.away == nil || time.Since(sess.away.at) > awayRefresh
	busy := sess.awayLoading
	if stale && !busy {
		sess.awayLoading = true
	}
	sess.awayMu.Unlock()
	if !stale || busy {
		return
	}
	load := func(ctx context.Context) {
		defer func() {
			sess.awayMu.Lock()
			sess.awayLoading = false
			sess.awayMu.Unlock()
		}()
		set, _, _, err := s.loadFilters(ctx, sess)
		switch {
		case errors.Is(err, errFiltersOff):
			s.setAway(sess, Vacation{})
		case err != nil:
			// Keep what was known; try again on a later page.
			s.log.Debug("webmail: read out-of-office state", "user", sess.User, "error", err)
		default:
			s.setAway(sess, set.Vacation)
		}
	}
	if known {
		go load(context.WithoutCancel(ctx))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	load(ctx)
}

// outOfOfficePage is Settings > Out of office.
func (s *Server) outOfOfficePage(w http.ResponseWriter, r *http.Request, sess *Session) {
	fv := &filtersView{EditIdx: -1}
	v := view{Title: "Out of office", Session: sess, App: "settings", SettingsTab: "out-of-office", Filters: fv, Notice: notices[r.URL.Query().Get("n")]}
	s.withFolders(r, sess, &v)
	if s.sieve == nil {
		fv.Disabled = true
		s.render(w, "outofoffice.html", http.StatusOK, v)
		return
	}
	set, foreign, _, err := s.loadFilters(r.Context(), sess)
	if errors.Is(err, errFiltersOff) {
		fv.TurnedOff = true
		s.render(w, "outofoffice.html", http.StatusOK, v)
		return
	}
	if err != nil {
		s.log.Warn("webmail: read filters", "user", sess.User, "error", err)
		v.Problem = "The filter server didn't respond, so your automatic reply can't be shown right now."
		s.render(w, "outofoffice.html", http.StatusBadGateway, v)
		return
	}
	if s.awayApplies(sess) {
		s.setAway(sess, set.Vacation)
	}
	fv.Set, fv.Foreign = set, foreign
	if fv.Set.Vacation.Days == 0 {
		fv.Set.Vacation.Days = 1
	}
	s.render(w, "outofoffice.html", http.StatusOK, v)
}
