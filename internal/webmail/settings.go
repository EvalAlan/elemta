package webmail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Settings are one user's preferences. They are stored as a JSON object in
// the Settings collection, so they follow the user to any webmail pod.
type Settings struct {
	DisplayName string `json:"display_name,omitempty"`
	ReplyTo     string `json:"reply_to,omitempty"`
	Signature   string `json:"signature,omitempty"`
	// SignatureAbove puts the signature above quoted text in replies,
	// rather than at the very bottom.
	SignatureAbove bool   `json:"signature_above,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	Clock24        *bool  `json:"clock24,omitempty"`
	WeekStart      int    `json:"week_start,omitempty"` // 0 Sunday, 1 Monday
	PageSize       int    `json:"page_size,omitempty"`
	// CalendarView is the view the calendar opens in: month, week, day or agenda.
	CalendarView string `json:"calendar_view,omitempty"`
	// Theme is "light" or "dark", or empty to follow the device's setting.
	Theme string `json:"theme,omitempty"`
}

// themeCookie remembers the theme in the browser too, so the sign-in page,
// which has no session to read settings from, matches the rest.
const themeCookie = "elemta_theme"

func themeFromCookie(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil {
		return validTheme(c.Value)
	}
	return ""
}

func validTheme(t string) string {
	if t == "light" || t == "dark" {
		return t
	}
	return ""
}

func (s *Server) setThemeCookie(w http.ResponseWriter, theme string) {
	if theme == "" {
		s.setCookie(w, themeCookie, "", -1)
		return
	}
	s.setCookie(w, themeCookie, theme, 400*24*3600)
}

// themeSubmit switches the theme from the top bar's toggle. Script posts it
// in the background and changes the page at once; without script the form
// posts and the page reloads where it was.
func (s *Server) themeSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.prefs(r.Context(), sess)
	p.Theme = validTheme(r.PostFormValue("theme"))
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.setThemeCookie(w, p.Theme)
	if r.Header.Get("X-CSRF-Token") != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	back := "/mail"
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host && strings.HasPrefix(ref.Path, "/") {
		back = (&url.URL{Path: ref.Path, RawQuery: ref.RawQuery}).String()
	}
	redirectLocal(w, r, back)
}

const settingsID = "preferences"

// Uses24h reports whether times show as 15:04 (the default) or 3:04 PM.
func (p Settings) Uses24h() bool { return p.Clock24 == nil || *p.Clock24 }

// prefs returns the session's settings, reading them once per session.
func (s *Server) prefs(ctx context.Context, sess *Session) Settings {
	sess.prefsMu.Lock()
	if sess.prefs != nil {
		p := *sess.prefs
		sess.prefsMu.Unlock()
		return p
	}
	sess.prefsMu.Unlock()

	var p Settings
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollSettings)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if o.ID == settingsID {
				return json.Unmarshal(o.Data, &p)
			}
		}
		return nil
	})
	if err != nil {
		// Defaults are a reasonable page; a settings read failure shouldn't
		// block the mail. Don't cache, so the next request tries again.
		s.log.Warn("webmail: read settings", "user", sess.User, "error", err)
		return p
	}
	sess.prefsMu.Lock()
	sess.prefs = &p
	sess.prefsMu.Unlock()
	return p
}

func (s *Server) savePrefs(ctx context.Context, sess *Session, p Settings) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		return st.PutObject(ctx, CollSettings, Object{ID: settingsID, Title: "Webmail settings", ContentType: "application/json", Data: data})
	})
	if err != nil {
		return err
	}
	sess.prefsMu.Lock()
	sess.prefs = &p
	sess.prefsMu.Unlock()
	return nil
}

// prefsCached returns the settings already read, or the defaults, without
// touching IMAP. Rendering uses it so a page never waits on a settings read.
func (s *Server) prefsCached(sess *Session) Settings {
	sess.prefsMu.Lock()
	defer sess.prefsMu.Unlock()
	if sess.prefs != nil {
		return *sess.prefs
	}
	return Settings{}
}

// loc is the user's time zone, which every date on every page is shown in.
func (s *Server) loc(sess *Session) *time.Location {
	sess.prefsMu.Lock()
	defer sess.prefsMu.Unlock()
	if sess.prefs != nil && sess.prefs.Timezone != "" {
		if l, err := time.LoadLocation(sess.prefs.Timezone); err == nil {
			return l
		}
	}
	return s.defaultLoc
}

func (s *Server) pageSize(sess *Session) int {
	sess.prefsMu.Lock()
	defer sess.prefsMu.Unlock()
	if sess.prefs != nil && sess.prefs.PageSize > 0 {
		return sess.prefs.PageSize
	}
	return s.cfg.PageSize
}

// fromAddress is who the user's mail is from: their address with the
// display name they chose.
func (p Settings) fromAddress(addr string) Address {
	return Address{Name: p.DisplayName, Email: addr}
}

// commonZones are offered first in the time zone list; any IANA name can be
// typed instead.
var commonZones = []string{
	"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "America/Los_Angeles",
	"America/Anchorage", "Pacific/Honolulu", "America/Toronto", "America/Vancouver", "America/Mexico_City",
	"America/Sao_Paulo", "Europe/London", "Europe/Dublin", "Europe/Lisbon", "Europe/Paris", "Europe/Berlin",
	"Europe/Madrid", "Europe/Rome", "Europe/Amsterdam", "Europe/Stockholm", "Europe/Warsaw", "Europe/Athens",
	"Europe/Helsinki", "Europe/Istanbul", "Europe/Moscow", "Africa/Johannesburg", "Africa/Lagos", "Africa/Cairo",
	"Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Hong_Kong", "Asia/Shanghai", "Asia/Tokyo",
	"Asia/Seoul", "Australia/Perth", "Australia/Sydney", "Pacific/Auckland",
}

type settingsView struct {
	Prefs Settings
	Zones []string
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.prefs(r.Context(), sess)
	v := view{Title: "Settings", Session: sess, Notice: notices[r.URL.Query().Get("n")], Settings: &settingsView{Prefs: p, Zones: commonZones}}
	s.withFolders(r, sess, &v)
	s.render(w, "settings.html", http.StatusOK, v)
}

func (s *Server) settingsSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.prefs(r.Context(), sess)
	problem := ""
	p.DisplayName = strings.TrimSpace(r.PostFormValue("display_name"))
	if strings.ContainsAny(p.DisplayName, "\r\n<>") || len(p.DisplayName) > 120 {
		problem = "The display name can't contain line breaks or angle brackets."
	}
	p.ReplyTo = strings.TrimSpace(r.PostFormValue("reply_to"))
	if p.ReplyTo != "" {
		if _, err := mail.ParseAddress(p.ReplyTo); err != nil {
			problem = "The reply-to address isn't a valid email address."
		}
	}
	p.Signature = strings.TrimRight(normaliseText(r.PostFormValue("signature")), "\n")
	if len(p.Signature) > 4000 {
		problem = "Keep the signature under 4,000 characters."
	}
	p.SignatureAbove = r.PostFormValue("signature_above") == "1"
	if tz := strings.TrimSpace(r.PostFormValue("timezone")); tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			problem = "That time zone isn't recognised. Use a name like Europe/Paris."
		} else {
			p.Timezone = tz
		}
	}
	clock24 := r.PostFormValue("clock") != "12"
	p.Clock24 = &clock24
	p.WeekStart, _ = strconv.Atoi(r.PostFormValue("week_start"))
	if p.WeekStart != 1 {
		p.WeekStart = 0
	}
	if n, err := strconv.Atoi(r.PostFormValue("page_size")); err == nil && n >= 10 && n <= 200 {
		p.PageSize = n
	}
	p.Theme = validTheme(r.PostFormValue("theme"))
	switch v := r.PostFormValue("calendar_view"); v {
	case "month", "week", "day", "agenda":
		p.CalendarView = v
	}
	if problem != "" {
		v := view{Title: "Settings", Session: sess, Problem: problem, Settings: &settingsView{Prefs: p, Zones: commonZones}}
		s.withFolders(r, sess, &v)
		s.render(w, "settings.html", http.StatusBadRequest, v)
		return
	}
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.setThemeCookie(w, p.Theme)
	http.Redirect(w, r, "/settings?n=settings-saved", http.StatusSeeOther)
}

// timezoneSubmit records the browser's time zone the first time a user
// signs in, so dates are right before they ever open Settings. It never
// overrides a zone the user chose.
func (s *Server) timezoneSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	tz := strings.TrimSpace(r.PostFormValue("timezone"))
	if _, err := time.LoadLocation(tz); err != nil || tz == "" || tz == "Local" {
		http.Error(w, "unknown time zone", http.StatusBadRequest)
		return
	}
	p := s.prefs(r.Context(), sess)
	if p.Timezone != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p.Timezone = tz
	if err := s.savePrefs(r.Context(), sess, p); err != nil && !errors.Is(err, context.Canceled) {
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// withFolders fills the folder tree for pages outside the mail view. A
// failure leaves the tree empty rather than failing the page.
func (s *Server) withFolders(r *http.Request, sess *Session, v *view) {
	_ = s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		v.Folders, err = st.Folders(r.Context())
		return err
	})
}
