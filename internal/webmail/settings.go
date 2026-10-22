package webmail

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
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
	// Empty region follows the user's time zone; the overlay is on unless disabled.
	HolidayDisabled       bool     `json:"holiday_disabled,omitempty"`
	HolidayRegion         string   `json:"holiday_region,omitempty"`
	HolidayExtraCountries []string `json:"holiday_extra_countries,omitempty"`
	HolidayInformal       bool     `json:"holiday_informal,omitempty"`
	HolidayObserved       bool     `json:"holiday_observed,omitempty"`
	HolidayHidden         []string `json:"holiday_hidden,omitempty"`
	// Theme is "light" or "dark", or empty to follow the device's setting.
	Theme string `json:"theme,omitempty"`
	// Palette is the colour scheme: empty for the default, which matches
	// the administration console, or "tidewater".
	Palette string `json:"palette,omitempty"`
	// Conversations groups the message list by thread; nil means on.
	Conversations *bool `json:"conversations,omitempty"`
	// LoadImages shows remote images without asking, except in Junk. Off by
	// default: loading an image tells its sender the message was opened.
	LoadImages bool `json:"load_images,omitempty"`
	// MailCalendar keeps messages at a reading width and shows the calendar
	// panel beside them on wide screens. Off, a message uses the full pane.
	MailCalendar bool `json:"mail_calendar,omitempty"`
}

// GroupConversations reports whether lists are grouped by thread.
func (p Settings) GroupConversations() bool { return p.Conversations == nil || *p.Conversations }

// conversationsSubmit switches the list between conversations and single
// messages, from the list's own menu.
func (s *Server) conversationsSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.prefs(r.Context(), sess)
	on := r.PostFormValue("on") == "1"
	p.Conversations = &on
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectLocal(w, r, localBack(r.PostFormValue("back"), "/mail"))
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

// paletteCookie does for the colour scheme what themeCookie does for
// light and dark.
const paletteCookie = "elemta_palette"

func paletteFromCookie(r *http.Request) string {
	if c, err := r.Cookie(paletteCookie); err == nil {
		return validPalette(c.Value)
	}
	return ""
}

func validPalette(p string) string {
	if p == "tidewater" {
		return p
	}
	return ""
}

func validTheme(t string) string {
	if t == "light" || t == "dark" {
		return t
	}
	return ""
}

// setAppearanceCookies copies the theme and palette into cookies; an empty
// value is the default, so its cookie is removed.
func (s *Server) setAppearanceCookies(w http.ResponseWriter, p Settings) {
	for name, v := range map[string]string{themeCookie: p.Theme, paletteCookie: p.Palette} {
		if v == "" {
			s.setCookie(w, name, "", -1)
			continue
		}
		s.setCookie(w, name, v, 400*24*3600)
	}
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
	s.setAppearanceCookies(w, p)
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

// mailCalendarSubmit shows or hides the calendar beside messages, from the
// top bar's toggle. The panel is rendered by the server, so the page reloads
// where it was: the form carries its own URL, because pages send no Referer.
func (s *Server) mailCalendarSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	p := s.prefs(r.Context(), sess)
	p.MailCalendar = r.PostFormValue("on") == "1"
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	redirectLocal(w, r, localBack(r.PostFormValue("back"), "/mail"))
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
	CanRecover       bool
	RecoveryEmail    string
	Prefs            Settings
	Zones            []string
	HolidayRegions   []holidayRegionChoice
	HolidayCountries []holidayRegionChoice
	HolidayDefault   string
	HiddenHolidays   []hiddenHolidayChoice
	// CanChangePassword shows the password form.
	CanChangePassword bool
	MinPasswordLength int
	// DAVURL is the address to give calendar and contact apps.
	DAVURL string
	// Security is two-step verification and app passwords; nil when the
	// mailbox service's API isn't configured.
	Security *securityView
	// Tab is the section shown: general, account, security or devices.
	Tab string
	// MailHost is the server name mail apps connect to.
	MailHost string
	// Notice is shown in the card named by NoticeCard, the one the change
	// was made in, rather than at the top of the page: after a change the
	// page returns to that card, so a notice at the top would go unseen.
	Notice, NoticeCard string
	// Forwarding is the account's directory forwarding; nil hides the card
	// (no directory, or the mail settings couldn't be read). ForwardText
	// keeps what was typed when the form is shown again with a problem.
	Forwarding   *AccountMail
	ForwardText  string
	ForwardLimit int
	// Senders are the allowed and blocked senders; nil hides the card.
	// AllowText and BlockText keep what was typed when shown again with a
	// problem.
	Senders              *senderRules
	AllowText, BlockText string
	Retention            []folderRetention
}

// noticeCards places each settings notice in the card it is about. The
// cards' ids match the anchors their forms and redirects return to.
var noticeCards = map[string]string{
	"forwarding-saved":     "forwarding",
	"senders-saved":        "senders",
	"senders-failed":       "senders",
	"forwarding-failed":    "forwarding",
	"retention-saved":      "retention",
	"settings-saved":       "general",
	"password-changed":     "password",
	"recovery-sent":        "recovery",
	"recovery-removed":     "recovery",
	"recovery-code-used":   "two-step",
	"2fa-off":              "two-step",
	"app-password-deleted": "app-passwords",
	"app-required":         "app-passwords",
	"app-optional":         "app-passwords",
}

// settingsTitles names the settings tabs, for the page title.
var settingsTitles = map[string]string{
	"general":  "Settings",
	"account":  "Account",
	"security": "Security",
	"devices":  "Mail apps and sync",
}

// mailHost is the server name to give mail apps: the public origin's host
// when one is configured, else the host this page was reached on.
func (s *Server) mailHost(r *http.Request) string {
	host := r.Host
	if s.cfg.RecoveryURL != "" {
		if u, err := url.Parse(s.cfg.RecoveryURL); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// davURL is where CalDAV and CardDAV clients should point. The configured
// public origin wins; otherwise the address this page was reached on,
// which is what the user's browser already trusts.
func (s *Server) davURL(r *http.Request) string {
	if s.cfg.RecoveryURL != "" {
		return strings.TrimSuffix(s.cfg.RecoveryURL, "/") + davRoot
	}
	scheme := "https"
	if r.TLS == nil && s.cfg.SecureCookies != nil && !*s.cfg.SecureCookies {
		scheme = "http"
	}
	return scheme + "://" + r.Host + davRoot
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.settingsTab("general")(w, r, sess)
}

// settingsTab serves one settings section. Each loads only what it shows,
// so a slow mailbox API doesn't hold up the general settings.
func (s *Server) settingsTab(tab string) func(http.ResponseWriter, *http.Request, *Session) {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) {
		v, err := s.settingsView(r, sess, tab)
		if err != nil {
			s.fail(w, r, sess, err)
			return
		}
		s.render(w, "settings.html", http.StatusOK, v)
	}
}

func (s *Server) settingsView(r *http.Request, sess *Session, tab string) (view, error) {
	p := s.prefs(r.Context(), sess)
	v := view{Title: settingsTitles[tab], Session: sess, App: "settings", SettingsTab: tab, Notice: notices[r.URL.Query().Get("n")],
		Settings: &settingsView{Tab: tab, Prefs: p, Zones: commonZones, CanChangePassword: s.passwords != nil, MinPasswordLength: s.cfg.MinPasswordLength, DAVURL: s.davURL(r), MailHost: s.mailHost(r)}}
	if card, ok := noticeCards[r.URL.Query().Get("n")]; ok {
		v.Settings.Notice, v.Settings.NoticeCard, v.Notice = v.Notice, card, ""
	}
	if tab == "general" {
		v.Settings.HolidayRegions = holidayRegionChoices(false)
		v.Settings.HolidayCountries = holidayRegionChoices(true)
		v.Settings.HolidayDefault = holidayRegionLabel(inferredHolidayRegion(p.Timezone, s.defaultLoc.String()))
		v.Settings.HiddenHolidays = hiddenHolidayChoices(p.HolidayHidden)
	}
	if tab == "account" {
		if m, ok := s.accountMail(r.Context(), sess); ok {
			v.Settings.Forwarding = &m
			v.Settings.ForwardText = strings.Join(m.Forward, ", ")
			v.Settings.ForwardLimit = s.forwardLimit(r.Context(), sess)
		}
		if rules, err := s.senderRules(r.Context(), sess); err != nil {
			s.log.Warn("webmail: read sender rules", "user", sess.User, "error", err)
		} else if rules != nil {
			v.Settings.Senders = rules
			v.Settings.AllowText, v.Settings.BlockText = strings.Join(rules.Allow, "\n"), strings.Join(rules.Block, "\n")
		}
	}
	if s.recovery != nil && tab == "account" {
		rec, err := s.recoveryRecord(r.Context(), s.recoveryAccount(sess.User))
		if err != nil {
			return v, err
		}
		v.Settings.CanRecover = true
		v.Settings.RecoveryEmail = rec.Email
	}
	if s.security != nil && (tab == "security" || tab == "devices") {
		// The rest of the page works without the mailbox service's API, so
		// its absence is shown on the card rather than failing the page.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		st, err := s.securityStatusFor(ctx, sess)
		cancel()
		if err != nil {
			s.log.Warn("webmail: account security status", "user", sess.User, "error", err)
		}
		v.Settings.Security = &securityView{Status: st, Unavailable: err != nil}
	}
	s.withFolders(r, sess, &v)
	if tab == "account" {
		if saved, err := s.folderRetentions(r.Context(), sess); err != nil {
			s.log.Warn("webmail: read folder retention", "user", sess.User, "error", err)
		} else if saved != nil {
			byName := make(map[string]int, len(saved))
			for _, setting := range saved {
				byName[setting.Name] = setting.Days
			}
			for _, role := range []Role{RoleTrash, RoleJunk, RoleSent} {
				for _, folder := range v.Folders {
					if folder.Role == role {
						v.Settings.Retention = append(v.Settings.Retention, folderRetention{Name: folder.Name, Days: byName[folder.Name], Role: role})
						break
					}
				}
			}
		}
	}
	return v, nil
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
	p.Palette = validPalette(r.PostFormValue("palette"))
	conv := r.PostFormValue("conversations") == "1"
	p.Conversations = &conv
	p.LoadImages = r.PostFormValue("load_images") == "1"
	p.MailCalendar = r.PostFormValue("mail_calendar") == "1"
	switch v := r.PostFormValue("calendar_view"); v {
	case "month", "week", "day", "agenda":
		p.CalendarView = v
	}
	p.HolidayDisabled = r.PostFormValue("holiday_enabled") != "1"
	p.HolidayInformal = r.PostFormValue("holiday_informal") == "1"
	p.HolidayObserved = r.PostFormValue("holiday_observed") == "1"
	if region := r.PostFormValue("holiday_region"); region == "" || validHolidayRegion(region) {
		p.HolidayRegion = region
	} else {
		problem = "Choose a listed holiday region."
	}
	p.HolidayExtraCountries = nil
	for _, country := range r.PostForm["holiday_extra_countries"] {
		if !validHolidayCountry(country) {
			problem = "Choose listed holiday countries."
			break
		}
		if country != p.HolidayRegion && !slices.Contains(p.HolidayExtraCountries, country) {
			p.HolidayExtraCountries = append(p.HolidayExtraCountries, country)
		}
	}
	// Without script, the picker's Add and remove buttons submit the form.
	if add := r.PostFormValue("holiday_extra_add"); add != "" {
		if !validHolidayCountry(add) {
			problem = "Choose listed holiday countries."
		} else if add != p.HolidayRegion && !slices.Contains(p.HolidayExtraCountries, add) {
			p.HolidayExtraCountries = append(p.HolidayExtraCountries, add)
		}
	}
	if remove := r.PostFormValue("holiday_extra_remove"); remove != "" {
		p.HolidayExtraCountries = slices.DeleteFunc(p.HolidayExtraCountries, func(v string) bool { return v == remove })
	}
	if len(p.HolidayExtraCountries) > 12 {
		problem = "Choose at most 12 additional countries."
	}
	if key := r.PostFormValue("holiday_restore"); key != "" {
		p.HolidayHidden = slices.DeleteFunc(p.HolidayHidden, func(v string) bool { return v == key })
	}
	if problem != "" {
		v := view{Title: "Settings", Session: sess, App: "settings", SettingsTab: "general", Problem: problem, Settings: &settingsView{Tab: "general", Prefs: p, Zones: commonZones, CanChangePassword: s.passwords != nil, MinPasswordLength: s.cfg.MinPasswordLength, HolidayRegions: holidayRegionChoices(false), HolidayCountries: holidayRegionChoices(true), HolidayDefault: holidayRegionLabel(inferredHolidayRegion(p.Timezone, s.defaultLoc.String())), HiddenHolidays: hiddenHolidayChoices(p.HolidayHidden)}}
		s.withFolders(r, sess, &v)
		s.render(w, "settings.html", http.StatusBadRequest, v)
		return
	}
	if err := s.savePrefs(r.Context(), sess, p); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.setAppearanceCookies(w, p)
	if r.PostFormValue("holiday_extra_op") != "" || r.PostFormValue("holiday_extra_remove") != "" {
		http.Redirect(w, r, "/settings?n=settings-saved#holidays", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?n=settings-saved#general", http.StatusSeeOther)
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
