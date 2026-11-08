package webmail

// Notifications on the user's phones and computers (Web Push), with the
// webmail closed.
//
// The mailbox service sends them: it sees every delivery, and holds the
// subscriptions and the key that signs them (internal/mailbox/push.go).
// The webmail's part is the browser end: the service worker that shows
// them (static/sw.js), the settings card that turns them on for a device,
// and publishing upcoming reminders, which only it can work out from the
// calendar, alongside free/busy times (freebusy.go).
//
// This is not push.go, which is the live update of an open page over IMAP
// IDLE.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// pushReminderAhead is how far ahead reminders are published. Changes to
// the calendar republish at once, and an open page republishes hourly; a
// recurring event's later reminders are picked up as time moves on, so
// someone who never opens the webmail for this long stops getting them.
const pushReminderAhead = 14 * 24 * time.Hour

// pushDevice is one browser that gets notifications.
type pushDevice struct {
	ID        int64      `json:"id"`
	Endpoint  string     `json:"endpoint"`
	Label     string     `json:"label"`
	Mail      string     `json:"mail"`
	Reminders bool       `json:"reminders"`
	Preview   bool       `json:"preview"`
	Created   time.Time  `json:"created"`
	LastSent  *time.Time `json:"last_sent"`
}

// Notifies says what the device gets, for the settings list.
func (d pushDevice) Notifies() string {
	var parts []string
	switch d.Mail {
	case "all":
		parts = append(parts, "new mail")
	case "primary":
		parts = append(parts, "new mail in Primary")
	}
	if d.Reminders {
		parts = append(parts, "reminders")
	}
	if len(parts) == 0 {
		return "Nothing"
	}
	s := strings.Join(parts, " and ")
	return strings.ToUpper(s[:1]) + s[1:]
}

// pushSettings is the settings card's data.
type pushSettings struct {
	// Key is the mailbox service's public key; empty when push is off.
	Key     string
	Devices []pushDevice
}

func (s *Server) pushCall(ctx context.Context, sess *Session, method, path string, in, out any) error {
	if s.security == nil {
		return errSecurityOff
	}
	password, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return s.security.call(ctx, method, path, sess.User, password, in, out)
}

// pushSettingsFor reads the card's data, or nil when push isn't offered.
func (s *Server) pushSettingsFor(ctx context.Context, sess *Session) *pushSettings {
	if s.security == nil || sess.AdminActor != "" {
		return nil
	}
	var out struct {
		Key     string       `json:"key"`
		Devices []pushDevice `json:"devices"`
	}
	if err := s.pushCall(ctx, sess, http.MethodGet, "/v1/push", nil, &out); err != nil {
		s.log.Warn("webmail: read push devices", "user", sess.User, "error", err)
		return nil
	}
	if out.Key == "" {
		return nil
	}
	loc := s.loc(sess)
	for i := range out.Devices {
		if t := out.Devices[i].LastSent; t != nil {
			local := t.In(loc)
			out.Devices[i].LastSent = &local
		}
	}
	return &pushSettings{Key: out.Key, Devices: out.Devices}
}

// deviceLabel names a browser from its User-Agent, as people would.
func deviceLabel(ua string) string {
	browser := "Browser"
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgA/") || strings.Contains(ua, "EdgiOS/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "SamsungBrowser/"):
		browser = "Samsung Internet"
	case strings.Contains(ua, "Firefox/") || strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		system = "iPhone"
	case strings.Contains(ua, "iPad"):
		system = "iPad"
	case strings.Contains(ua, "Android"):
		system = "Android"
	case strings.Contains(ua, "Windows"):
		system = "Windows"
	case strings.Contains(ua, "CrOS"):
		system = "ChromeOS"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		system = "macOS"
	case strings.Contains(ua, "Linux"):
		system = "Linux"
	}
	if system == "" {
		return browser
	}
	return browser + " on " + system
}

// webmailOrigin is the address push services are given for whoever runs
// this server.
func (s *Server) webmailOrigin(r *http.Request) string {
	if u, err := url.Parse(s.cfg.RecoveryURL); err == nil && u.Host != "" {
		return "https://" + u.Host
	}
	return "https://" + r.Host
}

type pushRequest struct {
	Endpoint  string `json:"endpoint"`
	P256dh    string `json:"p256dh"`
	Auth      string `json:"auth"`
	Mail      string `json:"mail"`
	Reminders bool   `json:"reminders"`
	Preview   bool   `json:"preview"`
	ID        int64  `json:"id"`
}

func readPushRequest(r *http.Request) (pushRequest, bool) {
	var in pushRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return in, json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in) == nil
	}
	// The device list's Remove buttons are plain forms.
	in.ID, _ = strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	return in, in.ID > 0
}

func (s *Server) pushJSON(w http.ResponseWriter, sess *Session, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		s.log.Warn("webmail: push", "user", sess.User, "error", err)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "That didn't work. Try again in a moment."})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// pushSubscribe turns notifications on for the browser asking, or saves
// what it wants.
func (s *Server) pushSubscribe(w http.ResponseWriter, r *http.Request, sess *Session) {
	in, ok := readPushRequest(r)
	if !ok || sess.AdminActor != "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	body := map[string]any{
		"endpoint": in.Endpoint, "p256dh": in.P256dh, "auth": in.Auth, "label": deviceLabel(r.UserAgent()),
		"mail": in.Mail, "reminders": in.Reminders, "preview": in.Preview, "contact": s.webmailOrigin(r),
	}
	err := s.pushCall(r.Context(), sess, http.MethodPut, "/v1/push/subscriptions", body, nil)
	if err == nil && in.Reminders {
		// So the reminders already on the calendar are there to send.
		if password, perr := s.sessions.password(sess); perr == nil {
			s.publishFreeBusy(sess.User, password, sess.Address)
		}
	}
	s.pushJSON(w, sess, err)
}

// pushDelete stops notifications to one device: this one, from its own
// page, or any of them from the list.
func (s *Server) pushDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	in, ok := readPushRequest(r)
	if !ok && in.Endpoint == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	err := s.pushCall(r.Context(), sess, http.MethodPost, "/v1/push/subscriptions/delete", map[string]any{"id": in.ID, "endpoint": in.Endpoint}, nil)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err != nil {
			s.log.Warn("webmail: push", "user", sess.User, "error", err)
			s.renderProblem(w, r, sess, http.StatusBadGateway, "The device couldn't be removed. Try again in a moment.")
			return
		}
		http.Redirect(w, r, "/settings/devices?n=push-removed#notifications", http.StatusSeeOther)
		return
	}
	s.pushJSON(w, sess, err)
}

// pushTest sends a notification to the device asking.
func (s *Server) pushTest(w http.ResponseWriter, r *http.Request, sess *Session) {
	in, ok := readPushRequest(r)
	if !ok || in.Endpoint == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.pushJSON(w, sess, s.pushCall(r.Context(), sess, http.MethodPost, "/v1/push/test", map[string]string{"endpoint": in.Endpoint}, nil))
}

// pushReminder is one upcoming reminder, as the mailbox service keeps it.
type pushReminder struct {
	Key   string    `json:"key"`
	At    time.Time `json:"at"`
	Start time.Time `json:"start"`
	Title string    `json:"title"`
	Body  string    `json:"body"`
	URL   string    `json:"url"`
}

// pushRemindersFrom lists the reminders due from now until ahead.
func pushRemindersFrom(events []Event, now time.Time, loc *time.Location, h24 bool, ahead time.Duration) []pushReminder {
	out := []pushReminder{}
	for _, r := range remindersBetween(events, now, loc, h24, ahead) {
		body := r.When
		if r.Where != "" {
			body += " · " + r.Where
		}
		out = append(out, pushReminder{Key: r.Key, At: time.Unix(r.FireAt, 0).UTC(), Start: time.Unix(r.StartAt, 0).UTC(), Title: r.Title, Body: body, URL: r.URL})
		if len(out) == 500 {
			break
		}
	}
	return out
}

// serviceWorker serves static/sw.js from the root, so it may look after
// every page.
func (s *Server) serviceWorker(w http.ResponseWriter, r *http.Request) {
	raw, err := staticFS.ReadFile("static/sw.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}

// manifest lets the webmail be installed as an app: its own window and
// icon, on a phone's home screen or a computer's dock.
func (s *Server) manifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":             "Elemta Mail",
		"short_name":       "Elemta",
		"id":               "/mail",
		"start_url":        "/mail",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#0F172A",
		"theme_color":      "#0F172A",
		"icons": []map[string]string{
			{"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
			{"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
			{"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
		},
	})
}
