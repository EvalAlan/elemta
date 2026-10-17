package webmail

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie  = "elemta_wm"
	preLoginCookie = "elemta_wm_pre"
)

// Server is the webmail HTTP application.
type Server struct {
	cfg      Config
	sessions *SessionManager
	dial     Dialer
	submit   Submitter
	// sieve reaches the ManageSieve server for filters; nil when none is
	// configured, which hides the feature.
	sieve   SieveDialer
	tmpl    map[string]*template.Template
	log     *slog.Logger
	limiter *loginLimiter
	now     func() time.Time
	// defaultLoc is the time zone for users who haven't chosen one and
	// whose browser hasn't reported one yet.
	defaultLoc *time.Location
}

// NewServer builds the webmail from a validated config. dial and submit may
// be nil, in which case the IMAP and SMTP implementations from cfg are used.
func NewServer(cfg Config, dial Dialer, submit Submitter, log *slog.Logger) (*Server, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if dial == nil {
		dial = IMAPDialer(cfg)
	}
	if submit == nil {
		submit = SMTPSubmitter{Addr: cfg.SubmissionAddr, TLSMode: cfg.SubmissionTLS, InsecureSkipVerify: cfg.InsecureSkipVerify}
	}
	if log == nil {
		log = slog.Default()
	}
	sessions, err := newSessions(cfg)
	if err != nil {
		return nil, err
	}
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	var sieve SieveDialer
	if cfg.SieveAddr != "" {
		sieve = ManageSieveDialer(cfg.SieveAddr, cfg.SieveTLS, cfg.InsecureSkipVerify)
	}
	return &Server{
		cfg: cfg, sessions: sessions, dial: dial, submit: submit, tmpl: tmpl, sieve: sieve,
		log: log, limiter: newLoginLimiter(10, 15*time.Minute), now: time.Now,
		defaultLoc: cfg.location(),
	}, nil
}

// newSessions builds the session manager the config asks for.
func newSessions(cfg Config) (*SessionManager, error) {
	if cfg.SessionStore != "valkey" {
		return NewSessionManager(cfg.sessionTTL())
	}
	addr := cfg.ValkeyAddr
	if addr == "" {
		addr = os.Getenv("VALKEY_ADDR")
	}
	if addr == "" {
		return nil, errors.New("webmail: session_store = \"valkey\" needs valkey_addr or VALKEY_ADDR")
	}
	key, err := loadSessionKey(cfg.SessionKeyFile)
	if err != nil {
		return nil, err
	}
	store, err := NewValkeySessionStore(addr)
	if err != nil {
		return nil, err
	}
	return NewSharedSessionManager(cfg.sessionTTL(), key, store)
}

// Sessions exposes the session manager so the caller can run its sweeper.
func (s *Server) Sessions() *SessionManager { return s.sessions }

// Handler returns the application's routes wrapped in its security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(staticFiles()))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/mail", http.StatusFound) })
	mux.HandleFunc("GET /mail", s.authed(s.mailPage))
	mux.HandleFunc("GET /mail/body", s.authed(s.messageBody))
	mux.HandleFunc("GET /mail/part", s.authed(s.messagePart))
	mux.HandleFunc("GET /mail/raw", s.authed(s.messageRaw))
	mux.HandleFunc("GET /mail/print", s.authed(s.messagePrint))
	mux.HandleFunc("GET /api/reminders", s.authed(s.remindersAPI))
	mux.HandleFunc("POST /mail/action", s.authed(s.messageAction))
	mux.HandleFunc("GET /compose", s.authed(s.composePage))
	mux.HandleFunc("POST /compose", s.authed(s.composeSubmit))
	mux.HandleFunc("GET /folders", s.authed(s.foldersPage))
	mux.HandleFunc("POST /folders", s.authed(s.foldersSubmit))
	mux.HandleFunc("GET /settings", s.authed(s.settingsPage))
	mux.HandleFunc("POST /settings", s.authed(s.settingsSubmit))
	mux.HandleFunc("POST /settings/timezone", s.authed(s.timezoneSubmit))
	mux.HandleFunc("POST /settings/theme", s.authed(s.themeSubmit))
	mux.HandleFunc("GET /contacts", s.authed(s.contactsPage))
	mux.HandleFunc("POST /contacts", s.authed(s.contactsSubmit))
	mux.HandleFunc("GET /contacts/export", s.authed(s.contactsExport))
	mux.HandleFunc("POST /contacts/import", s.authed(s.contactsImport))
	mux.HandleFunc("GET /calendar", s.authed(s.calendarPage))
	mux.HandleFunc("GET /calendar/event", s.authed(s.eventPage))
	mux.HandleFunc("POST /calendar/event", s.authed(s.eventSubmit))
	mux.HandleFunc("POST /calendar/rsvp", s.authed(s.rsvpSubmit))
	mux.HandleFunc("GET /calendar/export", s.authed(s.calendarExport))
	mux.HandleFunc("POST /calendar/import", s.authed(s.calendarImport))
	mux.HandleFunc("GET /filters", s.authed(s.filtersPage))
	mux.HandleFunc("POST /filters", s.authed(s.filtersSubmit))
	mux.HandleFunc("GET /tasks", s.authed(s.tasksPage))
	mux.HandleFunc("POST /tasks", s.authed(s.tasksSubmit))
	mux.HandleFunc("GET /api/counts", s.authed(s.countsAPI))
	mux.HandleFunc("GET /api/addresses", s.authed(s.addressesAPI))
	return securityHeaders(mux)
}

// securityHeaders sets a strict policy on every response. Pages are served
// with no inline script or style at all, so 'self' is the whole policy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Asset URLs are versioned by content hash, so they never change.
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

// authed wraps a handler that needs a session, and checks the CSRF token on
// every state-changing request.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, *Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		var sess *Session
		if err == nil {
			sess, _ = s.sessions.Get(c.Value)
		}
		if sess == nil {
			if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/mail/") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Your session has ended. Sign in again.", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			// Cap every request body: attachments plus room for the text
			// fields and multipart overhead. Without the cap, a large upload
			// would be buffered before any size check ran.
			limit := int64(s.cfg.MaxUploadMB+2) << 20
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
					// Up to 8 MB of parts stay in memory; the rest spills to temp files.
					// #nosec G120 -- r.Body is wrapped in http.MaxBytesReader just above
					if err := r.ParseMultipartForm(8 << 20); err != nil {
						http.Error(w, "The message is too large to send.", http.StatusRequestEntityTooLarge)
						return
					}
				}
				token = r.PostFormValue("csrf")
			}
			if !sess.CheckCSRF(token) {
				http.Error(w, "This form has expired. Go back, reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		// Settings shape every page (time zone, clock, page size); they
		// are read once per session and cached after that.
		s.prefs(r.Context(), sess)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)), sess)
	}
}

// view is the data every layout page receives.
type view struct {
	Title   string
	Session *Session
	// App is the top-bar section the page belongs to: mail (the default),
	// calendar, contacts or tasks.
	App      string
	Folders  []Folder
	Folder   string
	Query    string
	List     *listState
	Notice   string
	Problem  string
	Page     *Page
	Message  *Message
	Body     *sanitizeResult
	Remote   bool
	Tags     []string
	Thread   []Related
	Compose  *composeView
	Settings *settingsView
	Contacts *contactsView
	Calendar *calendarView
	Tasks    *tasksView
	Filters  *filtersView
	Status   int
	// Loc and Clock24 control how times are shown.
	Loc     *time.Location
	Clock24 bool
	// TZSet is false until the user has a time zone, which tells the page
	// to report the browser's.
	TZSet bool
	// Theme is "light", "dark" or empty for the device's setting.
	Theme string
}

func (s *Server) render(w http.ResponseWriter, name string, status int, v any) {
	if pv, ok := v.(view); ok && pv.Session != nil {
		if pv.Loc == nil {
			pv.Loc = s.loc(pv.Session)
		}
		cached := s.prefsCached(pv.Session)
		pv.Clock24 = cached.Uses24h()
		pv.TZSet = cached.Timezone != ""
		pv.Theme = cached.Theme
		if pv.App == "" {
			pv.App = "mail"
		}
		v = pv
	}
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		s.log.Error("webmail: render", "template", name, "error", err)
		http.Error(w, "Something went wrong showing this page.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// fail renders an error page for err with the right status and wording,
// without leaking internals.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, sess *Session, err error) {
	status, msg := http.StatusBadGateway, "The mail server didn't respond. Try again in a moment."
	switch {
	case errors.Is(err, ErrNotFound):
		status, msg = http.StatusNotFound, "That message or folder no longer exists. It may have been moved or deleted."
	case errors.Is(err, ErrAuthFailed):
		s.sessions.Destroy(sess.ID)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	case errors.Is(err, ErrTooLarge):
		status, msg = http.StatusRequestEntityTooLarge, "This message is too large to show here. Download it instead."
	default:
		s.log.Warn("webmail: request failed", "path", r.URL.Path, "user", sess.User, "error", err)
	}
	s.render(w, "error.html", status, view{Title: "Problem", Session: sess, Problem: msg, Status: status})
}

// renderProblem shows a validation message the user can act on.
func (s *Server) renderProblem(w http.ResponseWriter, r *http.Request, sess *Session, status int, msg string) {
	s.render(w, "error.html", status, view{Title: "Problem", Session: sess, Problem: msg, Status: status})
}

// notices maps the codes redirects carry to their text, so a crafted link
// can't put arbitrary words on the page.
var notices = map[string]string{
	"sent":              "Message sent.",
	"sent-nocopy":       "Message sent, but a copy couldn't be saved to Sent.",
	"saved":             "Draft saved.",
	"deleted":           "Message deleted.",
	"deleted-many":      "Messages deleted.",
	"moved":             "Message moved.",
	"moved-many":        "Messages moved.",
	"archived":          "Message archived.",
	"archived-many":     "Messages archived.",
	"emptied":           "Folder emptied.",
	"loggedout":         "You've signed out.",
	"folder-created":    "Folder created.",
	"folder-renamed":    "Folder renamed.",
	"folder-deleted":    "Folder deleted.",
	"settings-saved":    "Settings saved.",
	"contact-saved":     "Contact saved.",
	"contact-exists":    "That sender is already in your contacts.",
	"contact-deleted":   "Contact deleted.",
	"contacts-imported": "Contacts imported.",
	"event-saved":       "Event saved.",
	"event-deleted":     "Event deleted.",
	"events-imported":   "Events imported.",
	"invites-sent":      "Event saved and invitations sent.",
	"invite-failed":     "Event saved, but the invitations couldn't be sent.",
	"rsvp-sent":         "Your reply was sent and the event is in your calendar.",
	"rsvp-saved":        "The event is in your calendar. The organizer couldn't be told; try again later.",
	"rsvp-updated":      "The attendee's reply was recorded in your calendar.",
	"task-saved":        "Task saved.",
	"task-deleted":      "Task deleted.",
	"filters-saved":     "Filters saved.",
	"vacation-saved":    "Out-of-office reply saved.",
}

// ---- login -----------------------------------------------------------------

type loginView struct {
	Theme   string
	Token   string
	User    string
	Problem string
	Notice  string
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// #nosec G124 -- Secure follows secure_cookies, which defaults to true and is turned off only for plain-HTTP dev stacks
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: *s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if _, ok := s.sessions.Get(c.Value); ok {
			http.Redirect(w, r, "/mail", http.StatusFound)
			return
		}
	}
	s.renderLogin(w, r, http.StatusOK, "", notices[r.URL.Query().Get("n")], "")
}

// renderLogin issues a fresh pre-login token. The login form carries it back
// and must match the cookie (double submit), which stops another site from
// signing a victim in to an account of the attacker's choosing.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, user, notice, problem string) {
	token, err := randomToken(24)
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, preLoginCookie, token, 600)
	s.render(w, "login.html", status, loginView{Theme: themeFromCookie(r), Token: token, User: user, Notice: notice, Problem: problem})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	user := strings.TrimSpace(r.PostFormValue("user"))
	password := r.PostFormValue("password")
	pre, err := r.Cookie(preLoginCookie)
	if err != nil || pre.Value == "" || pre.Value != r.PostFormValue("token") {
		s.renderLogin(w, r, http.StatusForbidden, user, "", "The sign-in form expired. Try again.")
		return
	}
	ip := clientIP(r)
	if !s.limiter.allow(ip) || !s.limiter.allow("user:"+strings.ToLower(user)) {
		s.renderLogin(w, r, http.StatusTooManyRequests, user, "", "Too many sign-in attempts. Wait a few minutes and try again.")
		return
	}
	if user == "" || password == "" {
		s.renderLogin(w, r, http.StatusBadRequest, user, "", "Enter your email address and password.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	store, err := s.dial(ctx, user, password)
	if err != nil {
		if errors.Is(err, ErrAuthFailed) {
			s.log.Info("webmail: login failed", "user", user, "ip", ip)
			s.renderLogin(w, r, http.StatusUnauthorized, user, "", "That email address and password don't match.")
			return
		}
		s.log.Warn("webmail: login could not reach mail server", "error", err)
		s.renderLogin(w, r, http.StatusBadGateway, user, "", "The mail server didn't respond. Try again in a moment.")
		return
	}
	sess, err := s.sessions.Create(user, s.cfg.address(user), password, store)
	if err != nil {
		_ = store.Close()
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	s.limiter.reset("user:" + strings.ToLower(user))
	s.setCookie(w, preLoginCookie, "", -1)
	s.setCookie(w, sessionCookie, sess.ID, 0)
	s.setThemeCookie(w, s.prefs(ctx, sess).Theme)
	s.log.Info("webmail: login", "user", user, "ip", ip)
	http.Redirect(w, r, "/mail", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.sessions.Destroy(sess.ID)
	s.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/login?n=loggedout", http.StatusSeeOther)
}

// loginLimiter is a fixed-window attempt counter per key (IP or user).
type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*limitWindow
}

type limitWindow struct {
	count int
	reset time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, hits: map[string]*limitWindow{}}
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 100000 {
		// Bound memory under a credential-stuffing run from many sources.
		for k, w := range l.hits {
			if now.After(w.reset) {
				delete(l.hits, k)
			}
		}
	}
	w, ok := l.hits[key]
	if !ok || now.After(w.reset) {
		w = &limitWindow{reset: now.Add(l.window)}
		l.hits[key] = w
	}
	w.count++
	return w.count <= l.max
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}
