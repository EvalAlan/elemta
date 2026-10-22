package webmail

import (
	"bytes"
	"context"
	"database/sql"
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

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

const (
	sessionCookie  = "elemta_wm"
	preLoginCookie = "elemta_wm_pre"
)

// Server is the webmail HTTP application.
type Server struct {
	objectDB *sql.DB
	cfg      Config
	sessions *SessionManager
	dial     Dialer
	submit   Submitter
	// sieve reaches the ManageSieve server for filters; nil when none is
	// configured, which hides the feature.
	sieve SieveDialer
	// passwords changes users' passwords; nil hides the feature.
	passwords PasswordChanger
	// mailSettings reads and changes a user's forwarding and send-as
	// addresses in the directory (mailsettings.go); nil hides them.
	mailSettings MailSettings
	recovery     RecoveryStore
	recoveryMail chan struct{}
	resetter     PasswordResetter
	watch        MailWatcher
	pushMu       sync.Mutex
	pushStreams  map[string]int
	push         pushHub
	pages        pageCache
	tmpl         map[string]*template.Template
	log          *slog.Logger
	limiter      *loginLimiter
	now          func() time.Time
	// dav keeps the mail connections of CalDAV and CardDAV clients.
	dav *davPool
	// security reaches the mailbox service's account-security API; nil
	// when none is configured (security.go).
	security *securityClient
	pending  pendingLogins
	freeBusy freeBusyPublisher
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
	var passwords PasswordChanger
	var mailSettings MailSettings
	if cfg.LDAPURL != "" {
		pw := cfg.LDAPSearchPassword
		if env := os.Getenv("ELEMTA_WEBMAIL_LDAP_SEARCH_PASSWORD"); env != "" {
			pw = env
		}
		l := ldapPasswords{url: cfg.LDAPURL, base: cfg.LDAPBase, filter: cfg.LDAPUserFilter, searchDN: cfg.LDAPSearchDN, searchPassword: pw, insecureSkipVerify: cfg.InsecureSkipVerify}
		passwords, mailSettings = l, l
	}
	server := &Server{
		passwords: passwords, mailSettings: mailSettings, recoveryMail: make(chan struct{}, 4),
		cfg: cfg, sessions: sessions, dial: dial, submit: submit, tmpl: tmpl, sieve: sieve,
		log: log, limiter: newLoginLimiter(15 * time.Minute), now: time.Now, dav: newDAVPool(),
		defaultLoc: cfg.location(),
	}
	if v, ok := sessions.shared.(*valkeySessions); ok {
		server.pending.shared = v
		server.pending.aead = sessions.aead
	}
	if cfg.RecoveryURL != "" {
		if envOr("ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD", cfg.LDAPResetPassword) == "" || envOr("ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD", cfg.RecoverySMTPPassword) == "" {
			return nil, errors.New("webmail: recovery requires LDAP reset and SMTP service passwords")
		}
		if !validRecoveryEmail(cfg.RecoverySender, "") {
			return nil, errors.New("webmail: recovery_sender must be an email address")
		}
		v, ok := sessions.shared.(*valkeySessions)
		if !ok {
			return nil, errors.New("webmail: recovery requires Valkey")
		}
		server.recovery = valkeyRecovery{client: v.client}
		server.resetter = ldapPasswords{url: cfg.LDAPURL, base: cfg.LDAPBase, filter: cfg.LDAPUserFilter, searchDN: cfg.LDAPResetDN, searchPassword: envOr("ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD", cfg.LDAPResetPassword), insecureSkipVerify: cfg.InsecureSkipVerify}
	}
	if u := envOr("ELEMTA_WEBMAIL_SECURITY_URL", cfg.SecurityURL); u != "" {
		server.security = newSecurityClient(u)
	}
	if cfg.ObjectStore == "postgres" {
		if server.security == nil {
			return nil, errors.New("webmail: postgres object store requires security_url for immutable account identity")
		}
		dsn := envOr("ELEMTA_WEBMAIL_OBJECT_POSTGRES_DSN", cfg.ObjectPostgresDSN)
		if dsn == "" {
			return nil, errors.New("webmail: postgres object store needs object_postgres_dsn or ELEMTA_WEBMAIL_OBJECT_POSTGRES_DSN")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, errors.New("webmail: invalid object database configuration")
		}
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := initObjectSchema(ctx, db); err != nil {
			_ = db.Close()
			return nil, errors.New("webmail: could not initialize object database")
		}
		server.objectDB = db
		server.dial = postgresObjectDialer(db, server.security, dial)
	} else {
		coord := &objectCoordinator{}
		if v, ok := sessions.shared.(*valkeySessions); ok {
			coord.valkey = v
		}
		server.dial = coordinatedObjectDialer(coord, server.security, dial)
	}
	return server, nil
}

// Close releases the shared object pool after HTTP requests have drained.
func (s *Server) Close() error {
	if s.objectDB != nil {
		return s.objectDB.Close()
	}
	return nil
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
	// Pages link the SVG icon, but some browsers still ask for /favicon.ico.
	mux.Handle("GET /favicon.ico", http.RedirectHandler(assetURL("favicon.svg"), http.StatusMovedPermanently))
	mux.HandleFunc("GET /forgot-password", s.forgotPage)
	mux.HandleFunc("POST /forgot-password", s.forgotSubmit)
	mux.HandleFunc("GET /reset-password", s.resetPage)
	mux.HandleFunc("POST /reset-password", s.resetSubmit)
	mux.HandleFunc("GET /verify-recovery", s.verifyPage)
	mux.HandleFunc("POST /verify-recovery", s.verifySubmit)
	mux.HandleFunc("POST /settings/recovery", s.authed(s.recoverySubmit))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /login/admin", s.adminLoginSubmit)
	mux.HandleFunc("GET /login/verify", s.twoFactorPage)
	mux.HandleFunc("POST /login/verify", s.twoFactorSubmit)
	mux.HandleFunc("GET /login/setup", s.forcedSetupPage)
	mux.HandleFunc("POST /login/setup", s.forcedSetupSubmit)
	mux.HandleFunc("POST /settings/2fa/begin", s.authed(s.totpBeginSubmit))
	mux.HandleFunc("POST /settings/2fa/confirm", s.authed(s.totpConfirmSubmit))
	mux.HandleFunc("POST /settings/2fa/disable", s.authed(s.totpDisableSubmit))
	mux.HandleFunc("POST /settings/app-passwords", s.authed(s.appPasswordSubmit))
	mux.HandleFunc("POST /settings/app-passwords/delete", s.authed(s.appPasswordDeleteSubmit))
	mux.HandleFunc("POST /settings/app-required", s.authed(s.appRequiredSubmit))
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/mail", http.StatusFound) })
	mux.HandleFunc("GET /mail", s.authed(s.mailPage))
	mux.HandleFunc("GET /mail/body", s.authed(s.messageBody))
	mux.HandleFunc("GET /mail/part", s.authed(s.messagePart))
	mux.HandleFunc("GET /mail/raw", s.authed(s.messageRaw))
	mux.HandleFunc("GET /mail/print", s.authed(s.messagePrint))
	mux.HandleFunc("GET /mail/source", s.authed(s.messageSource))
	mux.HandleFunc("GET /api/reminders", s.authed(s.remindersAPI))
	mux.HandleFunc("POST /mail/action", s.authed(s.messageAction))
	mux.HandleFunc("POST /mail/switch", s.authed(s.switchMailbox))
	mux.HandleFunc("GET /compose", s.authed(s.composePage))
	mux.HandleFunc("POST /compose", s.authed(s.composeSubmit))
	mux.HandleFunc("GET /folders", s.authed(s.foldersPage))
	mux.HandleFunc("POST /folders", s.authed(s.foldersSubmit))
	mux.HandleFunc("GET /settings", s.authed(s.settingsPage))
	mux.HandleFunc("GET /settings/account", s.authed(s.settingsTab("account")))
	mux.HandleFunc("GET /settings/security", s.authed(s.settingsTab("security")))
	mux.HandleFunc("GET /settings/devices", s.authed(s.settingsTab("devices")))
	mux.HandleFunc("POST /settings", s.authed(s.settingsSubmit))
	mux.HandleFunc("POST /settings/timezone", s.authed(s.timezoneSubmit))
	mux.HandleFunc("POST /settings/theme", s.authed(s.themeSubmit))
	mux.HandleFunc("POST /settings/conversations", s.authed(s.conversationsSubmit))
	mux.HandleFunc("POST /settings/mail-calendar", s.authed(s.mailCalendarSubmit))
	mux.HandleFunc("POST /settings/password", s.authed(s.passwordSubmit))
	mux.HandleFunc("POST /settings/forwarding", s.authed(s.forwardingSubmit))
	mux.HandleFunc("POST /settings/senders", s.authed(s.sendersSubmit))
	mux.HandleFunc("GET /contacts", s.authed(s.contactsPage))
	mux.HandleFunc("POST /contacts", s.authed(s.contactsSubmit))
	mux.HandleFunc("GET /contacts/export", s.authed(s.contactsExport))
	mux.HandleFunc("POST /contacts/import", s.authed(s.contactsImport))
	mux.HandleFunc("GET /calendar", s.authed(s.calendarPage))
	mux.HandleFunc("GET /calendar/event", s.authed(s.eventPage))
	mux.HandleFunc("POST /calendar/event", s.authed(s.eventSubmit))
	mux.HandleFunc("POST /calendar/holiday/hide", s.authed(s.holidayHide))
	mux.HandleFunc("POST /calendar/rsvp", s.authed(s.rsvpSubmit))
	mux.HandleFunc("GET /calendar/export", s.authed(s.calendarExport))
	mux.HandleFunc("POST /calendar/import", s.authed(s.calendarImport))
	mux.HandleFunc("GET /filters", s.authed(s.filtersPage))
	mux.HandleFunc("POST /filters", s.authed(s.filtersSubmit))
	mux.HandleFunc("GET /tasks", s.authed(s.tasksPage))
	mux.HandleFunc("POST /tasks", s.authed(s.tasksSubmit))
	mux.HandleFunc("GET /api/events", s.authed(s.mailEvents))
	mux.HandleFunc("GET /api/counts", s.authed(s.countsAPI))
	mux.HandleFunc("GET /api/addresses", s.authed(s.addressesAPI))
	mux.HandleFunc("GET /api/freebusy", s.authed(s.freeBusyAPI))
	// Calendar and contact sync for phones and desktop clients. Clients
	// look for the well-known paths first (RFC 6764).
	mux.Handle("/dav/", s.davHandler())
	mux.Handle("/dav", s.davHandler())
	mux.Handle("/.well-known/caldav", http.RedirectHandler(davRoot, http.StatusMovedPermanently))
	mux.Handle("/.well-known/carddav", http.RedirectHandler(davRoot, http.StatusMovedPermanently))
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
		if sess.AdminActor != "" && !adminMailRoute(r.URL.Path) {
			http.Error(w, "This administrator session opens mail only.", http.StatusForbidden)
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

func adminMailRoute(path string) bool {
	return path == "/mail" || (strings.HasPrefix(path, "/mail/") && path != "/mail/switch") || path == "/folders" ||
		path == "/logout" || path == "/settings/theme" || path == "/api/counts" || path == "/api/events"
}

// view is the data every layout page receives.
type view struct {
	Title   string
	Session *Session
	// App is the top-bar section the page belongs to: mail (the default),
	// calendar, contacts or tasks.
	App             string
	Folders         []Folder
	SharedMailboxes []sharedMailbox
	ActiveMailbox   string
	Folder          string
	Query           string
	List            *listState
	Notice          string
	Problem         string
	Page            *Page
	Message         *Message
	Body            *sanitizeResult
	Remote          bool
	Tags            []string
	Thread          []Related
	// Conversations is the threaded list, when the list is grouped.
	Conversations []Conversation
	Threaded      bool
	// ThreadBefore and ThreadAfter are the open message's conversation,
	// split around it by date.
	ThreadBefore []Related
	ThreadAfter  []Related
	Source       string
	Compose      *composeView
	Settings     *settingsView
	Contacts     *contactsView
	Calendar     *calendarView
	Tasks        *tasksView
	Filters      *filtersView
	Status       int
	// Loc and Clock24 control how times are shown.
	Loc     *time.Location
	Clock24 bool
	// TZSet is false until the user has a time zone, which tells the page
	// to report the browser's.
	TZSet bool
	// Theme is "light", "dark" or empty for the device's setting.
	Theme string
	// Palette is the colour scheme, empty for the default.
	Palette string
	// SettingsTab is the settings section shown, for the settings
	// sidebar: general, account, security, devices, filters or folders.
	SettingsTab string
}

func (s *Server) render(w http.ResponseWriter, name string, status int, v any) {
	if pv, ok := v.(view); ok && pv.Session != nil {
		pv.ActiveMailbox = s.sessions.SelectedMailbox(pv.Session)
		if pv.Loc == nil {
			pv.Loc = s.loc(pv.Session)
		}
		cached := s.prefsCached(pv.Session)
		pv.Clock24 = cached.Uses24h()
		pv.TZSet = cached.Timezone != ""
		pv.Theme = cached.Theme
		pv.Palette = cached.Palette
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
	"sent":                 "Message sent.",
	"sent-nocopy":          "Message sent, but a copy couldn't be saved to Sent.",
	"saved":                "Draft saved.",
	"deleted":              "Message deleted.",
	"deleted-many":         "Messages deleted.",
	"moved":                "Message moved.",
	"moved-many":           "Messages moved.",
	"archived":             "Message archived.",
	"archived-many":        "Messages archived.",
	"emptied":              "Folder emptied.",
	"all-read":             "All messages marked read.",
	"loggedout":            "You've signed out.",
	"recovery-code-used":   "You signed in with a recovery code, which can't be used again. If you've lost your authenticator, turn two-step verification off and on again to get new codes.",
	"2fa-off":              "Two-step verification is off.",
	"app-password-deleted": "App password deleted. Apps using it will be asked for a new one.",
	"app-required":         "Mail apps now need an app password; your account password works only in webmail.",
	"app-optional":         "Mail apps can use your account password again.",
	"folder-created":       "Folder created.",
	"folder-renamed":       "Folder renamed.",
	"folder-deleted":       "Folder deleted.",
	"settings-saved":       "Settings saved.",
	"password-reset":       "Your password was reset. Sign in with your new password.",
	"recovery-sent":        "A verification link was sent to your recovery address.",
	"recovery-verified":    "Your recovery email is verified.",
	"recovery-removed":     "Your recovery email was removed.",
	"password-changed":     "Your password was changed. Use the new one everywhere you read mail.",
	"forwarding-saved":     "Forwarding saved.",
	"senders-saved":        "Allowed and blocked senders saved.",
	"senders-failed":       "Allowed and blocked senders couldn't be saved. Try again later.",
	"forwarding-failed":    "Forwarding couldn't be saved. Try again, or ask your administrator.",
	"contact-saved":        "Contact saved.",
	"contact-exists":       "That sender is already in your contacts.",
	"contact-deleted":      "Contact deleted.",
	"contacts-imported":    "Contacts imported.",
	"event-saved":          "Event saved.",
	"event-deleted":        "Event deleted.",
	"events-imported":      "Events imported.",
	"invites-sent":         "Event saved and invitations sent.",
	"invite-failed":        "Event saved, but the invitations couldn't be sent.",
	"rsvp-sent":            "Your reply was sent and the event is in your calendar.",
	"rsvp-saved":           "The event is in your calendar. The organizer couldn't be told; try again later.",
	"rsvp-updated":         "The attendee's reply was recorded in your calendar.",
	"task-saved":           "Task saved.",
	"task-deleted":         "Task deleted.",
	"filters-saved":        "Filters saved.",
	"vacation-saved":       "Out-of-office reply saved.",
}

// ---- login -----------------------------------------------------------------

type loginView struct {
	Recovery bool
	Theme    string
	Palette  string
	Token    string
	User     string
	Problem  string
	Notice   string
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
	s.render(w, "login.html", status, loginView{Recovery: s.recovery != nil, Theme: themeFromCookie(r), Palette: paletteFromCookie(r), Token: token, User: user, Notice: notice, Problem: problem})
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIP is the address a request came from. Behind a trusted proxy it
// is the right-most X-Forwarded-For address that isn't itself a trusted
// proxy: entries further left were written by the client and can't be
// believed.
func (s *Server) clientIP(r *http.Request) string {
	ip := remoteHost(r)
	if !s.trusted(ip) {
		return ip
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if net.ParseIP(hop) == nil {
			break
		}
		if !s.trusted(hop) {
			return hop
		}
	}
	return ip
}

func (s *Server) trusted(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, p := range s.cfg.TrustedProxies {
		if _, n, err := net.ParseCIDR(p); err == nil && n.Contains(addr) {
			return true
		}
		if t := net.ParseIP(p); t != nil && t.Equal(addr) {
			return true
		}
	}
	return false
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
	ip := s.clientIP(r)
	userKey := "user:" + strings.ToLower(user)
	if s.limiter.blocked(ip, maxFailuresPerIP) || s.limiter.blocked(userKey, maxFailuresPerUser) {
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
			s.limiter.fail(ip)
			s.limiter.fail(userKey)
			s.log.Info("webmail: login failed", "user", user, "ip", ip)
			s.renderLogin(w, r, http.StatusUnauthorized, user, "", "That email address and password don't match.")
			return
		}
		if errors.Is(err, ErrLoginRefused) {
			s.log.Warn("webmail: login refused by mail server", "user", user, "error", err)
			s.renderLogin(w, r, http.StatusServiceUnavailable, user, "", "The mail server is limiting connections for this account. Sign out of other sessions or wait a minute, then try again.")
			return
		}
		s.log.Warn("webmail: login could not reach mail server", "error", err)
		s.renderLogin(w, r, http.StatusBadGateway, user, "", "The mail server didn't respond. Try again in a moment.")
		return
	}
	if s.security != nil {
		check, err := s.security.check(ctx, user, password)
		if err != nil {
			// Without the answer, whether a second step is needed is
			// unknown, so the sign-in stops rather than skipping it.
			_ = store.Close()
			s.log.Warn("webmail: account security check unavailable", "user", user, "error", err)
			s.renderLogin(w, r, http.StatusBadGateway, user, "", "Sign-in is temporarily unavailable. Try again in a moment.")
			return
		}
		if check.Kind == "app" {
			// App passwords are for mail apps; the webmail would otherwise
			// be a way around the second step.
			_ = store.Close()
			s.limiter.fail(userKey)
			s.renderLogin(w, r, http.StatusUnauthorized, user, "", "That's an app password. Sign in to webmail with your account password.")
			return
		}
		if !check.allows(mailpolicy.Webmail) {
			_ = store.Close()
			s.log.Info("webmail: sign-in refused by class of service", "user", user, "ip", ip)
			s.renderLogin(w, r, http.StatusForbidden, user, "", "Webmail is turned off for this account. Ask your administrator if you need it.")
			return
		}
		if check.Kind == "admin" {
			if check.Administrator == "" || !check.Expires.After(s.now()) {
				_ = store.Close()
				s.renderLogin(w, r, http.StatusUnauthorized, user, "", "Administrator access has expired.")
				return
			}
			s.limiter.reset(userKey)
			if s.startSessionWithAccess(ctx, w, r, user, password, store, check.Administrator, check.Expires) {
				http.Redirect(w, r, "/mail", http.StatusSeeOther)
			}
			return
		}
		if !check.TOTP && check.RequireTwoFactor {
			// The class requires two-step verification and this account
			// hasn't set it up: that happens now, before any session exists.
			_ = store.Close()
			s.startForcedSetup(w, r, user, password, userKey)
			return
		}
		if check.TOTP {
			_ = store.Close()
			token, err := s.pending.put(user, password, s.now())
			if err != nil {
				http.Error(w, "Something went wrong.", http.StatusInternalServerError)
				return
			}
			s.limiter.reset(userKey)
			s.setCookie(w, preLoginCookie, "", -1)
			s.setCookie(w, twoFactorCookie, token, int(pendingLoginTTL.Seconds()))
			http.Redirect(w, r, "/login/verify", http.StatusSeeOther)
			return
		}
	}
	s.limiter.reset(userKey)
	s.finishLogin(ctx, w, r, user, password, store, "/mail")
}

// adminLoginSubmit accepts the short-lived token carried in a POST from the
// dashboard. The token never enters a URL, browser history or referrer.
func (s *Server) adminLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.security == nil {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Administrator access requires the mail dashboard.", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	user := strings.TrimSpace(r.PostFormValue("user"))
	token := r.PostFormValue("token")
	if user == "" || token == "" {
		http.Error(w, "Missing administrator access token.", http.StatusBadRequest)
		return
	}
	ip := s.clientIP(r)
	userKey := "user:" + strings.ToLower(user)
	if s.limiter.blocked(ip, maxFailuresPerIP) || s.limiter.blocked(userKey, maxFailuresPerUser) {
		http.Error(w, "Too many sign-in attempts.", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	store, err := s.dial(ctx, user, token)
	if err != nil {
		if errors.Is(err, ErrAuthFailed) {
			s.limiter.fail(ip)
			s.limiter.fail(userKey)
			http.Error(w, "Administrator access was refused.", http.StatusUnauthorized)
			return
		}
		s.log.Warn("webmail: administrator access could not reach mail server", "error", err)
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusBadGateway)
		return
	}
	check, err := s.security.check(ctx, user, token)
	if err != nil || check.Kind != "admin" || check.Administrator == "" || !check.Expires.After(s.now()) {
		_ = store.Close()
		s.limiter.fail(userKey)
		http.Error(w, "Administrator access was refused.", http.StatusUnauthorized)
		return
	}
	if !check.allows(mailpolicy.Webmail) {
		_ = store.Close()
		http.Error(w, "Webmail is turned off for this account.", http.StatusForbidden)
		return
	}
	s.limiter.reset(userKey)
	if s.startSessionWithAccess(ctx, w, r, user, token, store, check.Administrator, check.Expires) {
		http.Redirect(w, r, "/mail", http.StatusSeeOther)
	}
}

// finishLogin turns a verified sign-in into a session.
func (s *Server) finishLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, user, password string, store Mailstore, next string) {
	if s.startSession(ctx, w, r, user, password, store) {
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
}

// startSession creates the session and its cookies, or writes an error and
// reports false.
func (s *Server) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user, password string, store Mailstore) bool {
	return s.startSessionWithAccess(ctx, w, r, user, password, store, "", time.Time{})
}

func (s *Server) startSessionWithAccess(ctx context.Context, w http.ResponseWriter, r *http.Request, user, password string, store Mailstore, actor string, expires time.Time) bool {
	// Every account gets the standard folders, so Junk and Trash are there
	// to move mail to from the first sign-in. A failure here only means
	// they're created later, when first needed.
	if err := store.EnsureFolders(ctx, defaultFolderRoles); err != nil {
		s.log.Warn("webmail: create default folders", "user", user, "error", err)
	}
	var sess *Session
	var err error
	if actor != "" {
		sess, err = s.sessions.CreateAdmin(user, s.cfg.address(user), password, store, actor, expires)
	} else {
		sess, err = s.sessions.Create(user, s.cfg.address(user), password, store)
	}
	if err != nil {
		_ = store.Close()
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return false
	}
	s.setCookie(w, preLoginCookie, "", -1)
	s.setCookie(w, sessionCookie, sess.ID, 0)
	s.setAppearanceCookies(w, s.prefs(ctx, sess))
	s.log.Info("webmail: login", "user", user, "ip", s.clientIP(r))
	// Catch calendar changes made elsewhere (another mail app over IMAP,
	// or before free/busy existed).
	if actor == "" {
		s.publishFreeBusyAtSignIn(user, password, sess.Address)
	}
	return true
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.sessions.Destroy(sess.ID)
	s.pages.forget(sess.ID)
	s.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/login?n=loggedout", http.StatusSeeOther)
}

// Sign-in throttling counts failed attempts only. Successful sign-ins never
// count: behind Docker's port publishing, a NAT or a proxy, many people
// reach the webmail from one address, and counting every attempt let
// ordinary use lock everyone out. A password-guessing run fails, so it is
// still stopped: per account after a few tries, and per address after
// more, allowing for a shared address.
const (
	maxFailuresPerUser = 10
	maxFailuresPerIP   = 50
)

// loginLimiter counts failures per key (an address or an account) in fixed
// windows.
type loginLimiter struct {
	mu     sync.Mutex
	window time.Duration
	hits   map[string]*limitWindow
}

type limitWindow struct {
	count int
	reset time.Time
}

func newLoginLimiter(window time.Duration) *loginLimiter {
	return &loginLimiter{window: window, hits: map[string]*limitWindow{}}
}

// blocked reports whether key has reached max failures in its window.
func (l *loginLimiter) blocked(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.hits[key]
	return ok && time.Now().Before(w.reset) && w.count >= max
}

// fail records a failed attempt for key.
func (l *loginLimiter) fail(key string) {
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
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}
