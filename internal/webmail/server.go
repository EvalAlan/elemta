package webmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
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
	tmpl     map[string]*template.Template
	log      *slog.Logger
	limiter  *loginLimiter
	now      func() time.Time
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
	sessions, err := NewSessionManager(cfg.sessionTTL())
	if err != nil {
		return nil, err
	}
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, sessions: sessions, dial: dial, submit: submit, tmpl: tmpl,
		log: log, limiter: newLoginLimiter(10, 15*time.Minute), now: time.Now,
	}, nil
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
	mux.HandleFunc("POST /mail/action", s.authed(s.messageAction))
	mux.HandleFunc("GET /compose", s.authed(s.composePage))
	mux.HandleFunc("POST /compose", s.authed(s.composeSubmit))
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
		w.Header().Set("Cache-Control", "public, max-age=3600")
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
			if r.Method == http.MethodGet && (r.URL.Path == "/mail" || r.URL.Path == "/compose") {
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
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)), sess)
	}
}

// view is the data every layout page receives.
type view struct {
	Title   string
	Session *Session
	Folders []Folder
	Folder  string
	Query   string
	Notice  string
	Problem string
	Page    *Page
	Message *Message
	Body    *sanitizeResult
	Remote  bool
	Compose *composeView
	Status  int
}

func (s *Server) render(w http.ResponseWriter, name string, status int, v any) {
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

// notices maps the codes redirects carry to their text, so a crafted link
// can't put arbitrary words on the page.
var notices = map[string]string{
	"sent":        "Message sent.",
	"sent-nocopy": "Message sent, but a copy couldn't be saved to Sent.",
	"saved":       "Draft saved.",
	"deleted":     "Message deleted.",
	"moved":       "Message moved.",
	"loggedout":   "You've signed out.",
}

// ---- login -----------------------------------------------------------------

type loginView struct {
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
	s.renderLogin(w, http.StatusOK, "", notices[r.URL.Query().Get("n")], "")
}

// renderLogin issues a fresh pre-login token. The login form carries it back
// and must match the cookie (double submit), which stops another site from
// signing a victim in to an account of the attacker's choosing.
func (s *Server) renderLogin(w http.ResponseWriter, status int, user, notice, problem string) {
	token, err := randomToken(24)
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, preLoginCookie, token, 600)
	s.render(w, "login.html", status, loginView{Token: token, User: user, Notice: notice, Problem: problem})
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
		s.renderLogin(w, http.StatusForbidden, user, "", "The sign-in form expired. Try again.")
		return
	}
	ip := clientIP(r)
	if !s.limiter.allow(ip) || !s.limiter.allow("user:"+strings.ToLower(user)) {
		s.renderLogin(w, http.StatusTooManyRequests, user, "", "Too many sign-in attempts. Wait a few minutes and try again.")
		return
	}
	if user == "" || password == "" {
		s.renderLogin(w, http.StatusBadRequest, user, "", "Enter your email address and password.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	store, err := s.dial(ctx, user, password)
	if err != nil {
		if errors.Is(err, ErrAuthFailed) {
			s.log.Info("webmail: login failed", "user", user, "ip", ip)
			s.renderLogin(w, http.StatusUnauthorized, user, "", "That email address and password don't match.")
			return
		}
		s.log.Warn("webmail: login could not reach mail server", "error", err)
		s.renderLogin(w, http.StatusBadGateway, user, "", "The mail server didn't respond. Try again in a moment.")
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

// ---- mail ------------------------------------------------------------------

func parseUID(v string) (uint32, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

func (s *Server) maxMessage() int64 { return int64(s.cfg.MaxMessageMB) << 20 }

func (s *Server) mailPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	folder := q.Get("f")
	if folder == "" {
		folder = "INBOX"
	}
	page, _ := strconv.Atoi(q.Get("page"))
	query := strings.TrimSpace(q.Get("q"))
	uid, hasUID := parseUID(q.Get("uid"))
	remote := q.Get("remote") == "1"

	v := view{Title: folder, Session: sess, Folder: folder, Query: query, Notice: notices[q.Get("n")], Remote: remote}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		if hasUID {
			raw, err := st.Raw(r.Context(), folder, uid, s.maxMessage())
			if err != nil {
				return err
			}
			msg, err := parseMessage(raw)
			if err != nil {
				return err
			}
			msg.UID, msg.Folder = uid, folder
			// Opening a message is what marks it read; fetching it peeks.
			if err := st.SetSeen(r.Context(), folder, uid, true); err != nil {
				return err
			}
			msg.Seen = true
			v.Message = msg
			if msg.HTML != "" {
				res := sanitizeHTML(msg.HTML, sanitizeOptions{AllowRemote: remote})
				v.Body = &res
			}
			v.Title = msg.Subject
		}
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		p, err := st.List(r.Context(), folder, query, page, s.cfg.PageSize)
		if err != nil {
			return err
		}
		v.Page = &p
		for _, m := range p.Messages {
			if m.UID == uid && v.Message != nil {
				v.Message.Flagged = m.Flagged
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.render(w, "mail.html", http.StatusOK, v)
}

// loadMessage fetches and parses one message for the body/part handlers.
func (s *Server) loadMessage(r *http.Request, sess *Session) (string, uint32, []byte, error) {
	folder := r.URL.Query().Get("f")
	uid, ok := parseUID(r.URL.Query().Get("uid"))
	if folder == "" || !ok {
		return "", 0, nil, ErrNotFound
	}
	var raw []byte
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		raw, err = st.Raw(r.Context(), folder, uid, s.maxMessage())
		return err
	})
	return folder, uid, raw, err
}

// maxInlineImage caps a cid: image embedded into the body as a data: URI.
const maxInlineImage = 4 << 20

// messageBody serves sanitised message HTML for the reading pane's frame.
//
// It runs under its own CSP: a sandbox with no scripts and a unique origin,
// so even HTML that got past the sanitiser can't reach the webmail's cookies
// or DOM. cid: images are embedded as data: URIs rather than linked, because
// requests from a sandboxed (opaque-origin) frame don't carry the session
// cookie.
func (s *Server) messageBody(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil || msg.HTML == "" {
		http.Error(w, "No HTML body.", http.StatusNotFound)
		return
	}
	remote := r.URL.Query().Get("remote") == "1"
	res := sanitizeHTML(msg.HTML, sanitizeOptions{
		AllowRemote: remote,
		CIDURL: func(cid string) string {
			part, body, err := findPart(raw, 0, cid)
			if err != nil || len(body) > maxInlineImage || !strings.HasPrefix(part.ContentType, "image/") {
				return ""
			}
			return "data:" + part.ContentType + ";base64," + base64.StdEncoding.EncodeToString(body)
		},
	})
	imgSrc := "data:"
	if remote {
		imgSrc = "data: https: http:"
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; img-src "+imgSrc+"; style-src 'unsafe-inline'; font-src data:; frame-ancestors 'self'")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-store")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><base target="_blank"><style>body{margin:0;padding:16px 20px;font:15px/1.6 system-ui,sans-serif;color:#0E1726;word-wrap:break-word}img{max-width:100%%;height:auto}</style></head><body>%s</body></html>`, res.HTML)
}

// messagePart downloads one attachment. It is always served as an
// attachment with nosniff, never rendered inline, so an HTML or SVG
// "attachment" can't run as a page on the webmail's origin.
func (s *Server) messagePart(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	part, body, err := findPart(raw, n, "")
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	name := part.Filename
	if name == "" {
		name = fmt.Sprintf("part-%d", part.Index)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- served as an octet-stream attachment with nosniff, so the browser never renders it
	_, _ = w.Write(body)
}

// messageRaw downloads the message source as .eml.
func (s *Server) messageRaw(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, uid, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fmt.Sprintf("message-%d.eml", uid)}))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- served as a message/rfc822 attachment with nosniff, so the browser never renders it
	_, _ = w.Write(raw)
}

func (s *Server) messageAction(w http.ResponseWriter, r *http.Request, sess *Session) {
	folder := r.PostFormValue("f")
	uid, ok := parseUID(r.PostFormValue("uid"))
	op := r.PostFormValue("op")
	if folder == "" || !ok {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	back := folderURL(folder, 1, "")
	notice := ""
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		switch op {
		case "unread":
			return st.SetSeen(r.Context(), folder, uid, false)
		case "flag":
			back = messageURL(folder, uid, 1, "")
			return st.SetFlagged(r.Context(), folder, uid, true)
		case "unflag":
			back = messageURL(folder, uid, 1, "")
			return st.SetFlagged(r.Context(), folder, uid, false)
		case "delete":
			notice = "deleted"
			return st.Delete(r.Context(), folder, uid)
		case "move":
			dest := r.PostFormValue("dest")
			if dest == "" || dest == folder {
				return nil
			}
			notice = "moved"
			return st.Move(r.Context(), folder, uid, dest)
		case "junk":
			notice = "moved"
			return moveToRole(r.Context(), st, folder, uid, RoleJunk)
		}
		return fmt.Errorf("webmail: unknown action %q", op)
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if notice != "" {
		back += "&n=" + notice
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// moveToRole moves a message to the folder with role, if the account has one.
func moveToRole(ctx context.Context, st Mailstore, folder string, uid uint32, role Role) error {
	folders, err := st.Folders(ctx)
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f.Role == role {
			return st.Move(ctx, folder, uid, f.Name)
		}
	}
	return ErrNotFound
}

// ---- compose ---------------------------------------------------------------

type composeView struct {
	To, Cc, Bcc string
	Subject     string
	Text        string
	InReplyTo   string
	References  string
	Mode        string
	ShowCc      bool
}

func (s *Server) composePage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	cv := &composeView{Mode: q.Get("mode"), To: q.Get("to")}
	v := view{Title: "New message", Session: sess, Folder: q.Get("f"), Compose: cv}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		uid, ok := parseUID(q.Get("uid"))
		if cv.Mode == "" || !ok {
			return nil
		}
		raw, err := st.Raw(r.Context(), q.Get("f"), uid, s.maxMessage())
		if err != nil {
			return err
		}
		orig, err := parseMessage(raw)
		if err != nil {
			return err
		}
		prefillReply(cv, orig, sess.Address)
		return nil
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.render(w, "compose.html", http.StatusOK, v)
}

// prefillReply fills a reply, reply-all or forward from the original.
func prefillReply(cv *composeView, orig *Message, self string) {
	quoted := quoteText(orig)
	switch cv.Mode {
	case "forward":
		cv.Subject = prefixSubject("Fwd: ", orig.Subject)
		cv.Text = "\n\n---------- Forwarded message ----------\nFrom: " + formatList(orig.From) +
			"\nDate: " + orig.Date.Format("Mon, Jan 2, 2006 at 15:04") + "\nSubject: " + orig.Subject +
			"\nTo: " + formatList(orig.To) + "\n\n" + orig.Text
	case "reply", "replyall":
		cv.Subject = prefixSubject("Re: ", orig.Subject)
		to := orig.ReplyTo
		if len(to) == 0 {
			to = orig.From
		}
		cv.To = formatList(to)
		if cv.Mode == "replyall" {
			var cc []Address
			skip := map[string]bool{strings.ToLower(self): true}
			for _, a := range to {
				skip[strings.ToLower(a.Email)] = true
			}
			for _, a := range append(append([]Address{}, orig.To...), orig.Cc...) {
				if !skip[strings.ToLower(a.Email)] {
					skip[strings.ToLower(a.Email)] = true
					cc = append(cc, a)
				}
			}
			cv.Cc = formatList(cc)
			cv.ShowCc = len(cc) > 0
		}
		cv.InReplyTo = orig.MessageID
		cv.References = orig.References
		cv.Text = "\n\nOn " + orig.Date.Format("Mon, Jan 2, 2006 at 15:04") + ", " + formatList(orig.From) + " wrote:\n" + quoted
	}
}

func prefixSubject(prefix, subject string) string {
	if strings.HasPrefix(strings.ToLower(subject), strings.ToLower(prefix)) {
		return subject
	}
	return prefix + subject
}

func quoteText(m *Message) string {
	body := m.Text
	if body == "" && m.HTML != "" {
		body = htmlToText(m.HTML)
	}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = "> " + l
	}
	return strings.Join(lines, "\n")
}

// plainNameRE matches display names that need no quoting in an address field.
var plainNameRE = regexp.MustCompile(`^[\p{L}\p{N} .'-]+$`)

func formatList(list []Address) string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a.Email == "" {
			continue
		}
		switch {
		case a.Name == "":
			out = append(out, a.Email)
		case plainNameRE.MatchString(a.Name):
			out = append(out, a.Name+" <"+a.Email+">")
		default:
			// Quotes, commas or non-ASCII in the name need RFC 5322 quoting
			// or encoding to survive being parsed back from the To field.
			out = append(out, (&mail.Address{Name: a.Name, Address: a.Email}).String())
		}
	}
	return strings.Join(out, ", ")
}

func parseList(field string) ([]Address, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil, nil
	}
	// People separate addresses with semicolons as often as commas.
	list, err := mail.ParseAddressList(strings.ReplaceAll(field, ";", ","))
	if err != nil {
		return nil, err
	}
	out := make([]Address, 0, len(list))
	for _, a := range list {
		out = append(out, Address{Name: a.Name, Email: a.Address})
	}
	return out, nil
}

func (s *Server) composeSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	cv := &composeView{
		To: r.PostFormValue("to"), Cc: r.PostFormValue("cc"), Bcc: r.PostFormValue("bcc"),
		Subject: r.PostFormValue("subject"), Text: r.PostFormValue("body"),
		InReplyTo: r.PostFormValue("in_reply_to"), References: r.PostFormValue("references"),
		Mode: r.PostFormValue("mode"),
	}
	cv.ShowCc = cv.Cc != "" || cv.Bcc != ""
	saveDraft := r.PostFormValue("op") == "save"
	v := view{Title: "New message", Session: sess, Compose: cv}

	again := func(status int, problem string) {
		_ = s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			v.Folders, _ = st.Folders(r.Context())
			return nil
		})
		v.Problem = problem
		s.render(w, "compose.html", status, v)
	}

	d := &Draft{From: Address{Email: sess.Address}, Subject: cv.Subject, Text: cv.Text, InReplyTo: cv.InReplyTo, References: cv.References}
	var err error
	for _, f := range []struct {
		label string
		value string
		dst   *[]Address
	}{{"To", cv.To, &d.To}, {"Cc", cv.Cc, &d.Cc}, {"Bcc", cv.Bcc, &d.Bcc}} {
		if *f.dst, err = parseList(f.value); err != nil {
			again(http.StatusBadRequest, "Check the addresses in "+f.label+". Separate them with commas.")
			return
		}
	}
	if !saveDraft && len(d.Recipients()) == 0 {
		again(http.StatusBadRequest, "Add at least one recipient.")
		return
	}
	if r.MultipartForm != nil {
		total := 0
		for _, fh := range r.MultipartForm.File["attachments"] {
			f, err := fh.Open()
			if err != nil {
				again(http.StatusBadRequest, "An attachment couldn't be read. Attach it again.")
				return
			}
			data, err := io.ReadAll(io.LimitReader(f, int64(s.cfg.MaxUploadMB)<<20+1))
			_ = f.Close()
			total += len(data)
			if err != nil || total > s.cfg.MaxUploadMB<<20 {
				again(http.StatusRequestEntityTooLarge, fmt.Sprintf("Attachments are limited to %d MB in total.", s.cfg.MaxUploadMB))
				return
			}
			d.Attachments = append(d.Attachments, Attachment{Filename: fh.Filename, ContentType: fh.Header.Get("Content-Type"), Data: data})
		}
	}
	raw, err := d.Build(s.now())
	if err != nil {
		s.log.Error("webmail: build message", "error", err)
		again(http.StatusInternalServerError, "The message couldn't be prepared. Try again.")
		return
	}

	if saveDraft {
		err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			return st.Append(r.Context(), RoleDrafts, raw, true, true)
		})
		if err != nil {
			s.log.Warn("webmail: save draft", "user", sess.User, "error", err)
			again(http.StatusBadGateway, "The draft couldn't be saved. Try again.")
			return
		}
		http.Redirect(w, r, folderURL("INBOX", 1, "")+"&n=saved", http.StatusSeeOther)
		return
	}

	pw, err := s.sessions.password(sess)
	if err != nil {
		s.sessions.Destroy(sess.ID)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.submit.Submit(ctx, sess.User, pw, sess.Address, d.Recipients(), raw); err != nil {
		s.log.Warn("webmail: submit", "user", sess.User, "error", err)
		if errors.Is(err, ErrRejected) {
			again(http.StatusBadRequest, "The mail server refused this message: "+strings.TrimPrefix(err.Error(), ErrRejected.Error()+": "))
			return
		}
		again(http.StatusBadGateway, "The message couldn't be sent. It hasn't been lost: try Send again.")
		return
	}
	notice := "sent"
	if err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		return st.Append(r.Context(), RoleSent, raw, true, false)
	}); err != nil {
		s.log.Warn("webmail: save sent copy", "user", sess.User, "error", err)
		notice = "sent-nocopy"
	}
	http.Redirect(w, r, folderURL("INBOX", 1, "")+"&n="+notice, http.StatusSeeOther)
}
