package webmail

// Two-step verification and app passwords. The mailbox service stores and
// checks both (internal/mailbox/security.go); the webmail calls its internal
// API with the signed-in user's own credentials, adds the second step to
// sign-in, and gives users the settings to manage them.
//
// A sign-in that passes the password but still needs a code gets no
// session. It is held as a pending login for five minutes, with the
// password in memory only, the way a session holds it. A session is created
// only once the code checks out, so nothing that needs a session is
// reachable halfway through.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

const (
	twoFactorCookie   = "elemta_wm_2fa"
	pendingLoginTTL   = 5 * time.Minute
	maxPendingAttempt = 5
)

var (
	errSecurityAuth    = errors.New("security: credentials refused")
	errSecurityCode    = errors.New("security: wrong code")
	errSecurityLimited = errors.New("security: too many attempts")
	errSecurityInput   = errors.New("security: request refused")
)

type securityClient struct {
	base   string
	client *http.Client
}

func newSecurityClient(base string) *securityClient {
	return &securityClient{base: strings.TrimSuffix(base, "/"), client: &http.Client{Timeout: 10 * time.Second}}
}

type securityCheck struct {
	Kind        string `json:"kind"` // "password" or "app"
	TOTP        bool   `json:"totp"`
	AppRequired bool   `json:"app_required"`
}

type appPassword struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used"`
}

type securityStatus struct {
	TOTP         bool          `json:"totp"`
	AppRequired  bool          `json:"app_required"`
	RecoveryLeft int           `json:"recovery_left"`
	AppPasswords []appPassword `json:"app_passwords"`
}

func (c *securityClient) call(ctx context.Context, method, path, user, password string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	// #nosec G704 -- base is the operator's security_url and path is one of this file's constant routes
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, password)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req) // #nosec G704 -- request built above from operator configuration only
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errSecurityAuth
	case http.StatusUnprocessableEntity:
		return errSecurityCode
	case http.StatusTooManyRequests:
		return errSecurityLimited
	case http.StatusBadRequest, http.StatusNotFound:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("%w: %s", errSecurityInput, strings.TrimSpace(string(msg)))
	default:
		return fmt.Errorf("security: mailbox service returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out)
}

func (c *securityClient) check(ctx context.Context, user, password string) (securityCheck, error) {
	var out securityCheck
	err := c.call(ctx, http.MethodPost, "/v1/security/check", user, password, nil, &out)
	return out, err
}

// pendingLogin is a password that passed, waiting for its second step.
type pendingLogin struct {
	user, password string
	expires        time.Time
	attempts       int
}

type pendingLogins struct {
	mu sync.Mutex
	m  map[string]*pendingLogin
}

func (p *pendingLogins) put(user, password string, now time.Time) (string, error) {
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*pendingLogin{}
	}
	for k, v := range p.m {
		if now.After(v.expires) {
			delete(p.m, k)
		}
	}
	p.m[token] = &pendingLogin{user: user, password: password, expires: now.Add(pendingLoginTTL)}
	return token, nil
}

// get returns a copy, so callers never hold a pointer the map may drop.
func (p *pendingLogins) get(token string, now time.Time) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[token]
	if !ok || now.After(v.expires) {
		delete(p.m, token)
		return pendingLogin{}, false
	}
	return *v, true
}

// fail counts a wrong code and reports whether the pending login survives.
func (p *pendingLogins) fail(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[token]
	if !ok {
		return false
	}
	v.attempts++
	if v.attempts >= maxPendingAttempt {
		delete(p.m, token)
		return false
	}
	return true
}

func (p *pendingLogins) drop(token string) {
	p.mu.Lock()
	delete(p.m, token)
	p.mu.Unlock()
}

type twoFactorView struct {
	Theme, Palette string
	Token          string
	Problem        string
}

func (s *Server) twoFactorPage(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(twoFactorCookie)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if _, ok := s.pending.get(c.Value, s.now()); !ok {
		s.setCookie(w, twoFactorCookie, "", -1)
		s.renderLogin(w, r, http.StatusUnauthorized, "", "", "The sign-in expired. Sign in again.")
		return
	}
	s.render(w, "twofactor.html", http.StatusOK, twoFactorView{Theme: themeFromCookie(r), Palette: paletteFromCookie(r), Token: c.Value})
}

func (s *Server) twoFactorSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	c, err := r.Cookie(twoFactorCookie)
	// The token is in the cookie and the form both, so another site can't
	// submit codes into someone's pending sign-in.
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("token"))) != 1 {
		s.renderLogin(w, r, http.StatusForbidden, "", "", "The sign-in form expired. Sign in again.")
		return
	}
	p, ok := s.pending.get(c.Value, s.now())
	if !ok {
		s.setCookie(w, twoFactorCookie, "", -1)
		s.renderLogin(w, r, http.StatusUnauthorized, "", "", "The sign-in expired. Sign in again.")
		return
	}
	retry := func(status int, problem string) {
		s.render(w, "twofactor.html", status, twoFactorView{Theme: themeFromCookie(r), Palette: paletteFromCookie(r), Token: c.Value, Problem: problem})
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" {
		retry(http.StatusBadRequest, "Enter the code from your authenticator app.")
		return
	}
	ip := s.clientIP(r)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var out struct {
		Recovery     bool `json:"recovery"`
		RecoveryLeft int  `json:"recovery_left"`
	}
	err = s.security.call(ctx, http.MethodPost, "/v1/security/verify", p.user, p.password, map[string]string{"code": code}, &out)
	switch {
	case errors.Is(err, errSecurityCode):
		s.limiter.fail(ip)
		s.log.Info("webmail: wrong verification code", "user", p.user, "ip", ip)
		if !s.pending.fail(c.Value) {
			s.setCookie(w, twoFactorCookie, "", -1)
			s.renderLogin(w, r, http.StatusUnauthorized, p.user, "", "Too many wrong codes. Sign in again.")
			return
		}
		retry(http.StatusUnauthorized, "That code isn't right. Codes change every 30 seconds; use the current one.")
		return
	case errors.Is(err, errSecurityLimited):
		retry(http.StatusTooManyRequests, "Too many wrong codes. Wait a few minutes and try again.")
		return
	case err != nil:
		s.log.Warn("webmail: verification unavailable", "user", p.user, "error", err)
		retry(http.StatusBadGateway, "The code couldn't be checked. Try again in a moment.")
		return
	}
	s.pending.drop(c.Value)
	s.setCookie(w, twoFactorCookie, "", -1)
	store, err := s.dial(ctx, p.user, p.password)
	if err != nil {
		s.log.Warn("webmail: login after verification", "user", p.user, "error", err)
		s.renderLogin(w, r, http.StatusBadGateway, p.user, "", "The mail server didn't respond. Try again in a moment.")
		return
	}
	next := "/mail"
	if out.Recovery {
		s.log.Info("webmail: recovery code used", "user", p.user, "left", out.RecoveryLeft)
		next = "/settings/security?n=recovery-code-used#two-step"
	}
	s.finishLogin(ctx, w, r, p.user, p.password, store, next)
}

// securityView is the Security part of the settings page. The one-time
// fields are filled only on the response that creates them, and never put
// in a URL.
type securityView struct {
	Status      *securityStatus
	Unavailable bool
	// Setup is set while a new authenticator is being added.
	SetupSecret string
	SetupQR     template.URL
	// RecoveryCodes are shown once, when two-step verification is turned on.
	RecoveryCodes []string
	// NewAppPassword is shown once, when it is created.
	NewAppName, NewAppPassword string
	Problem                    string
}

// securityRender re-renders the settings page with the security card's
// one-time state, or a problem.
func (s *Server) securityRender(w http.ResponseWriter, r *http.Request, sess *Session, status int, sv securityView) {
	v, err := s.settingsView(r, sess, "security")
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if v.Settings.Security != nil {
		sv.Status = v.Settings.Security.Status
		sv.Unavailable = v.Settings.Security.Unavailable
	}
	v.Settings.Security = &sv
	s.render(w, "settings.html", status, v)
}

func (s *Server) securityStatusFor(ctx context.Context, sess *Session) (*securityStatus, error) {
	password, err := s.sessions.password(sess)
	if err != nil {
		return nil, err
	}
	var st securityStatus
	if err := s.security.call(ctx, http.MethodGet, "/v1/security", sess.User, password, nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// securityAction runs one settings change against the mailbox service as
// the signed-in user, rendering any failure.
func (s *Server) securityAction(w http.ResponseWriter, r *http.Request, sess *Session, path string, in, out any) bool {
	err := s.securityCall(r, sess, path, in, out)
	if err != nil {
		s.securityFailed(w, r, sess, path, err)
	}
	return err == nil
}

var errSecurityOff = errors.New("security: not configured")

func (s *Server) securityCall(r *http.Request, sess *Session, path string, in, out any) error {
	if s.security == nil {
		return errSecurityOff
	}
	password, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	return s.security.call(ctx, http.MethodPost, path, sess.User, password, in, out)
}

func (s *Server) securityFailed(w http.ResponseWriter, r *http.Request, sess *Session, path string, err error) {
	switch {
	case errors.Is(err, errSecurityOff):
		s.renderProblem(w, r, sess, http.StatusNotFound, "Account security settings aren't available here.")
	case errors.Is(err, errSecurityCode):
		s.securityRender(w, r, sess, http.StatusUnprocessableEntity, securityView{Problem: "That code isn't right. Use the current code from your authenticator app."})
	case errors.Is(err, errSecurityLimited):
		s.securityRender(w, r, sess, http.StatusTooManyRequests, securityView{Problem: "Too many wrong codes. Wait a few minutes and try again."})
	case errors.Is(err, errSecurityAuth):
		// The session's password no longer works: changed elsewhere.
		s.sessions.Destroy(sess.ID)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.Is(err, errSecurityInput):
		msg := strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":"))
		s.securityRender(w, r, sess, http.StatusBadRequest, securityView{Problem: capitalize(msg) + "."})
	default:
		s.log.Warn("webmail: security settings", "user", sess.User, "path", path, "error", err)
		s.securityRender(w, r, sess, http.StatusBadGateway, securityView{Problem: "The change couldn't be made. Try again in a moment."})
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// qrDataURI renders an otpauth URI as a PNG for the authenticator app to scan.
func qrDataURI(text string) (template.URL, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	code.Scale = 6
	// #nosec G203 -- a PNG this server just encoded, in a data: URI the page CSP allows for images
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())), nil
}

// totpIssuer names the account in authenticator apps.
func totpIssuer(address string) string {
	if _, domain, ok := strings.Cut(address, "@"); ok {
		return "Elemta Mail (" + domain + ")"
	}
	return "Elemta Mail"
}

// totpURI is the otpauth URI apps scan (Key Uri Format).
func totpURI(issuer, address, secret string) string {
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+address) + "?" + q.Encode()
}

func (s *Server) totpBeginSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	var out struct{ Secret string }
	if !s.securityAction(w, r, sess, "/v1/security/totp/begin", map[string]string{"issuer": totpIssuer(sess.Address)}, &out) {
		return
	}
	s.renderTOTPSetup(w, r, sess, http.StatusOK, out.Secret, "")
}

func (s *Server) renderTOTPSetup(w http.ResponseWriter, r *http.Request, sess *Session, status int, secret, problem string) {
	img, err := qrDataURI(totpURI(totpIssuer(sess.Address), sess.Address, secret))
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.securityRender(w, r, sess, status, securityView{SetupSecret: groupSecret(secret), SetupQR: img, Problem: problem})
}

// groupSecret spaces the secret in fours for typing it in by hand.
func groupSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Server) totpConfirmSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	err := s.securityCall(r, sess, "/v1/security/totp/confirm", map[string]string{"code": strings.TrimSpace(r.PostFormValue("code"))}, &out)
	if errors.Is(err, errSecurityCode) {
		// Show the same secret again so the user can retry without adding
		// the account to their app a second time. The form returns the
		// secret only to redraw it; confirmation checks the copy the
		// mailbox service holds.
		secret := strings.ToUpper(strings.ReplaceAll(r.PostFormValue("secret"), " ", ""))
		if _, decodeErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); decodeErr != nil || len(secret) > 64 {
			s.securityRender(w, r, sess, http.StatusUnprocessableEntity, securityView{Problem: "That code isn't right. Start the setup again."})
			return
		}
		s.renderTOTPSetup(w, r, sess, http.StatusUnprocessableEntity, secret, "That code isn't right. Check that your phone's clock is correct, then enter the current code.")
		return
	}
	if err != nil {
		s.securityFailed(w, r, sess, "/v1/security/totp/confirm", err)
		return
	}
	s.log.Info("webmail: two-step verification on", "user", sess.User, "ip", s.clientIP(r))
	s.securityRender(w, r, sess, http.StatusOK, securityView{RecoveryCodes: out.RecoveryCodes})
}

func (s *Server) totpDisableSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.securityAction(w, r, sess, "/v1/security/totp/disable", map[string]string{"code": strings.TrimSpace(r.PostFormValue("code"))}, nil) {
		return
	}
	s.log.Info("webmail: two-step verification off", "user", sess.User, "ip", s.clientIP(r))
	http.Redirect(w, r, "/settings/security?n=2fa-off#two-step", http.StatusSeeOther)
}

func (s *Server) appPasswordSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	var out struct {
		AppPassword appPassword `json:"app_password"`
		Password    string      `json:"password"`
	}
	if !s.securityAction(w, r, sess, "/v1/security/app-passwords", map[string]string{"name": r.PostFormValue("name")}, &out) {
		return
	}
	s.log.Info("webmail: app password created", "user", sess.User, "name", out.AppPassword.Name)
	s.securityRender(w, r, sess, http.StatusOK, securityView{NewAppName: out.AppPassword.Name, NewAppPassword: out.Password})
}

func (s *Server) appPasswordDeleteSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "That app password wasn't found.")
		return
	}
	if !s.securityAction(w, r, sess, "/v1/security/app-passwords/"+strconv.FormatInt(id, 10)+"/delete", nil, nil) {
		return
	}
	http.Redirect(w, r, "/settings/security?n=app-password-deleted#app-passwords", http.StatusSeeOther)
}

func (s *Server) appRequiredSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	required := r.PostFormValue("required") == "1"
	if !s.securityAction(w, r, sess, "/v1/security/app-required", map[string]bool{"required": required}, nil) {
		return
	}
	n := "app-optional"
	if required {
		n = "app-required"
	}
	http.Redirect(w, r, "/settings/security?n="+n+"#app-passwords", http.StatusSeeOther)
}
