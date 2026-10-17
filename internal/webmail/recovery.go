package webmail

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"
)

const recoveryTTL = 15 * time.Minute
const recoveryNotice = "If this account has a verified recovery address, a reset link has been sent."

type recoveryAddress struct{ Email, Version string }
type recoveryToken struct{ User, Address, Email, Version, Purpose string }
type recoveryView struct {
	Theme, CSRF, Token, Title, Action, Notice, Problem string
	Reset                                              bool
	Min                                                int
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func (s *Server) recoveryAccount(user string) string {
	return strings.ToLower(s.cfg.address(strings.TrimSpace(user)))
}

func (s *Server) recoveryRecord(ctx context.Context, address string) (recoveryAddress, error) {
	raw, err := s.recovery.Get(ctx, "address:"+accountKey(address))
	if err != nil || raw == "" {
		return recoveryAddress{}, err
	}
	var rec recoveryAddress
	err = json.Unmarshal([]byte(raw), &rec)
	return rec, err
}
func (s *Server) saveRecovery(ctx context.Context, address string, rec recoveryAddress) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.recovery.Put(ctx, "address:"+accountKey(address), string(raw), 0)
}
func (s *Server) issueRecovery(ctx context.Context, rec recoveryToken) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	if err = s.recovery.Put(ctx, tokenKey(token), string(raw), recoveryTTL); err != nil {
		return "", err
	}
	return token, nil
}
func (s *Server) sendRecovery(ctx context.Context, to, token, purpose string) error {
	path, title := "/reset-password", "Reset your Elemta password"
	if purpose == "verify" {
		path, title = "/verify-recovery", "Verify your recovery email"
	}
	link := strings.TrimRight(s.cfg.RecoveryURL, "/") + path + "?token=" + url.QueryEscape(token)
	draft := Draft{From: Address{Email: s.cfg.RecoverySender}, To: []Address{{Email: to}}, Subject: title, Text: "Open this link to continue:\n\n" + link + "\n\nThis link expires in 15 minutes and can be used once. If you did not request it, ignore this email.\n"}
	raw, err := draft.Build(s.now())
	if err != nil {
		return err
	}
	return s.submit.Submit(ctx, s.cfg.RecoverySMTPUser, envOr("ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD", s.cfg.RecoverySMTPPassword), s.cfg.RecoverySender, []string{to}, raw)
}
func (s *Server) renderRecovery(w http.ResponseWriter, r *http.Request, status int, v recoveryView) {
	csrf, err := randomToken(24)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.setCookie(w, preLoginCookie, csrf, 600)
	v.CSRF = csrf
	v.Theme = themeFromCookie(r)
	v.Min = s.cfg.MinPasswordLength
	s.render(w, "recovery.html", status, v)
}
func (s *Server) recoveryForm(w http.ResponseWriter, r *http.Request) bool {
	if s.recovery == nil || s.resetter == nil {
		http.NotFound(w, r)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	pre, err := r.Cookie(preLoginCookie)
	if err != nil || pre.Value == "" || subtle.ConstantTimeCompare([]byte(pre.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		http.Error(w, "This form has expired. Reload and try again.", http.StatusForbidden)
		return false
	}
	return true
}
func (s *Server) forgotPage(w http.ResponseWriter, r *http.Request) {
	if s.recovery == nil {
		http.NotFound(w, r)
		return
	}
	s.renderRecovery(w, r, http.StatusOK, recoveryView{Title: "Forgot password", Action: "/forgot-password"})
}
func (s *Server) forgotSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.recoveryForm(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	user := s.recoveryAccount(r.PostFormValue("user"))
	// Shared cooldowns prevent one browser or pod from bypassing the limits.
	ipOK, ipErr := s.recovery.Claim(ctx, "request-ip:"+accountKey(clientIP(r)), "1", time.Minute)
	userOK, userErr := s.recovery.Claim(ctx, "request-user:"+accountKey(user), "1", time.Minute)
	if ipErr != nil || userErr != nil {
		s.log.Error("webmail: recovery rate limit unavailable")
		http.Error(w, "Try again later.", http.StatusServiceUnavailable)
		return
	}
	if ipOK && userOK {
		rec, err := s.recoveryRecord(ctx, user)
		if err == nil && rec.Email != "" {
			s.sendResetLink(user, rec)
		}

	}
	s.renderRecovery(w, r, http.StatusOK, recoveryView{Title: "Check your recovery email", Notice: recoveryNotice})
}

func validRecoveryEmail(value, account string) bool {
	a, err := mail.ParseAddress(value)
	return err == nil && a.Address == value && strings.Contains(value, "@") && len(value) <= 254 && !strings.EqualFold(value, account) && !strings.ContainsAny(value, "\r\n")
}
func (s *Server) recoverySubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.recovery == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	current := r.PostFormValue("current")
	key := "recovery-auth:" + strings.ToLower(sess.User)
	if s.limiter.blocked(key, maxFailuresPerUser) {
		http.Error(w, "Try again later.", http.StatusTooManyRequests)
		return
	}
	if s.passwords == nil {
		http.Error(w, "Password verification unavailable.", http.StatusServiceUnavailable)
		return
	}
	// Verify against IMAP without changing the password or trusting a session
	// that may have been left open on a shared computer.
	if current == "" {
		http.Error(w, "Enter your current password.", http.StatusBadRequest)
		return
	}
	st, err := s.dial(ctx, sess.User, current)
	if err != nil {
		s.limiter.fail(key)
		http.Error(w, "Your current password could not be verified.", http.StatusForbidden)
		return
	}
	_ = st.Close()
	address := s.recoveryAccount(sess.User)
	email := strings.TrimSpace(r.PostFormValue("email"))
	version, err := randomToken(24)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	unlock, err := s.lockRecovery(ctx, address)
	if err != nil {
		http.Error(w, "Try again later.", http.StatusServiceUnavailable)
		return
	}
	defer unlock()
	if email == "" {
		if _, err = s.recovery.Take(ctx, "pending:"+accountKey(address)); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		if err = s.saveRecovery(ctx, address, recoveryAddress{Version: version}); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		http.Redirect(w, r, "/settings?n=recovery-removed", http.StatusSeeOther)
		return
	}
	if !validRecoveryEmail(email, address) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Enter a different email address that you can access.")
		return
	}
	ok, err := s.recovery.Claim(ctx, "enroll:"+accountKey(address), "1", time.Minute)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if !ok {
		http.Error(w, "Wait a minute before requesting another link.", http.StatusTooManyRequests)
		return
	}
	// A pending version lets a newer request supersede older verification links
	// without disabling the previously verified recovery address.
	if err = s.recovery.Put(ctx, "pending:"+accountKey(address), version, recoveryTTL); err != nil {
		s.fail(w, r, sess, err)
		return
	}
	token, err := s.issueRecovery(ctx, recoveryToken{User: sess.User, Address: address, Email: email, Version: version, Purpose: "verify"})
	if err == nil {
		err = s.sendRecovery(ctx, email, token, "verify")
	}
	if err != nil {
		s.log.Error("webmail: recovery verification delivery failed")
		s.renderProblem(w, r, sess, http.StatusBadGateway, "The verification email could not be sent. Try again later.")
		return
	}
	http.Redirect(w, r, "/settings?n=recovery-sent", http.StatusSeeOther)
}
func (s *Server) resetPage(w http.ResponseWriter, r *http.Request)  { s.tokenPage(w, r, "reset") }
func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request) { s.tokenPage(w, r, "verify") }
func (s *Server) tokenPage(w http.ResponseWriter, r *http.Request, purpose string) {
	if s.recovery == nil {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if len(token) != 43 {
		http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
		return
	}
	// GET never consumes a token: email security scanners follow links.
	title, action := "Choose a new password", "/reset-password"
	if purpose == "verify" {
		title, action = "Verify recovery email", "/verify-recovery"
	}
	s.renderRecovery(w, r, http.StatusOK, recoveryView{Title: title, Action: action, Token: token, Reset: purpose == "reset"})
}
func (s *Server) verifySubmit(w http.ResponseWriter, r *http.Request) { s.useRecovery(w, r, "verify") }
func (s *Server) resetSubmit(w http.ResponseWriter, r *http.Request)  { s.useRecovery(w, r, "reset") }
func (s *Server) useRecovery(w http.ResponseWriter, r *http.Request, purpose string) {
	if !s.recoveryForm(w, r) {
		return
	}
	token := r.PostFormValue("token")
	if len(token) != 43 {
		http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	raw, err := s.recovery.Get(ctx, tokenKey(token))
	var rec recoveryToken
	if err != nil {
		http.Error(w, "Try again later.", http.StatusServiceUnavailable)
		return
	}
	if raw == "" || json.Unmarshal([]byte(raw), &rec) != nil || rec.Purpose != purpose {
		http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
		return
	}
	if purpose == "reset" {
		if problem := checkNewPassword(rec.User, "", r.PostFormValue("new"), r.PostFormValue("confirm"), s.cfg.MinPasswordLength); problem != "" {
			s.renderRecovery(w, r, http.StatusBadRequest, recoveryView{Title: "Choose a new password", Action: "/reset-password", Token: token, Reset: true, Problem: problem})
			return
		}
	}
	// Serialize enrollment and resets for this account across instances.
	unlock, err := s.lockRecovery(ctx, rec.Address)
	if err != nil {
		http.Error(w, "Try again later.", http.StatusServiceUnavailable)
		return
	}
	defer unlock()
	if purpose == "verify" {
		pending, e := s.recovery.Get(ctx, "pending:"+accountKey(rec.Address))
		if e != nil || pending != rec.Version {
			http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
			return
		}
	} else {
		address, e := s.recoveryRecord(ctx, rec.Address)
		if e != nil || address.Version != rec.Version || address.Email != rec.Email {
			http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
			return
		}
	}
	consumed, err := s.recovery.Take(ctx, tokenKey(token))
	if err != nil || consumed == "" {
		http.Error(w, "This link is invalid or has expired.", http.StatusBadRequest)
		return
	}
	version, err := randomToken(24)
	if err != nil {
		http.Error(w, "Try again later.", http.StatusServiceUnavailable)
		return
	}
	// Rotate before modifying the directory: even a later store failure must
	// not leave other links capable of resetting the newly chosen password.
	err = s.saveRecovery(ctx, rec.Address, recoveryAddress{Email: rec.Email, Version: version})
	if err == nil {
		_, err = s.recovery.Take(ctx, "pending:"+accountKey(rec.Address))
	}
	if err == nil && purpose == "reset" {
		err = s.performReset(ctx, rec.User, r.PostFormValue("new"))
	}

	if err != nil {
		if errors.Is(err, errPolicyRejected) {
			http.Error(w, "The directory refused that password. Request a new link and choose a stronger password.", http.StatusBadRequest)
			return
		}
		s.log.Error("webmail: recovery operation failed")
		http.Error(w, "This request could not be completed. Request a new link or contact your administrator.", http.StatusBadGateway)
		return
	}
	notice := "recovery-verified"
	if purpose == "reset" {
		notice = "password-reset"
	}
	http.Redirect(w, r, "/login?n="+notice, http.StatusSeeOther)
}

func (s *Server) performReset(ctx context.Context, user, next string) error {
	if s.resetter == nil {
		return errors.New("webmail: password reset is not configured")
	}
	// Invalidate first, so a store outage cannot leave old webmail sessions
	// authorized after the directory password has already changed.
	if err := s.sessions.RevokeUser(ctx, s.recoveryAccount(user)); err != nil {
		return err
	}
	if err := s.resetter.ResetPassword(ctx, s.recoveryAccount(user), next); err != nil {
		return err
	}
	if err := s.sessions.RevokeUser(ctx, s.recoveryAccount(user)); err != nil {
		return err
	}
	s.log.Info("webmail: password reset", "user", s.recoveryAccount(user))
	return nil
}

// AdminResetPassword is for the local administrator command, never a public
// route. OS access and the privileged directory credentials authorize it.
func (s *Server) AdminResetPassword(ctx context.Context, user, next string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if problem := checkNewPassword(user, "", next, next, s.cfg.MinPasswordLength); problem != "" {
		return errors.New(problem)
	}
	if s.resetter == nil {
		if s.cfg.LDAPURL == "" || s.cfg.LDAPResetDN == "" {
			return errors.New("webmail: configure ldap_url and ldap_reset_dn for administrator resets")
		}
		s.resetter = ldapPasswords{url: s.cfg.LDAPURL, base: s.cfg.LDAPBase, filter: s.cfg.LDAPUserFilter, searchDN: s.cfg.LDAPResetDN, searchPassword: envOr("ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD", s.cfg.LDAPResetPassword), insecureSkipVerify: s.cfg.InsecureSkipVerify}
	}
	if s.recovery == nil {
		if v, ok := s.sessions.shared.(*valkeySessions); ok {
			s.recovery = valkeyRecovery{client: v.client}
		}
	}
	if s.recovery != nil {
		address := s.recoveryAccount(user)
		unlock, err := s.lockRecovery(ctx, address)
		if err != nil {
			return err
		}
		defer unlock()
		rec, err := s.recoveryRecord(ctx, address)
		if err != nil {
			return err
		}
		rec.Version, err = randomToken(24)
		if err != nil {
			return err
		}
		if err = s.saveRecovery(ctx, address, rec); err != nil {
			return err
		}
		if _, err = s.recovery.Take(ctx, "pending:"+accountKey(address)); err != nil {
			return err
		}
	}
	if err := s.performReset(ctx, user, next); err != nil {
		return fmt.Errorf("webmail: administrator reset: %w", err)
	}

	return nil
}

func (s *Server) lockRecovery(ctx context.Context, address string) (func(), error) {
	key := "lock:" + accountKey(address)
	ok, err := s.recovery.Claim(ctx, key, "1", 2*time.Minute)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("webmail: recovery request already in progress")
	}
	return func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.recovery.Take(c, key)
	}, nil
}

// SMTP latency must not reveal whether the submitted account has a recovery
// address. Bound background delivery so a public endpoint cannot exhaust it.
func (s *Server) sendResetLink(user string, rec recoveryAddress) {
	select {
	case s.recoveryMail <- struct{}{}:
	default:
		s.log.Error("webmail: recovery delivery busy")
		return
	}
	go func() {
		defer func() { <-s.recoveryMail }()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		token, err := s.issueRecovery(ctx, recoveryToken{User: user, Address: user, Email: rec.Email, Version: rec.Version, Purpose: "reset"})
		if err == nil {
			err = s.sendRecovery(ctx, rec.Email, token, "reset")
		}
		if err != nil {
			s.log.Error("webmail: recovery delivery failed")
		}
	}()
}
