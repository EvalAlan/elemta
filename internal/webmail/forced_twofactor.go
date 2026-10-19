package webmail

// Required two-step verification. When an account's class of service
// requires it and the account hasn't set it up, signing in to the webmail
// leads through setting it up before any session exists: there is no way
// into the mail without it, and nothing to skip.
//
// The password that passed is kept server-side as a pending login (the
// same store the verification step uses), keyed by a cookie, while the
// user adds the account to an authenticator app. Confirming the first code
// turns verification on, shows the recovery codes once, and starts the
// session.

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
)

const setupCookie = "elemta_wm_2fa_setup"

type forcedSetupView struct {
	Theme, Palette string
	Token          string
	Secret         string // grouped for typing, and posted back to redraw
	QR             template.URL
	RecoveryCodes  []string
	Problem        string
}

func (s *Server) startForcedSetup(w http.ResponseWriter, r *http.Request, user, password, userKey string) {
	token, err := s.pending.put(user, password, s.now())
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	s.limiter.reset(userKey)
	s.setCookie(w, preLoginCookie, "", -1)
	s.setCookie(w, setupCookie, token, int(pendingLoginTTL.Seconds()))
	s.log.Info("webmail: two-step verification required; starting setup", "user", user, "ip", s.clientIP(r))
	http.Redirect(w, r, "/login/setup", http.StatusSeeOther)
}

// forcedPending finds the pending login behind the setup cookie, checking
// the form's copy of the token on a POST so another site can't drive it.
func (s *Server) forcedPending(w http.ResponseWriter, r *http.Request) (pendingLogin, string, bool) {
	c, err := r.Cookie(setupCookie)
	if err != nil || r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("token"))) != 1 {
		s.renderLogin(w, r, http.StatusForbidden, "", "", "The sign-in expired. Sign in again.")
		return pendingLogin{}, "", false
	}
	p, ok := s.pending.get(c.Value, s.now())
	if !ok {
		s.setCookie(w, setupCookie, "", -1)
		s.renderLogin(w, r, http.StatusUnauthorized, "", "", "The sign-in expired. Sign in again.")
		return pendingLogin{}, "", false
	}
	return p, c.Value, true
}

func (s *Server) renderForcedSetup(w http.ResponseWriter, r *http.Request, status int, p pendingLogin, token, secret, problem string) {
	address := s.cfg.address(p.user)
	img, err := qrDataURI(totpURI(totpIssuer(address), address, secret))
	if err != nil {
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	s.render(w, "twofactor_setup.html", status, forcedSetupView{Theme: themeFromCookie(r), Palette: paletteFromCookie(r), Token: token, Secret: groupSecret(secret), QR: img, Problem: problem})
}

func (s *Server) forcedSetupPage(w http.ResponseWriter, r *http.Request) {
	p, token, ok := s.forcedPending(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var out struct{ Secret string }
	err := s.security.call(ctx, http.MethodPost, "/v1/security/totp/begin", p.user, p.password, map[string]string{"issuer": totpIssuer(s.cfg.address(p.user))}, &out)
	if err != nil {
		s.log.Warn("webmail: start required two-step setup", "user", p.user, "error", err)
		s.renderLogin(w, r, http.StatusBadGateway, p.user, "", "Two-step verification couldn't be set up right now. Try again in a moment.")
		return
	}
	s.renderForcedSetup(w, r, http.StatusOK, p, token, out.Secret, "")
}

func (s *Server) forcedSetupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	p, token, ok := s.forcedPending(w, r)
	if !ok {
		return
	}
	secret := strings.ToUpper(strings.ReplaceAll(r.PostFormValue("secret"), " ", ""))
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil || secret == "" || len(secret) > 64 {
		http.Redirect(w, r, "/login/setup", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	err := s.security.call(ctx, http.MethodPost, "/v1/security/totp/confirm", p.user, p.password, map[string]string{"code": strings.TrimSpace(r.PostFormValue("code"))}, &out)
	switch {
	case errors.Is(err, errSecurityCode):
		if !s.pending.fail(token) {
			s.setCookie(w, setupCookie, "", -1)
			s.renderLogin(w, r, http.StatusUnauthorized, p.user, "", "Too many wrong codes. Sign in again.")
			return
		}
		s.renderForcedSetup(w, r, http.StatusUnprocessableEntity, p, token, secret, "That code isn't right. Check that your phone's clock is correct, then enter the current code.")
		return
	case errors.Is(err, errSecurityLimited):
		s.renderForcedSetup(w, r, http.StatusTooManyRequests, p, token, secret, "Too many wrong codes. Wait a few minutes and try again.")
		return
	case err != nil:
		s.log.Warn("webmail: confirm required two-step setup", "user", p.user, "error", err)
		s.renderForcedSetup(w, r, http.StatusBadGateway, p, token, secret, "The code couldn't be checked. Try again in a moment.")
		return
	}
	s.pending.drop(token)
	s.setCookie(w, setupCookie, "", -1)
	s.log.Info("webmail: two-step verification on (required)", "user", p.user, "ip", s.clientIP(r))
	store, err := s.dial(ctx, p.user, p.password)
	if err != nil {
		s.renderLogin(w, r, http.StatusBadGateway, p.user, "", "Two-step verification is on. The mail server didn't respond; sign in again in a moment.")
		return
	}
	if !s.startSession(ctx, w, r, p.user, p.password, store) {
		return
	}
	// The codes are shown once, now, on a page of their own; the session
	// already exists, so "Continue" goes straight to the mail.
	s.render(w, "twofactor_setup.html", http.StatusOK, forcedSetupView{Theme: themeFromCookie(r), Palette: paletteFromCookie(r), RecoveryCodes: out.RecoveryCodes})
}
