package webmail

// Passkeys, from the browser's side. The mailbox service holds them and checks
// every signature (internal/mailbox/passkey.go). This passes the ceremony to the
// browser and back, and turns a good sign-in into a session.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// passkeySessionPrefix marks a session opened with a passkey, whose stored
// credential is a token rather than the user's password.
const passkeySessionPrefix = "elemta-session." // #nosec G101 -- public credential marker, not a credential

// passkeySite is the host and origin a request came through. A passkey belongs
// to its host. Only localhost may be plain HTTP, as browsers require.
func passkeySite(r *http.Request) (host, origin string) {
	host = strings.ToLower(r.Host)
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	if name == "localhost" {
		return name, "http://" + host
	}
	return name, "https://" + host
}

type passkeyInfo struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Host     string     `json:"host"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// passkeyToken checks the sign-in form's token, which is what stops another
// site starting a sign-in in someone's browser.
func (s *Server) passkeyToken(r *http.Request, token string) bool {
	pre, err := r.Cookie(preLoginCookie)
	return err == nil && pre.Value != "" && pre.Value == token
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !s.passkeyToken(r, in.Token) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "The sign-in form expired. Reload the page."})
		return
	}
	ip := s.clientIP(r)
	if s.security == nil || s.throttled(ip, ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many sign-in attempts. Wait a few minutes and try again."})
		return
	}
	host, origin := passkeySite(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var out json.RawMessage
	if err := s.security.call(ctx, http.MethodPost, "/v1/passkeys/login/begin", "", "", map[string]string{"host": host, "origin": origin}, &out); err != nil {
		s.log.Warn("webmail: passkey sign-in unavailable", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Sign-in is temporarily unavailable. Try again in a moment."})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var in struct {
		Token     string          `json:"token"`
		Challenge string          `json:"challenge"`
		Response  json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !s.passkeyToken(r, in.Token) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "The sign-in form expired. Reload the page."})
		return
	}
	ip := s.clientIP(r)
	if s.security == nil || s.throttled(ip, ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many sign-in attempts. Wait a few minutes and try again."})
		return
	}
	host, origin := passkeySite(r)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var out struct {
		Address string `json:"address"`
		Token   string `json:"token"`
	}
	err := s.security.call(ctx, http.MethodPost, "/v1/passkeys/login/finish", "", "", map[string]any{
		"host": host, "origin": origin, "challenge": in.Challenge, "response": in.Response,
	}, &out)
	if err != nil {
		s.limiter.fail(ip)
		s.log.Info("webmail: passkey sign-in failed", "ip", ip, "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That passkey wasn't accepted here."})
		return
	}
	store, err := s.dial(ctx, out.Address, out.Token)
	if err != nil {
		s.log.Warn("webmail: passkey session couldn't open the mailbox", "user", out.Address, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The mail server didn't respond. Try again in a moment."})
		return
	}
	check, err := s.security.check(ctx, out.Address, out.Token)
	if err != nil || !check.allows("webmail") {
		_ = store.Close()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Webmail is turned off for this account. Ask your administrator."})
		return
	}
	if !s.startSession(ctx, w, r, out.Address, out.Token, store) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"next": "/mail"})
}

// passkeyAvailable is whether this session can manage passkeys.
func (s *Server) passkeyAvailable(sess *Session) bool {
	return s.security != nil && sess.AdminActor == ""
}

func (s *Server) passkeysFor(ctx context.Context, sess *Session) []passkeyInfo {
	if !s.passkeyAvailable(sess) {
		return nil
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return nil
	}
	var out []passkeyInfo
	if err := s.security.call(ctx, http.MethodGet, "/v1/security/passkeys", sess.User, pw, nil, &out); err != nil {
		s.log.Warn("webmail: passkeys unavailable", "user", sess.User, "error", err)
		return nil
	}
	return out
}

func (s *Server) passkeyAddBegin(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.passkeyAvailable(sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Passkeys can't be changed here."})
		return
	}
	host, origin := passkeySite(r)
	var out json.RawMessage
	err := s.securityCall(r, sess, "/v1/security/passkeys/begin", map[string]string{"password": r.PostFormValue("password"), "host": host, "origin": origin}, &out)
	switch {
	case errors.Is(err, errSecurityAuth):
		ip := s.clientIP(r)
		s.limiter.fail(loginKey(sess.User, ip))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That password isn't right."})
	case err != nil:
		s.log.Warn("webmail: start adding a passkey", "user", sess.User, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The passkey couldn't be added right now."})
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) passkeyAddFinish(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.passkeyAvailable(sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Passkeys can't be changed here."})
		return
	}
	host, origin := passkeySite(r)
	err := s.securityCall(r, sess, "/v1/security/passkeys/finish", map[string]any{
		"challenge": r.PostFormValue("challenge"), "name": r.PostFormValue("name"), "host": host, "origin": origin,
		"response": json.RawMessage(r.PostFormValue("response")),
	}, nil)
	if err != nil {
		s.log.Warn("webmail: add a passkey", "user", sess.User, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The passkey couldn't be added. Give it a name and try again."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"next": "/settings/security?n=passkey-added#passkeys"})
}

func (s *Server) passkeyDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil || !s.passkeyAvailable(sess) {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	if err := s.securityCall(r, sess, "/v1/security/passkeys/"+strconv.FormatInt(id, 10)+"/delete", map[string]string{}, nil); err != nil {
		s.log.Warn("webmail: remove a passkey", "user", sess.User, "error", err)
		// Removing the one this session signed in with ends the session.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/security?n=passkey-removed#passkeys", http.StatusSeeOther)
}

// endPasskeySession tells the mailbox a passkey session is over, so its token
// stops working now and not when it lapses.
func (s *Server) endPasskeySession(ctx context.Context, sess *Session) {
	pw, err := s.sessions.password(sess)
	if err != nil || s.security == nil || !strings.HasPrefix(pw, passkeySessionPrefix) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.security.call(ctx, http.MethodPost, "/v1/security/session/end", sess.User, pw, map[string]string{}, nil); err != nil {
		s.log.Warn("webmail: end passkey session", "user", sess.User, "error", err)
	}
}
