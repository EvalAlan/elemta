package api

// Two-step sign-in for the console (internal/adminmfa).
//
// A user with an authenticator app or a passkey signs in with their password
// and then one of them; a passkey alone also signs in, since it checks a
// fingerprint or PIN itself. Between the two steps the user holds a short,
// single-use token, not a session: nothing is reachable with the password
// alone. Basic auth, a password on every request, can't carry a second step,
// so it is refused for these users; scripts use API keys.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/adminmfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"rsc.io/qr"
)

const (
	// pendingLoginLife is how long the second step may take.
	pendingLoginLife = 5 * time.Minute
	// pendingLoginTries is how many wrong codes end a pending sign-in, on
	// top of the address's own failure count.
	pendingLoginTries = 5
	ceremonyLife      = 5 * time.Minute
	maxCeremonies     = 1000
)

var errSecondFactor = errors.New("this account uses two-step sign-in; sign in through the console, or use an API key")

// mfaFlow holds what lives between steps: sign-ins waiting for their
// second factor, and passkey ceremonies waiting for the browser. They are
// in this process's memory, like the second-factor file is on its disk.
type mfaFlow struct {
	mu         sync.Mutex
	pending    map[string]*pendingLogin
	ceremonies map[string]*ceremony
}

type pendingLogin struct {
	user    string
	addr    string
	expires time.Time
	tries   int
}

type ceremony struct {
	kind    string // "login", "second", "add"
	user    string
	session webauthn.SessionData
	expires time.Time
}

func newMFAFlow() *mfaFlow {
	return &mfaFlow{pending: map[string]*pendingLogin{}, ceremonies: map[string]*ceremony{}}
}

func flowToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (f *mfaFlow) sweep(now time.Time) {
	for k, p := range f.pending {
		if now.After(p.expires) {
			delete(f.pending, k)
		}
	}
	for k, c := range f.ceremonies {
		if now.After(c.expires) {
			delete(f.ceremonies, k)
		}
	}
}

func (f *mfaFlow) startPending(user, addr string) (string, error) {
	token, err := flowToken()
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep(time.Now())
	if len(f.pending) >= maxCeremonies {
		return "", errors.New("too many sign-ins waiting")
	}
	f.pending[token] = &pendingLogin{user: user, addr: addr, expires: time.Now().Add(pendingLoginLife)}
	return token, nil
}

// pendingUser is the user a token is for, if it is still good and comes
// from the address that gave the password.
func (f *mfaFlow) pendingUser(token, addr string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pending[token]
	if p == nil || time.Now().After(p.expires) || p.addr != addr {
		return "", false
	}
	return p.user, true
}

// failPending counts a wrong second factor, and ends the sign-in after too
// many.
func (f *mfaFlow) failPending(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.pending[token]; p != nil {
		p.tries++
		if p.tries >= pendingLoginTries {
			delete(f.pending, token)
		}
	}
}

func (f *mfaFlow) endPending(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pending, token)
}

func (f *mfaFlow) startCeremony(kind, user string, session *webauthn.SessionData) (string, error) {
	id, err := flowToken()
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep(time.Now())
	if len(f.ceremonies) >= maxCeremonies {
		return "", errors.New("too many passkey requests waiting")
	}
	f.ceremonies[id] = &ceremony{kind: kind, user: user, session: *session, expires: time.Now().Add(ceremonyLife)}
	return id, nil
}

// takeCeremony removes a ceremony as it reads it: each is good once.
func (f *mfaFlow) takeCeremony(id, kind, user string) (webauthn.SessionData, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.ceremonies[id]
	delete(f.ceremonies, id)
	if c == nil || c.kind != kind || c.user != user || time.Now().After(c.expires) {
		return webauthn.SessionData{}, false
	}
	return c.session, true
}

// consoleSite is the host and origin the console was reached at, which a
// passkey belongs to. Only localhost may be plain HTTP, as browsers require.
func consoleSite(r *http.Request) (host, origin string) {
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

func (s *Server) mfaRoutes(r *mux.Router) {
	if s.mfa == nil {
		return
	}
	r.HandleFunc("/auth/login/code", s.handleLoginCode).Methods("POST")
	r.HandleFunc("/auth/login/passkey/begin", s.handleLoginPasskeyBegin).Methods("POST")
	r.HandleFunc("/auth/login/passkey/finish", s.handleLoginPasskeyFinish).Methods("POST")
	sec := r.PathPrefix("/auth/security").Subrouter()
	sec.Use(s.authMiddleware.RequireAuth)
	sec.HandleFunc("", s.handleSecurityStatus).Methods("GET")
	sec.HandleFunc("/totp/begin", s.handleTOTPBegin).Methods("POST")
	sec.HandleFunc("/totp/confirm", s.handleTOTPConfirm).Methods("POST")
	sec.HandleFunc("/totp/disable", s.handleTOTPDisable).Methods("POST")
	sec.HandleFunc("/recovery", s.handleRecoveryCodes).Methods("POST")
	sec.HandleFunc("/passkeys/begin", s.handlePasskeyAddBegin).Methods("POST")
	sec.HandleFunc("/passkeys/finish", s.handlePasskeyAddFinish).Methods("POST")
	sec.HandleFunc("/passkeys/{id}/delete", s.handlePasskeyDelete).Methods("POST")
}

// signInGate refuses a sign-in step from an address that is denied, blocked
// or throttled, as the password step does.
func (s *Server) signInGate(w http.ResponseWriter, r *http.Request, user string) (string, bool) {
	addr := s.loginAddr(r)
	if _, denied := s.abuse.DenyPeer(addr, abuse.ProtocolAdmin); denied {
		http.Error(w, "Refused by policy", http.StatusForbidden)
		return "", false
	}
	if b, blocked := s.abuse.Blocked(addr); blocked {
		writeThrottled(w, time.Until(b.Until))
		return "", false
	}
	if wait := s.loginThrottle.retryAfter(addr, user); wait > 0 {
		writeThrottled(w, wait)
		return "", false
	}
	return addr, true
}

func (s *Server) signInFailed(r *http.Request, addr, user, why string) {
	s.loginThrottle.recordFailure(addr, user)
	s.abuse.Failure(r.Context(), addr, "admin", user)
	slog.Warn("Failed login", "username", sanitizeForLog(user), "remote", addr, "step", why)
}

// secondStep answers a correct password for a user with a second factor:
// no session yet, a token for the next step. It reports whether it
// answered.
func (s *Server) secondStep(w http.ResponseWriter, user, addr string) bool {
	if s.mfa == nil {
		return false
	}
	st, err := s.mfa.Status(user)
	if err != nil {
		// Unreadable is not "none": signing in on the password alone would
		// skip the second step for everyone.
		slog.Error("Two-step sign-in settings unreadable", "error", err)
		http.Error(w, "Sign-in is unavailable; check the console's log", http.StatusServiceUnavailable)
		return true
	}
	if !st.On() {
		return false
	}
	token, err := s.mfaFlow.startPending(user, addr)
	if err != nil {
		http.Error(w, "Sign-in is busy; try again shortly", http.StatusServiceUnavailable)
		return true
	}
	writeJSON(w, map[string]any{"status": "second_factor", "token": token, "methods": st.Methods()})
	return true
}

func (s *Server) handleLoginCode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) {
		return
	}
	addr := s.loginAddr(r)
	user, ok := s.mfaFlow.pendingUser(in.Token, addr)
	if !ok {
		http.Error(w, "The sign-in timed out; start again", http.StatusUnauthorized)
		return
	}
	if _, ok := s.signInGate(w, r, user); !ok {
		return
	}
	recovery, err := s.mfa.VerifyCode(user, in.Code, time.Now())
	if err != nil {
		if !errors.Is(err, adminmfa.ErrWrongCode) {
			slog.Error("Two-step sign-in failed", "error", err)
			http.Error(w, "Sign-in is unavailable; check the console's log", http.StatusServiceUnavailable)
			return
		}
		s.mfaFlow.failPending(in.Token)
		s.signInFailed(r, addr, user, "code")
		http.Error(w, "That code isn't right", http.StatusUnauthorized)
		return
	}
	s.mfaFlow.endPending(in.Token)
	if recovery {
		s.provisionAudit(r, "dashboard-user-recovery-code-used", user, "")
	}
	s.completeLogin(w, r, user, addr)
}

func (s *Server) handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) {
		return
	}
	addr, ok := s.signInGate(w, r, "")
	if !ok {
		return
	}
	user, kind := "", "login"
	if in.Token != "" {
		if user, ok = s.mfaFlow.pendingUser(in.Token, addr); !ok {
			http.Error(w, "The sign-in timed out; start again", http.StatusUnauthorized)
			return
		}
		kind = "second"
	}
	host, origin := consoleSite(r)
	assertion, session, err := s.mfa.BeginPasskeyLogin(user, host, origin)
	if err != nil {
		http.Error(w, passkeyMessage(err), http.StatusBadRequest)
		return
	}
	id, err := s.mfaFlow.startCeremony(kind, user, session)
	if err != nil {
		http.Error(w, "Sign-in is busy; try again shortly", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"challenge": id, "options": assertion})
}

func (s *Server) handleLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token     string          `json:"token"`
		Challenge string          `json:"challenge"`
		Response  json.RawMessage `json:"response"`
	}
	if !decodeBoundedJSON(w, r, &in, 64<<10) {
		return
	}
	addr, ok := s.signInGate(w, r, "")
	if !ok {
		return
	}
	user, kind := "", "login"
	if in.Token != "" {
		if user, ok = s.mfaFlow.pendingUser(in.Token, addr); !ok {
			http.Error(w, "The sign-in timed out; start again", http.StatusUnauthorized)
			return
		}
		kind = "second"
	}
	session, ok := s.mfaFlow.takeCeremony(in.Challenge, kind, user)
	if !ok {
		http.Error(w, "The passkey request timed out; try again", http.StatusUnauthorized)
		return
	}
	host, origin := consoleSite(r)
	who, err := s.mfa.FinishPasskeyLogin(user, host, origin, session, in.Response)
	if err != nil {
		if in.Token != "" {
			s.mfaFlow.failPending(in.Token)
		}
		s.signInFailed(r, addr, user, "passkey")
		http.Error(w, passkeyMessage(err), http.StatusUnauthorized)
		return
	}
	// A passkey outlives a user removed from the users file by hand.
	if _, err := s.authSystem.GetUser(r.Context(), who); err != nil {
		s.signInFailed(r, addr, who, "passkey for a removed user")
		http.Error(w, "The passkey wasn't accepted", http.StatusUnauthorized)
		return
	}
	if in.Token != "" {
		s.mfaFlow.endPending(in.Token)
	}
	s.completeLogin(w, r, who, addr)
}

func passkeyMessage(err error) string {
	if errors.Is(err, adminmfa.ErrPasskey) || errors.Is(err, adminmfa.ErrInvalid) {
		msg := err.Error()
		if i := strings.Index(msg, ": "); i >= 0 && (strings.HasPrefix(msg, adminmfa.ErrInvalid.Error()) || strings.HasPrefix(msg, adminmfa.ErrPasskey.Error())) {
			msg = msg[i+2:]
		}
		return capitalize(msg)
	}
	slog.Error("Passkey request failed", "error", err)
	return "The passkey couldn't be used"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---- the signed-in user's own settings ---------------------------------------

// securityUser is the signed-in user, for changing their own sign-in. Only a
// person at the console may: an API key could otherwise turn off its
// owner's second factor.
func (s *Server) securityUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	ac := GetAuthContext(r)
	if ac == nil || ac.IsAPIKey || ac.Username == "" {
		http.Error(w, "Sign in to the console to change how you sign in", http.StatusForbidden)
		return "", false
	}
	return ac.Username, true
}

// confirmPassword checks the user's password again before a change to how
// they sign in, so a session left open can't be used to lock them out or
// keep someone else in.
func (s *Server) confirmPassword(w http.ResponseWriter, r *http.Request, user, password string) bool {
	addr, ok := s.signInGate(w, r, user)
	if !ok {
		return false
	}
	if ok, err := s.authSystem.Authenticate(r.Context(), user, password); err != nil || !ok {
		s.signInFailed(r, addr, user, "password confirmation")
		http.Error(w, "That password isn't right", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	st, err := s.mfa.Status(user)
	if err != nil {
		mfaError(w, err)
		return
	}
	writeJSON(w, st)
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) || !s.confirmPassword(w, r, user, in.Password) {
		return
	}
	host, _ := consoleSite(r)
	secret, uri, err := s.mfa.BeginTOTP(user, "Elemta Admin ("+host+")")
	if err != nil {
		mfaError(w, err)
		return
	}
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		mfaError(w, err)
		return
	}
	code.Scale = 5
	writeJSON(w, map[string]any{
		"secret": groupSecret(secret),
		"uri":    uri,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()),
	})
}

func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) {
		return
	}
	codes, err := s.mfa.ConfirmTOTP(user, in.Code, time.Now())
	if err != nil {
		mfaError(w, err)
		return
	}
	s.provisionAudit(r, "dashboard-user-totp-on", user, "")
	writeJSON(w, map[string]any{"recovery_codes": codes})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) || !s.confirmPassword(w, r, user, in.Password) {
		return
	}
	if err := s.mfa.DisableTOTP(user); err != nil {
		mfaError(w, err)
		return
	}
	s.provisionAudit(r, "dashboard-user-totp-off", user, "")
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) || !s.confirmPassword(w, r, user, in.Password) {
		return
	}
	codes, err := s.mfa.NewRecoveryCodes(user)
	if err != nil {
		mfaError(w, err)
		return
	}
	s.provisionAudit(r, "dashboard-user-recovery-codes", user, "replaced")
	writeJSON(w, map[string]any{"recovery_codes": codes})
}

func (s *Server) handlePasskeyAddBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) || !s.confirmPassword(w, r, user, in.Password) {
		return
	}
	host, origin := consoleSite(r)
	creation, session, err := s.mfa.BeginAddPasskey(user, host, origin)
	if err != nil {
		http.Error(w, passkeyMessage(err), http.StatusBadRequest)
		return
	}
	id, err := s.mfaFlow.startCeremony("add", user, session)
	if err != nil {
		http.Error(w, "Too many passkey requests waiting; try again shortly", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"challenge": id, "options": creation})
}

func (s *Server) handlePasskeyAddFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Challenge string          `json:"challenge"`
		Name      string          `json:"name"`
		Response  json.RawMessage `json:"response"`
	}
	if !decodeBoundedJSON(w, r, &in, 64<<10) {
		return
	}
	session, ok := s.mfaFlow.takeCeremony(in.Challenge, "add", user)
	if !ok {
		http.Error(w, "The passkey request timed out; try again", http.StatusBadRequest)
		return
	}
	host, origin := consoleSite(r)
	info, err := s.mfa.FinishAddPasskey(user, host, origin, in.Name, session, in.Response)
	if err != nil {
		http.Error(w, passkeyMessage(err), http.StatusBadRequest)
		return
	}
	s.provisionAudit(r, "dashboard-user-passkey-add", user, info.Name)
	writeJSON(w, info)
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := s.securityUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		http.Error(w, "No such passkey", http.StatusNotFound)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeBoundedJSON(w, r, &in, 4<<10) || !s.confirmPassword(w, r, user, in.Password) {
		return
	}
	if err := s.mfa.DeletePasskey(user, id); err != nil {
		if errors.Is(err, adminmfa.ErrInvalid) {
			http.Error(w, "No such passkey", http.StatusNotFound)
			return
		}
		mfaError(w, err)
		return
	}
	s.provisionAudit(r, "dashboard-user-passkey-remove", user, strconv.FormatInt(id, 10))
	writeJSON(w, map[string]any{"ok": true})
}

// handleResetSecondFactor clears another user's second factors, for someone
// who lost their phone and recovery codes.
func (s *Server) handleResetSecondFactor(w http.ResponseWriter, r *http.Request) {
	if s.mfa == nil {
		http.Error(w, "Two-step sign-in needs a users file", http.StatusServiceUnavailable)
		return
	}
	name := mux.Vars(r)["username"]
	// Your own goes through your settings, which ask for your password: a
	// session left open mustn't be enough to remove it.
	if ac := GetAuthContext(r); ac == nil || ac.Username == name {
		http.Error(w, "Turn off your own two-step sign-in under Settings > Users, with your password", http.StatusConflict)
		return
	}
	if _, err := s.authSystem.GetUser(r.Context(), name); err != nil {
		http.Error(w, "No such user", http.StatusNotFound)
		return
	}
	if err := s.mfa.Reset(name); err != nil {
		mfaError(w, err)
		return
	}
	s.provisionAudit(r, "dashboard-user-2fa-reset", name, "")
	writeJSON(w, map[string]any{"ok": true})
}

func mfaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, adminmfa.ErrWrongCode):
		http.Error(w, "That code isn't right; check your phone's clock if it keeps happening", http.StatusBadRequest)
	case errors.Is(err, adminmfa.ErrActive), errors.Is(err, adminmfa.ErrNoPending):
		http.Error(w, capitalize(err.Error()), http.StatusConflict)
	case errors.Is(err, adminmfa.ErrInvalid):
		http.Error(w, "That can't be done", http.StatusBadRequest)
	default:
		slog.Error("Two-step sign-in settings failed", "error", err)
		http.Error(w, fmt.Sprintf("The change couldn't be saved (%s)", "see the console's log"), http.StatusInternalServerError)
	}
}
