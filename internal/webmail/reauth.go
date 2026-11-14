package webmail

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Some settings turn a webmail session, which ends, into access that
// doesn't: an app password works in mail apps for as long as it exists and
// skips the second step by design, and forwarding (or a filter that
// redirects) copies every new message out. Someone holding a session for a
// few minutes (a stolen cookie, an unlocked computer) could set either up and
// keep reading mail after the user changed their password. So these ask for
// the current password, as changing the recovery address already does.

// currentPasswordField is the form field these settings read it from.
const currentPasswordField = "current_password"

// confirmPassword checks the account password typed into the request against
// the mail server. It returns "" when it is right, or what to tell the user.
func (s *Server) confirmPassword(ctx context.Context, r *http.Request, sess *Session) string {
	if sess.AdminActor != "" {
		return "An administrator session can't change this."
	}
	key := "reauth:" + strings.ToLower(sess.User)
	if s.limiter.blocked(key, maxFailuresPerUser) {
		return "Too many wrong passwords. Wait a few minutes and try again."
	}
	current := r.PostFormValue(currentPasswordField)
	if current == "" {
		return "Enter your current password to make this change."
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	store, err := s.dial(ctx, sess.User, current)
	if err != nil {
		if errors.Is(err, ErrAuthFailed) {
			s.limiter.fail(key)
			return "Your current password isn't right."
		}
		s.log.Warn("webmail: password confirmation unavailable", "user", sess.User, "error", err)
		return "Your password couldn't be checked. Try again in a moment."
	}
	_ = store.Close()
	// The mail server also takes app passwords, and a passkey sign-in's
	// token; neither proves the person knows the account password.
	if s.security != nil {
		check, err := s.security.check(ctx, sess.User, current)
		if err != nil {
			s.log.Warn("webmail: password confirmation unavailable", "user", sess.User, "error", err)
			return "Your password couldn't be checked. Try again in a moment."
		}
		if check.Kind == "app" || check.Kind == "session" {
			s.limiter.fail(key)
			return "Enter your account password, not an app password."
		}
	}
	s.limiter.reset(key)
	return ""
}

// revokeAppPasswords deletes every app password on the account. It runs after
// the password is changed or reset, with the new password: an app password
// someone else created must not survive the user's response to that.
// It returns how many were revoked.
func (s *Server) revokeAppPasswords(ctx context.Context, user, password string) (int, error) {
	if s.security == nil {
		return 0, nil
	}
	var out struct {
		Revoked int `json:"revoked"`
	}
	err := s.security.call(ctx, http.MethodPost, "/v1/security/app-passwords/revoke-all", user, password, nil, &out)
	return out.Revoked, err
}
