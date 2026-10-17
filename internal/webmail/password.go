package webmail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// Users change their own password from Settings. The mailbox password is
// the user's LDAP password (Dovecot and Elemta's submission both check it
// against LDAP), so the change is made there, with the LDAP Password Modify
// operation (RFC 3062) performed as the user: the webmail binds with the
// user's current password, so it can only ever change the password of
// someone who knows it, and the directory applies its own password policy.

// PasswordChanger changes a user's password.
type PasswordChanger interface {
	ChangePassword(ctx context.Context, user, current, next string) error
}

// Errors from a password change that the page explains.
var (
	errWrongPassword  = errors.New("webmail: current password is wrong")
	errPolicyRejected = errors.New("webmail: the directory refused the new password")
)

// ldapPasswords changes passwords in an LDAP directory.
type ldapPasswords struct {
	url, base, filter        string
	searchDN, searchPassword string
	insecureSkipVerify       bool
}

func (l ldapPasswords) find(ctx context.Context, user string) (*ldap.Conn, string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := ldap.DialURL(l.url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- opt-in for the dev stack's self-signed certificate; documented as dev-only
		InsecureSkipVerify: l.insecureSkipVerify,
	}))
	if err != nil {
		return nil, "", fmt.Errorf("webmail: connect to LDAP: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(dl))
	}

	// Find the user's entry. The lookup account only needs to read DNs.
	if l.searchDN != "" {
		if err := conn.Bind(l.searchDN, l.searchPassword); err != nil {
			return nil, "", fmt.Errorf("webmail: LDAP lookup bind: %w", err)
		}
	}
	filter := strings.ReplaceAll(l.filter, "%s", ldap.EscapeFilter(user))
	res, err := conn.Search(ldap.NewSearchRequest(l.base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, filter, []string{"dn"}, nil))
	if err != nil {
		return nil, "", fmt.Errorf("webmail: LDAP search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, "", fmt.Errorf("webmail: LDAP search for %q found %d entries", user, len(res.Entries))
	}
	ok = true
	return conn, res.Entries[0].DN, nil
}

func (l ldapPasswords) ChangePassword(ctx context.Context, user, current, next string) error {
	conn, dn, err := l.find(ctx, user)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// From here on the connection acts as the user.
	if err := conn.Bind(dn, current); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return errWrongPassword
		}
		return fmt.Errorf("webmail: LDAP bind as user: %w", err)
	}
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest("", current, next)); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) || ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
			return fmt.Errorf("%w: %v", errPolicyRejected, err)
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			return fmt.Errorf("webmail: the directory doesn't let users change their own password: %w", err)
		}
		return fmt.Errorf("webmail: LDAP password modify: %w", err)
	}
	return nil
}

// checkNewPassword applies the webmail's own minimum rules before the
// directory's policy sees the password.
func checkNewPassword(user, current, next, confirm string, minLen int) string {
	switch {
	case next != confirm:
		return "The new passwords don't match."
	case utf8.RuneCountInString(next) < minLen:
		return fmt.Sprintf("Use at least %d characters.", minLen)
	case next == current:
		return "The new password must be different from the current one."
	case len(next) > 256:
		return "That password is too long."
	}
	local := strings.ToLower(user)
	if i := strings.IndexByte(local, '@'); i > 0 {
		local = local[:i]
	}
	if len(local) >= 3 && strings.Contains(strings.ToLower(next), local) {
		return "The password can't contain your user name."
	}
	return ""
}

func (s *Server) passwordSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.passwords == nil {
		s.renderProblem(w, r, sess, http.StatusNotFound, "Password changes aren't available here. Ask your administrator.")
		return
	}
	current := r.PostFormValue("current")
	next := r.PostFormValue("new")
	userKey := "user:" + strings.ToLower(sess.User)
	if s.limiter.blocked(userKey, maxFailuresPerUser) {
		s.renderProblem(w, r, sess, http.StatusTooManyRequests, "Too many wrong passwords. Wait a few minutes and try again.")
		return
	}
	if problem := checkNewPassword(sess.User, current, next, r.PostFormValue("confirm"), s.cfg.MinPasswordLength); problem != "" {
		s.renderProblem(w, r, sess, http.StatusBadRequest, problem)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := s.passwords.ChangePassword(ctx, sess.User, current, next)
	switch {
	case errors.Is(err, errWrongPassword):
		// Counts like a failed sign-in, so this form can't be used to
		// guess the current password.
		s.limiter.fail(userKey)
		s.renderProblem(w, r, sess, http.StatusForbidden, "Your current password isn't right.")
		return
	case errors.Is(err, errPolicyRejected):
		s.renderProblem(w, r, sess, http.StatusBadRequest, "The directory refused that password. Choose a longer or less common one.")
		return
	case err != nil:
		s.log.Warn("webmail: change password", "user", sess.User, "error", err)
		s.renderProblem(w, r, sess, http.StatusBadGateway, "The password couldn't be changed. Try again later.")
		return
	}
	// This session carries on with the new password. Other sessions keep
	// working until their mail connection is redialled, then sign out.
	if err := s.sessions.UpdatePassword(sess, next); err != nil {
		s.log.Warn("webmail: reseal session password", "user", sess.User, "error", err)
	}
	s.log.Info("webmail: password changed", "user", sess.User, "ip", clientIP(r))
	http.Redirect(w, r, "/settings?n=password-changed", http.StatusSeeOther)
}

// PasswordResetter requires a directory account authorized to reset passwords.
// It is separate from PasswordChanger so self-service never gains that power.
type PasswordResetter interface {
	ResetPassword(context.Context, string, string) error
}

func (l ldapPasswords) ResetPassword(ctx context.Context, user, next string) error {
	if l.searchDN == "" || l.searchPassword == "" {
		return errors.New("webmail: privileged LDAP reset credentials are required")
	}
	conn, dn, err := l.find(ctx, user)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", next)); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) || ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
			return errPolicyRejected
		}
		return fmt.Errorf("webmail: LDAP password reset: %w", err)
	}
	return nil
}
