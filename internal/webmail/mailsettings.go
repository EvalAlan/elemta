package webmail

// A user's own mail settings in the directory (docs/directory.md): where
// their mail is forwarded, whether a copy stays, and which addresses an
// administrator has let them send as.
//
// Like a password change, this acts as the user: the webmail binds with
// their own password, so the directory's rules decide what they may do.
// They may change their forwarding; they may only read their send-as
// rights, which an administrator grants.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// AccountMail is the part of a user's directory entry the webmail shows.
type AccountMail struct {
	Forward  []string
	KeepCopy bool
	SendAs   []string
}

// MailSettings reads and changes a user's own directory mail settings.
type MailSettings interface {
	ReadMailSettings(ctx context.Context, user, password string) (AccountMail, error)
	SetForwarding(ctx context.Context, user, password string, forward []string, keepCopy bool) error
}

// maxForward matches the provisioning limit (internal/provision).
const maxForward = 10

func (l ldapPasswords) asUser(ctx context.Context, user, password string) (*ldap.Conn, string, error) {
	conn, dn, err := l.find(ctx, user)
	if err != nil {
		return nil, "", err
	}
	if err := conn.Bind(dn, password); err != nil {
		_ = conn.Close()
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, "", errWrongPassword
		}
		return nil, "", fmt.Errorf("webmail: LDAP bind as user: %w", err)
	}
	return conn, dn, nil
}

func (l ldapPasswords) ReadMailSettings(ctx context.Context, user, password string) (AccountMail, error) {
	conn, dn, err := l.asUser(ctx, user, password)
	if err != nil {
		return AccountMail{}, err
	}
	defer func() { _ = conn.Close() }()
	res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)",
		[]string{"elemtaForwardTo", "elemtaForwardKeepCopy", "elemtaSendAs"}, nil))
	if err != nil {
		return AccountMail{}, fmt.Errorf("webmail: read mail settings: %w", err)
	}
	if len(res.Entries) != 1 {
		return AccountMail{}, errors.New("webmail: account entry not found")
	}
	e := res.Entries[0]
	return AccountMail{
		Forward:  lowerAll(e.GetAttributeValues("elemtaForwardTo")),
		KeepCopy: strings.EqualFold(e.GetAttributeValue("elemtaForwardKeepCopy"), "TRUE"),
		SendAs:   lowerAll(e.GetAttributeValues("elemtaSendAs")),
	}, nil
}

func (l ldapPasswords) SetForwarding(ctx context.Context, user, password string, forward []string, keepCopy bool) error {
	conn, dn, err := l.asUser(ctx, user, password)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	change := ldap.NewModifyRequest(dn, nil)
	change.Replace("elemtaForwardTo", forward) // no values removes it
	change.Replace("elemtaForwardKeepCopy", []string{strings.ToUpper(strconv.FormatBool(keepCopy))})
	if err := conn.Modify(change); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			return fmt.Errorf("webmail: the directory doesn't let users change their forwarding: %w", err)
		}
		return fmt.Errorf("webmail: set forwarding: %w", err)
	}
	return nil
}

func lowerAll(values []string) []string {
	out := []string{}
	for _, v := range values {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// accountMail reads the signed-in user's settings, cached for the session
// for a minute: compose asks for the send-as addresses on every message.
func (s *Server) accountMail(ctx context.Context, sess *Session) (AccountMail, bool) {
	if s.mailSettings == nil || sess.AdminActor != "" {
		return AccountMail{}, false
	}
	if m, ok := s.pages.getMail(sess.ID, s.now()); ok {
		return m, true
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return AccountMail{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m, err := s.mailSettings.ReadMailSettings(ctx, sess.User, pw)
	if err != nil {
		s.log.Warn("webmail: read mail settings", "user", sess.User, "error", err)
		return AccountMail{}, false
	}
	s.pages.putMail(sess.ID, m, s.now())
	return m, true
}

// fromChoices are the sender addresses compose offers: the session's own
// (or the shared mailbox it has selected), then each address an
// administrator lets this user send as. A grant for a whole domain
// (@example.com) isn't listed: there is no one address to offer.
func (s *Server) fromChoices(ctx context.Context, sess *Session) []string {
	choices := []string{s.sendAddress(ctx, sess)}
	if m, ok := s.accountMail(ctx, sess); ok {
		for _, a := range m.SendAs {
			if !strings.HasPrefix(a, "@") && !slices.Contains(choices, a) {
				choices = append(choices, a)
			}
		}
	}
	return choices
}

// chosenFrom is the sender a compose form asked for, if it is one of the
// choices; otherwise the default. The MTA checks the sender again.
func (s *Server) chosenFrom(ctx context.Context, sess *Session, asked string) string {
	choices := s.fromChoices(ctx, sess)
	asked = strings.ToLower(strings.TrimSpace(asked))
	if asked != "" && slices.Contains(choices, asked) {
		return asked
	}
	return choices[0]
}

// parseForward reads the forwarding addresses a form posted, separated by
// commas, semicolons or line breaks.
func parseForward(raw, own string) ([]string, string) {
	out := []string{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		a, err := mail.ParseAddress(part)
		if err != nil {
			return nil, "“" + part + "” isn't an email address."
		}
		addr := strings.ToLower(a.Address)
		if addr == strings.ToLower(own) {
			return nil, "You can't forward your mail to yourself."
		}
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	if len(out) > maxForward {
		return nil, fmt.Sprintf("Forward to at most %d addresses.", maxForward)
	}
	return out, ""
}

func (s *Server) forwardingSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.mailSettings == nil || sess.AdminActor != "" {
		http.Error(w, "Forwarding can't be changed here.", http.StatusForbidden)
		return
	}
	forward, problem := parseForward(r.PostFormValue("forward"), sess.Address)
	if problem != "" {
		v, err := s.settingsView(r, sess, "account")
		if err != nil {
			s.fail(w, r, sess, err)
			return
		}
		v.Settings.Notice, v.Settings.NoticeCard = problem, "forwarding"
		v.Settings.ForwardText = r.PostFormValue("forward")
		s.render(w, "settings.html", http.StatusBadRequest, v)
		return
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.mailSettings.SetForwarding(ctx, sess.User, pw, forward, r.PostFormValue("keep_copy") == "1"); err != nil {
		s.log.Warn("webmail: set forwarding", "user", sess.User, "error", err)
		http.Redirect(w, r, "/settings/account?n=forwarding-failed#forwarding", http.StatusSeeOther)
		return
	}
	s.pages.forgetMail(sess.ID)
	http.Redirect(w, r, "/settings/account?n=forwarding-saved#forwarding", http.StatusSeeOther)
}
