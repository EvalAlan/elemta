package webmail

// Allowed and blocked senders (internal/mailbox/sender_rules.go): kept by
// the mailbox service and changed through its security API with the
// user's own credentials, up to their class of service's limit.

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"
)

type senderRules struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
	Max   int      `json:"max"`
}

func (s *Server) senderRules(ctx context.Context, sess *Session) (*senderRules, error) {
	if s.security == nil || sess.AdminActor != "" {
		return nil, nil
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out senderRules
	if err := s.security.call(ctx, http.MethodGet, "/v1/security/senders", sess.User, pw, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// splitLines reads a list typed one per line (or separated by commas).
func splitLines(raw string) []string {
	out := strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t' })
	if out == nil {
		out = []string{} // an empty list, which clears, rather than null
	}
	return out
}

func (s *Server) sendersSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.security == nil || sess.AdminActor != "" {
		http.Error(w, "Allowed and blocked senders can't be changed here.", http.StatusForbidden)
		return
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	in := senderRules{Allow: splitLines(r.PostFormValue("allow")), Block: splitLines(r.PostFormValue("block"))}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	err = s.security.call(ctx, http.MethodPut, "/v1/security/senders", sess.User, pw, in, nil)
	if errors.Is(err, errSecurityInput) {
		v, verr := s.settingsView(r, sess, "account")
		if verr != nil {
			s.fail(w, r, sess, verr)
			return
		}
		v.Settings.Notice = strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":"))
		v.Settings.NoticeCard = "senders"
		v.Settings.AllowText, v.Settings.BlockText = r.PostFormValue("allow"), r.PostFormValue("block")
		s.render(w, "settings.html", http.StatusBadRequest, v)
		return
	}
	if err != nil {
		s.log.Warn("webmail: save sender rules", "user", sess.User, "error", err)
		http.Redirect(w, r, "/settings/account?n=senders-failed#senders", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/account?n=senders-saved#senders", http.StatusSeeOther)
}

func (s *Server) blockSender(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.security == nil || sess.AdminActor != "" {
		http.Error(w, "Blocked senders can't be changed here.", http.StatusForbidden)
		return
	}
	address := strings.ToLower(strings.TrimSpace(r.PostFormValue("sender")))
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "This message has no sender address to block.")
		return
	}
	rules, err := s.senderRules(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if !slices.Contains(rules.Block, address) {
		// A previously allowed sender must leave that list before the API can
		// accept it as blocked; the remaining entries stay in place.
		rules.Allow = slices.DeleteFunc(rules.Allow, func(entry string) bool { return strings.EqualFold(entry, address) })
		rules.Block = append(rules.Block, address)
		pw, err := s.sessions.password(sess)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := s.security.call(ctx, http.MethodPut, "/v1/security/senders", sess.User, pw, rules, nil); err != nil {
			if errors.Is(err, errSecurityInput) {
				s.renderProblem(w, r, sess, http.StatusBadRequest, strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":")))
				return
			}
			s.fail(w, r, sess, err)
			return
		}
	}
	back := localBack(r.PostFormValue("back"), "/mail")
	redirectLocal(w, r, setParam(back, "n", "sender-blocked"))
}
