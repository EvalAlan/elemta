package webmail

import (
	"context"
	"net/http"
	"strings"
)

type sharedMailbox struct {
	Mailbox string `json:"mailbox"`
	Member  string `json:"member"`
	CanSend bool   `json:"can_send"`
}

func (s *Server) sharedMailboxes(ctx context.Context, sess *Session) []sharedMailbox {
	if s.security == nil {
		return nil
	}
	if list, ok := s.pages.getShares(sess.ID, s.now()); ok {
		return list
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return nil
	}
	var out []sharedMailbox
	if err := s.security.call(ctx, http.MethodGet, "/v1/security/shares", sess.User, pw, nil, &out); err != nil {
		s.log.Warn("shared mailbox list unavailable", "error", err)
		return nil
	}
	s.pages.putShares(sess.ID, out, s.now())
	return out
}

func (s *Server) sendAddress(ctx context.Context, sess *Session) string {
	selected := s.sessions.SelectedMailbox(sess)
	if selected != "" {
		for _, share := range s.sharedMailboxes(ctx, sess) {
			if share.Mailbox == selected && share.CanSend {
				return selected
			}
		}
	}
	return sess.Address
}

func (s *Server) switchMailbox(w http.ResponseWriter, r *http.Request, sess *Session) {
	address := strings.ToLower(strings.TrimSpace(r.PostFormValue("mailbox")))
	if address != "" {
		allowed := false
		for _, share := range s.sharedMailboxes(r.Context(), sess) {
			if share.Mailbox == address {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "mailbox access denied", http.StatusForbidden)
			return
		}
		pw, err := s.sessions.password(sess)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		store, err := s.dial(r.Context(), sess.User+"|"+address, pw)
		if err != nil {
			http.Error(w, "mailbox access denied", http.StatusForbidden)
			return
		}
		_ = store.Close()
	}
	if err := s.sessions.SetMailbox(r.Context(), sess, address); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/mail", http.StatusSeeOther)
}
