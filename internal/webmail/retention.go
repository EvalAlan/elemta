package webmail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type folderRetention struct {
	Name string `json:"name"`
	Days int    `json:"days"`
	Role Role   `json:"-"`
}

func (s *Server) folderRetentions(ctx context.Context, sess *Session) ([]folderRetention, error) {
	if s.security == nil || sess.AdminActor != "" {
		return nil, nil
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []folderRetention
	if err := s.security.call(ctx, http.MethodGet, "/v1/security/retention", sess.User, pw, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) saveFolderRetentions(ctx context.Context, sess *Session, settings []folderRetention) error {
	if s.security == nil || sess.AdminActor != "" {
		return errSecurityAuth
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.security.call(ctx, http.MethodPut, "/v1/security/retention", sess.User, pw, settings, nil)
}

func retentionDays(raw string) (int, bool) {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	return days, err == nil && days >= 0 && days <= 36500
}

func (s *Server) retentionSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	names, values := r.PostForm["folder"], r.PostForm["days"]
	if len(names) != 3 || len(values) != 3 {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Choose a retention period for Trash, Junk and Sent.")
		return
	}
	settings := make([]folderRetention, 0, 3)
	for i, name := range names {
		days, ok := retentionDays(values[i])
		if !ok || name == "" {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "Retention must be 0 to 36500 days.")
			return
		}
		settings = append(settings, folderRetention{Name: name, Days: days})
	}
	if err := s.saveFolderRetentions(r.Context(), sess, settings); err != nil {
		s.retentionFailure(w, r, sess, err)
		return
	}
	http.Redirect(w, r, "/settings/account?n=retention-saved#retention", http.StatusSeeOther)
}

func (s *Server) folderRetentionGet(w http.ResponseWriter, r *http.Request, sess *Session) {
	settings, err := s.folderRetentions(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	for _, setting := range settings {
		if setting.Name == r.URL.Query().Get("folder") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(setting)
			return
		}
	}
	http.Error(w, "Folder not found.", http.StatusNotFound)
}

func (s *Server) folderRetentionSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	name := r.PostFormValue("folder")
	days, ok := retentionDays(r.PostFormValue("days"))
	if !ok || name == "" {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Retention must be 0 to 36500 days.")
		return
	}
	if err := s.saveFolderRetentions(r.Context(), sess, []folderRetention{{Name: name, Days: days}}); err != nil {
		s.retentionFailure(w, r, sess, err)
		return
	}
	back := localBack(r.PostFormValue("back"), "/folders")
	redirectLocal(w, r, setParam(back, "n", "retention-saved"))
}

func (s *Server) retentionFailure(w http.ResponseWriter, r *http.Request, sess *Session, err error) {
	if errors.Is(err, errSecurityInput) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":")))
		return
	}
	s.fail(w, r, sess, err)
}
