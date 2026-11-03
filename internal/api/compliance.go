package api

// Compliance search and export (mailpolicy.ComplianceQuery), for system
// administrators and the compliance role.
//
// Reading other people's mail is the most sensitive thing the dashboard
// does, so every search, export and message opened is recorded in the audit
// log before anything is shown, and one that can't be recorded isn't
// answered. The entries are kept from domain administrators, who may be the
// people an investigation is about.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/gorilla/mux"
)

// complianceExportTime bounds one export. The dashboard's server answers
// ordinary requests within seconds; an export of years of mail can't.
const complianceExportTime = 30 * time.Minute

// errNotRecorded answers a request whose audit entry couldn't be stored.
var errNotRecorded = errors.New("the audit log could not record this, so it was not done; try again")

func (s *Server) complianceRoutes(api *mux.Router) {
	if s.authMiddleware == nil {
		api.PathPrefix("/compliance/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Administrator authentication is required", http.StatusForbidden)
		})
		return
	}
	need := s.authMiddleware.RequirePermission(auth.PermissionMailCompliance)
	api.Handle("/compliance/search", need(http.HandlerFunc(s.handleComplianceSearch))).Methods("POST")
	api.Handle("/compliance/export", need(http.HandlerFunc(s.handleComplianceExport))).Methods("POST")
	api.Handle("/compliance/message", need(http.HandlerFunc(s.handleComplianceMessage))).Methods("GET")
}

// complianceQuery reads a query: a JSON body, or, for a download the browser
// starts itself, a form whose "query" field holds the JSON.
func complianceQuery(w http.ResponseWriter, r *http.Request) (mailpolicy.ComplianceQuery, bool) {
	var q mailpolicy.ComplianceQuery
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		err = json.NewDecoder(r.Body).Decode(&q)
	} else {
		err = json.Unmarshal([]byte(r.PostFormValue("query")), &q)
	}
	if err != nil {
		http.Error(w, "The search could not be read", http.StatusBadRequest)
		return q, false
	}
	// The dashboard's searchers see every domain; Domains is for callers
	// that confine someone, never for the searcher to widen or set.
	q.Domains = nil
	if err := q.Normalize(); err != nil {
		// The explanation is the error's last line; the first is the sentinel.
		lines := strings.Split(err.Error(), "\n")
		http.Error(w, lines[len(lines)-1], http.StatusBadRequest)
		return q, false
	}
	return q, true
}

func (s *Server) complianceClient(w http.ResponseWriter) (*mailpolicy.Client, bool) {
	c, err := s.provisioner.MailboxAdmin()
	if err != nil {
		http.Error(w, "Compliance search needs the mailbox admin API: set "+mailpolicy.TokenEnv+" for the dashboard", http.StatusServiceUnavailable)
		return nil, false
	}
	return c, true
}

// complianceAudit records a compliance action, and reports whether it was
// stored. It is never left to the log alone.
func (s *Server) complianceAudit(r *http.Request, action, target, detail string) bool {
	actor := "unknown"
	if ac := GetAuthContext(r); ac != nil {
		actor = ac.Username
		if ac.IsAPIKey {
			actor += " (API key)"
		}
	}
	if s.provisioner == nil || s.provisioner.Mailbox == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	// "(system)" keeps the entry from every domain administrator's view.
	entry := mailpolicy.AuditEntry{Actor: actor, Source: "dashboard", Client: s.loginAddr(r), Action: action, Target: target, Domain: "(system)", Detail: detail}
	return s.provisioner.Audit(ctx, entry) == nil
}

// complianceTarget names what a query reads, for the audit log's target.
func complianceTarget(q mailpolicy.ComplianceQuery) string {
	switch len(q.Accounts) {
	case 0:
		return "all mailboxes"
	case 1:
		return q.Accounts[0]
	}
	return fmt.Sprintf("%d mailboxes", len(q.Accounts))
}

func complianceError(w http.ResponseWriter, err error) {
	var apiErr *mailpolicy.APIError
	if errors.As(err, &apiErr) && apiErr.Status < 500 {
		http.Error(w, apiErr.Message, apiErr.Status)
		return
	}
	slog.Error("Compliance search failed", "error", err)
	http.Error(w, "The mailbox service could not answer the search", http.StatusBadGateway)
}

func (s *Server) handleComplianceSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, ok := complianceQuery(w, r)
	if !ok {
		return
	}
	c, ok := s.complianceClient(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := c.ComplianceSearch(ctx, q)
	if err != nil {
		complianceError(w, err)
		return
	}
	if !s.complianceAudit(r, "compliance-search", complianceTarget(q), fmt.Sprintf("%s: %d found", q.Describe(), res.Total)) {
		http.Error(w, errNotRecorded.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, ok := complianceQuery(w, r)
	if !ok {
		return
	}
	c, ok := s.complianceClient(w)
	if !ok {
		return
	}
	if !s.complianceAudit(r, "compliance-export", complianceTarget(q), q.Describe()) {
		http.Error(w, errNotRecorded.Error(), http.StatusServiceUnavailable)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(complianceExportTime))
	ctx, cancel := context.WithTimeout(r.Context(), complianceExportTime)
	defer cancel()
	name := "compliance-export-" + time.Now().UTC().Format("20060102-150405") + ".mbox"
	out := &startedWriter{w: w, start: func() {
		w.Header().Set("Content-Type", "application/mbox")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}}
	err := c.ComplianceExport(ctx, q, out)
	switch {
	case err != nil && !out.started:
		complianceError(w, err)
	case err != nil:
		// Too late for an error page: the file is cut short, and the log
		// says so.
		slog.Error("Compliance export failed part way", "error", err)
	case !out.started:
		out.start()
		w.WriteHeader(http.StatusOK)
	}
}

// refPattern is what the mailbox's refs look like, checked before one is
// written into the audit log or passed on.
var refPattern = regexp.MustCompile(`^(m:[0-9]{1,19}:[0-9]{1,10}|h:[0-9]{1,19})$`)

func (s *Server) handleComplianceMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ref := r.URL.Query().Get("ref")
	if !refPattern.MatchString(ref) {
		http.Error(w, "No such message", http.StatusNotFound)
		return
	}
	c, ok := s.complianceClient(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var buf strings.Builder
	account, err := c.ComplianceMessage(ctx, ref, nil, &buf)
	if err != nil {
		complianceError(w, err)
		return
	}
	if account == "" {
		account = "unknown account"
	}
	if !s.complianceAudit(r, "compliance-view", account, "downloaded "+ref) {
		http.Error(w, errNotRecorded.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(ref, ":", "-")+`.eml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(buf.String()))
}

// startedWriter calls start before the first byte reaches w, so a refusal
// that comes first can still be an error page rather than a broken file.
type startedWriter struct {
	w       http.ResponseWriter
	start   func()
	started bool
}

func (s *startedWriter) Write(p []byte) (int, error) {
	if !s.started {
		s.started = true
		s.start()
	}
	return s.w.Write(p)
}
