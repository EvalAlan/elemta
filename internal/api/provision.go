package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/gorilla/mux"
)

func (s *Server) SetProvisioner(service *provision.Service) { s.provisioner = service }
func (s *Server) provisionRoutes(api *mux.Router) {
	// Mailbox credentials and routing must never inherit the dashboard's
	// development mode where some operational endpoints can run without login.
	protected := api.PathPrefix("/provision").Subrouter()
	if s.authMiddleware == nil {
		protected.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Administrator authentication is required", http.StatusForbidden)
		})
		return
	}
	protected.Use(s.requireMailAdmin)
	protected.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if s.provisioner == nil {
			writeJSON(w, map[string]any{"available": false, "reason": "Configure shared sessions and a privileged mailbox directory account to enable mail administration"})
			return
		}
		writeJSON(w, map[string]any{"available": true, "min_password_length": max(10, s.provisioner.MinPasswordLength), "mailbox_admin": s.provisioner.Mailbox != nil, "scope": scopeOf(r).view()})
	}).Methods("GET")
	s.provisionPolicyRoutes(protected)
	protected.HandleFunc("/accounts/{address}/access", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		address, err := provision.Address(mux.Vars(r)["address"])
		if err != nil {
			return err
		}
		if err := scopeOf(r).checkAddress(address); err != nil {
			return err
		}
		account, err := s.provisioner.Get(ctx, address)
		if err != nil {
			return err
		}
		// Require the primary address: an alias in an assigned domain may
		// point at an account in another domain. A suspended account can
		// be opened (looking into why it was suspended is a common reason);
		// a disabled one can't.
		if account.Address != address || (account.Status != "active" && account.Status != "suspended") {
			return provision.ErrInvalid
		}
		if err := scopeOf(r).checkAddress(account.Address); err != nil {
			return err
		}
		publicURL := strings.TrimRight(os.Getenv("ELEMTA_WEBMAIL_PUBLIC_URL"), "/")
		u, err := url.Parse(publicURL)
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return mailpolicy.ErrUnavailable
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		ac := GetAuthContext(r)
		access, err := c.AdminAccess(ctx, address, ac.Username, s.loginAddr(r))
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"address": access.Address, "token": access.Token, "expires": access.Expires, "webmail_url": publicURL})
		return nil
	})).Methods("POST")
	protected.HandleFunc("/audit", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		v := r.URL.Query()
		q := mailpolicy.AuditQuery{Actor: v.Get("actor"), Target: v.Get("target"), Action: v.Get("action")}
		q.Before, _ = strconv.ParseInt(v.Get("before"), 10, 64)
		q.Limit, _ = strconv.Atoi(v.Get("limit"))
		if sc := scopeOf(r); !sc.all {
			q.Domains = sc.domains
		}
		entries, err := c.AuditLog(ctx, q)
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"entries": entries})
		return nil
	})).Methods("GET")
	protected.HandleFunc("/accounts", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		sc := scopeOf(r)
		if r.Method == "GET" {
			accounts, err := s.provisioner.List(ctx)
			if err != nil {
				return err
			}
			writeJSON(w, map[string]any{"accounts": filterAccounts(sc, accounts)})
			return nil
		}
		var in provision.Create
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if err := sc.checkAddress(in.Address); err != nil {
			return err
		}
		account, err := s.provisioner.Create(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "account-create", account.Address, fmt.Sprintf("quota %d", account.QuotaBytes))
		writeJSONStatus(w, http.StatusCreated, account)
		return nil
	})).Methods("GET", "POST")
	protected.HandleFunc("/accounts/{address}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		address := mux.Vars(r)["address"]
		if err := scopeOf(r).checkAddress(address); err != nil {
			return err
		}
		switch r.Method {
		case "GET":
			account, err := s.provisioner.Get(ctx, address)
			if err != nil {
				return err
			}
			writeJSON(w, account)
		case "PATCH":
			var patch provision.Patch
			if !decodeJSONBody(w, r, &patch) {
				return nil
			}
			account, err := s.provisioner.Update(ctx, address, patch)
			if err != nil {
				return err
			}
			s.provisionAudit(r, "account-update", account.Address, patchDetail(patch))
			writeJSON(w, account)
		case "DELETE":
			var in struct {
				Confirm string `json:"confirm"`
				Purge   bool   `json:"purge"`
			}
			if !decodeJSONBody(w, r, &in) {
				return nil
			}
			if in.Confirm != address {
				return provision.ErrInvalid
			}
			if in.Purge {
				// Checked first, so a missing admin token can't leave the
				// account deleted and its mail behind.
				if err := s.provisioner.CheckPurgeable(ctx, address); err != nil {
					return err
				}
			}
			if err := s.provisioner.Delete(ctx, address); err != nil {
				return err
			}
			s.provisionAudit(r, "account-delete", address, "")
			if !in.Purge {
				writeJSON(w, map[string]any{"status": "Account removed; its mailbox is retained."})
				return nil
			}
			result, err := s.provisioner.Purge(ctx, address)
			if err != nil {
				return err
			}
			s.provisionAudit(r, "account-purge", address, fmt.Sprintf("%d messages", result.Messages))
			writeJSON(w, map[string]any{"status": fmt.Sprintf("Account removed and its mailbox purged (%d messages).", result.Messages)})
		}
		return nil
	})).Methods("GET", "PATCH", "DELETE")
	protected.HandleFunc("/accounts/{address}/password", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Password string `json:"password"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		address := mux.Vars(r)["address"]
		if err := scopeOf(r).checkAddress(address); err != nil {
			return err
		}
		if err := s.provisioner.Password(ctx, address, in.Password); err != nil {
			return err
		}
		s.provisionAudit(r, "account-password", address, "")
		writeJSON(w, map[string]any{"status": "password reset; webmail sessions ended"})
		return nil
	})).Methods("POST")
	protected.HandleFunc("/accounts/{address}/aliases", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Alias string `json:"alias"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if err := scopeOf(r).checkAddress(mux.Vars(r)["address"], in.Alias); err != nil {
			return err
		}
		account, err := s.provisioner.Alias(ctx, mux.Vars(r)["address"], in.Alias, r.Method == "POST")
		if err != nil {
			return err
		}
		action := "alias-add"
		if r.Method == "DELETE" {
			action = "alias-remove"
		}
		s.provisionAudit(r, action, account.Address, in.Alias)
		writeJSON(w, account)
		return nil
	})).Methods("POST", "DELETE")
	protected.HandleFunc("/domains", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		sc := scopeOf(r)
		if r.Method == "GET" {
			domains, err := s.provisioner.Domains(ctx)
			if err != nil {
				return err
			}
			visible := []provision.Domain{}
			for _, d := range domains {
				if sc.domain(d.Name) {
					visible = append(visible, d)
				}
			}
			writeJSON(w, map[string]any{"domains": visible})
			return nil
		}
		if err := sc.systemOnly(); err != nil {
			return err
		}
		var in struct {
			Name string `json:"name"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if err := s.provisioner.Domain(ctx, in.Name, r.Method == "POST"); err != nil {
			return err
		}
		action := "domain-add"
		if r.Method == "DELETE" {
			action = "domain-remove"
		}
		s.provisionAudit(r, action, in.Name, "")
		writeJSON(w, map[string]any{"requires_restart": true, "status": "Domain configuration saved. Restart the SMTP service to apply routing changes."})
		return nil
	})).Methods("GET", "POST", "DELETE")
}
func (s *Server) provisionCall(fn func(context.Context, http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.provisioner == nil {
			http.Error(w, "Mail administration is not configured", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		err := fn(ctx, w, r)
		if err == nil {
			return
		}
		var apiErr *mailpolicy.APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.Status < 500:
			// The mailbox's own refusal, which explains itself.
			http.Error(w, apiErr.Message, apiErr.Status)
		case errors.Is(err, errOutOfScope):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, provision.ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, provision.ErrExists):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, provision.ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, provision.ErrUnavailable):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		default:
			slog.Error("Mailbox administration failed", "error", err)
			http.Error(w, "The mailbox directory operation failed. Check the directory connection and mail schema configuration.", http.StatusBadGateway)
		}
	}
}

// provisionAudit records a change made from the dashboard. It runs after
// the change succeeded and on a context of its own, so a client that hangs
// up as the response is written doesn't lose the entry.
func (s *Server) provisionAudit(r *http.Request, action, target, detail string) {
	actor := "unknown"
	if ac := GetAuthContext(r); ac != nil {
		actor = ac.Username
		if ac.IsAPIKey {
			actor += " (API key)"
		}
	}
	entry := mailpolicy.AuditEntry{Actor: actor, Source: "dashboard", Client: s.loginAddr(r), Action: action, Target: target, Detail: detail}
	if strings.HasPrefix(action, "dashboard-user-") {
		// A dashboard user named like an address isn't part of that
		// domain; keep these entries away from its domain administrator.
		entry.Domain = "(system)"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	_ = s.provisioner.Audit(ctx, entry)
}

// patchDetail describes an account update for the audit log.
func patchDetail(p provision.Patch) string {
	var parts []string
	if p.Name != nil {
		parts = append(parts, "name")
	}
	if p.Status != nil {
		parts = append(parts, "status "+*p.Status)
	}
	if p.QuotaBytes != nil {
		parts = append(parts, fmt.Sprintf("quota %d", *p.QuotaBytes))
	}
	return strings.Join(parts, ", ")
}
