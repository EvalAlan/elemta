package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/EvalAlan/elemta/internal/auth"
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
	protected.Use(s.authMiddleware.RequirePermission(auth.PermissionSystemAdmin))
	protected.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if s.provisioner == nil {
			writeJSON(w, map[string]any{"available": false, "reason": "Configure shared sessions and a privileged mailbox directory account to enable mail administration"})
			return
		}
		writeJSON(w, map[string]any{"available": true, "min_password_length": max(10, s.provisioner.MinPasswordLength), "mailbox_admin": s.provisioner.Mailbox != nil})
	}).Methods("GET")
	s.provisionPolicyRoutes(protected)
	protected.HandleFunc("/accounts", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if r.Method == "GET" {
			accounts, err := s.provisioner.List(ctx)
			if err != nil {
				return err
			}
			writeJSON(w, map[string]any{"accounts": accounts})
			return nil
		}
		var in provision.Create
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		account, err := s.provisioner.Create(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "create", account.Address)
		writeJSONStatus(w, http.StatusCreated, account)
		return nil
	})).Methods("GET", "POST")
	protected.HandleFunc("/accounts/{address}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		address := mux.Vars(r)["address"]
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
			s.provisionAudit(r, "update", account.Address)
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
			s.provisionAudit(r, "delete", address)
			if !in.Purge {
				writeJSON(w, map[string]any{"status": "Account removed; its mailbox is retained."})
				return nil
			}
			result, err := s.provisioner.Purge(ctx, address)
			if err != nil {
				return err
			}
			s.provisionAudit(r, "purge", address)
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
		if err := s.provisioner.Password(ctx, address, in.Password); err != nil {
			return err
		}
		s.provisionAudit(r, "reset-password", address)
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
		account, err := s.provisioner.Alias(ctx, mux.Vars(r)["address"], in.Alias, r.Method == "POST")
		if err != nil {
			return err
		}
		s.provisionAudit(r, "alias-"+r.Method, account.Address)
		writeJSON(w, account)
		return nil
	})).Methods("POST", "DELETE")
	protected.HandleFunc("/domains", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if r.Method == "GET" {
			domains, err := s.provisioner.Domains(ctx)
			if err != nil {
				return err
			}
			writeJSON(w, map[string]any{"domains": domains})
			return nil
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
		s.provisionAudit(r, "domain-"+r.Method, in.Name)
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
func (s *Server) provisionAudit(r *http.Request, action, target string) {
	actor := ""
	if ac := GetAuthContext(r); ac != nil {
		actor = ac.Username
	}
	slog.Info("Mailbox administration", "actor", actor, "action", action, "target", target)
}
