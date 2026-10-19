package api

// Dashboard routes for classes of service, account policy, purging, and
// distribution lists, domain aliases and catch-alls. They sit under the same
// /api/provision prefix and the same administrator check as the account
// routes (provision.go), and go through the provisioning service, so the
// dashboard applies exactly the checks the CLI does.

import (
	"context"
	"net/http"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/gorilla/mux"
)

func (s *Server) provisionPolicyRoutes(protected *mux.Router) {
	admin := func() (*mailpolicy.Client, error) { return s.provisioner.MailboxAdmin() }

	protected.HandleFunc("/classes", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		classes, err := c.Classes(ctx)
		if err != nil {
			return err
		}
		domains, err := c.Domains(ctx)
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"classes": classes, "domains": domains, "protocols": mailpolicy.Protocols})
		return nil
	})).Methods("GET")
	protected.HandleFunc("/classes/{name}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		name := mux.Vars(r)["name"]
		switch r.Method {
		case "PUT":
			var in mailpolicy.Class
			if !decodeJSONBody(w, r, &in) {
				return nil
			}
			in.Name = name
			out, err := c.PutClass(ctx, in)
			if err != nil {
				return err
			}
			s.provisionAudit(r, "class-put", name)
			writeJSON(w, out)
		case "DELETE":
			if err := c.DeleteClass(ctx, name); err != nil {
				return err
			}
			s.provisionAudit(r, "class-delete", name)
			writeJSON(w, map[string]any{"status": "Class of service deleted."})
		}
		return nil
	})).Methods("PUT", "DELETE")
	protected.HandleFunc("/domains/{domain}/class", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		var in struct {
			Class string `json:"class"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		domain := mux.Vars(r)["domain"]
		out, err := c.SetDomain(ctx, mailpolicy.DomainPolicy{Domain: domain, Class: in.Class})
		if err != nil {
			return err
		}
		s.provisionAudit(r, "domain-class", domain)
		writeJSON(w, out)
		return nil
	})).Methods("PUT")
	protected.HandleFunc("/domains/{domain}/catch-all", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Address string `json:"address"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		domain := mux.Vars(r)["domain"]
		out, err := s.provisioner.CatchAll(ctx, domain, in.Address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "catch-all", domain)
		writeJSON(w, out)
		return nil
	})).Methods("PUT")
	protected.HandleFunc("/domain-aliases", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Alias  string `json:"alias"`
			Target string `json:"target"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if _, err := s.provisioner.DomainAlias(ctx, in.Alias, in.Target, r.Method == "POST"); err != nil {
			return err
		}
		s.provisionAudit(r, "domain-alias-"+r.Method, in.Alias)
		writeJSON(w, map[string]any{"requires_restart": true, "status": "Domain alias saved. Restart the SMTP service to apply routing changes."})
		return nil
	})).Methods("POST", "DELETE")
	protected.HandleFunc("/accounts/{address}/policy", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		address, err := provision.Address(mux.Vars(r)["address"])
		if err != nil {
			return err
		}
		if r.Method == "GET" {
			view, err := c.Account(ctx, address)
			if err != nil {
				return err
			}
			writeJSON(w, view)
			return nil
		}
		var in mailpolicy.AccountPolicy
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		in.Address = address
		view, err := c.PutAccount(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "account-policy", address)
		writeJSON(w, view)
		return nil
	})).Methods("GET", "PUT")
	protected.HandleFunc("/purge", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		var in struct {
			Address string `json:"address"`
			Confirm string `json:"confirm"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if in.Confirm != in.Address {
			return provision.ErrInvalid
		}
		out, err := s.provisioner.Purge(ctx, in.Address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "purge", in.Address)
		writeJSON(w, out)
		return nil
	})).Methods("POST")
	protected.HandleFunc("/lists", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if r.Method == "GET" {
			lists, err := s.provisioner.Lists(ctx)
			if err != nil {
				return err
			}
			writeJSON(w, map[string]any{"lists": lists, "posting": mailpolicy.PostingPolicies})
			return nil
		}
		var in mailpolicy.List
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if _, err := s.provisioner.GetList(ctx, in.Address); err == nil {
			return provision.ErrExists
		}
		out, err := s.provisioner.PutList(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "list-create", out.Address)
		writeJSONStatus(w, http.StatusCreated, out)
		return nil
	})).Methods("GET", "POST")
	protected.HandleFunc("/lists/{address}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		address := mux.Vars(r)["address"]
		switch r.Method {
		case "GET":
			l, err := s.provisioner.GetList(ctx, address)
			if err != nil {
				return err
			}
			writeJSON(w, l)
		case "PUT":
			var in mailpolicy.List
			if !decodeJSONBody(w, r, &in) {
				return nil
			}
			in.Address = address
			out, err := s.provisioner.PutList(ctx, in)
			if err != nil {
				return err
			}
			s.provisionAudit(r, "list-update", address)
			writeJSON(w, out)
		case "DELETE":
			if err := s.provisioner.DeleteList(ctx, address); err != nil {
				return err
			}
			s.provisionAudit(r, "list-delete", address)
			writeJSON(w, map[string]any{"status": "Distribution list deleted."})
		}
		return nil
	})).Methods("GET", "PUT", "DELETE")
}
