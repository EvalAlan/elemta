package api

// Dashboard routes for classes of service, account policy, purging, and
// distribution lists, domain aliases and catch-alls. They sit under the same
// /api/provision prefix and the same administrator check as the account
// routes (provision.go), and go through the provisioning service, so the
// dashboard applies exactly the checks the CLI does.

import (
	"context"
	"encoding/json"
	"fmt"
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
		// Domain administrators see the classes (to assign them) but only
		// their own domains' defaults.
		sc := scopeOf(r)
		visible := []mailpolicy.DomainPolicy{}
		for _, d := range domains {
			if sc.domain(d.Domain) {
				visible = append(visible, d)
			}
		}
		writeJSON(w, map[string]any{"classes": classes, "domains": visible, "protocols": mailpolicy.Protocols})
		return nil
	})).Methods("GET")
	protected.HandleFunc("/classes/{name}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		if err := scopeOf(r).systemOnly(); err != nil {
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
			s.provisionAudit(r, "class-save", name, summarizeSettings(in.Settings))
			writeJSON(w, out)
		case "DELETE":
			if err := c.DeleteClass(ctx, name); err != nil {
				return err
			}
			s.provisionAudit(r, "class-delete", name, "")
			writeJSON(w, map[string]any{"status": "Class of service deleted."})
		}
		return nil
	})).Methods("PUT", "DELETE")
	protected.HandleFunc("/domains/{domain}/class", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := admin()
		if err != nil {
			return err
		}
		if err := scopeOf(r).systemOnly(); err != nil {
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
		s.provisionAudit(r, "domain-class", domain, "class "+orDefault(in.Class))
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
		if err := scopeOf(r).checkDomain(domain); err != nil {
			return err
		}
		out, err := s.provisioner.CatchAll(ctx, domain, in.Address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "catch-all", domain, in.Address)
		writeJSON(w, out)
		return nil
	})).Methods("PUT")
	protected.HandleFunc("/domain-aliases", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := scopeOf(r).systemOnly(); err != nil {
			return err
		}
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
		if r.Method == "POST" {
			s.provisionAudit(r, "domain-alias-add", in.Alias, "delivers as "+in.Target)
		} else {
			s.provisionAudit(r, "domain-alias-remove", in.Alias, "")
		}
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
		sc := scopeOf(r)
		if err := sc.checkAddress(address); err != nil {
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
		if !sc.all {
			// A domain administrator assigns classes; the per-account
			// overrides stay as a system administrator left them. Nor can
			// they move an account off a legal hold by giving it a class
			// without one.
			current, err := c.Account(ctx, address)
			if err != nil {
				return err
			}
			if current.Effective.LegalHold {
				return fmt.Errorf("%w: %s is on legal hold; only a system administrator can change its class", errOutOfScope, address)
			}
			in.Settings = current.Policy.Settings
		}
		view, err := c.PutAccount(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "account-policy", address, "class "+orDefault(in.Class)+"; overrides: "+summarizeSettings(in.Settings))
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
		if err := scopeOf(r).checkAddress(in.Address); err != nil {
			return err
		}
		out, err := s.provisioner.Purge(ctx, in.Address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "account-purge", in.Address, fmt.Sprintf("%d messages", out.Messages))
		writeJSON(w, out)
		return nil
	})).Methods("POST")
	protected.HandleFunc("/lists", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		sc := scopeOf(r)
		if r.Method == "GET" {
			lists, err := s.provisioner.Lists(ctx)
			if err != nil {
				return err
			}
			writeJSON(w, map[string]any{"lists": filterLists(sc, lists), "posting": mailpolicy.PostingPolicies})
			return nil
		}
		var in mailpolicy.List
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		if err := sc.checkAddress(in.Address); err != nil {
			return err
		}
		if _, err := s.provisioner.GetList(ctx, in.Address); err == nil {
			return provision.ErrExists
		}
		out, err := s.provisioner.PutList(ctx, in)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "list-create", out.Address, fmt.Sprintf("%d members, posting %s", len(out.Members), out.Posting))
		writeJSONStatus(w, http.StatusCreated, out)
		return nil
	})).Methods("GET", "POST")
	protected.HandleFunc("/lists/{address}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		address := mux.Vars(r)["address"]
		if err := scopeOf(r).checkAddress(address); err != nil {
			return err
		}
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
			s.provisionAudit(r, "list-update", address, fmt.Sprintf("%d members, posting %s", len(out.Members), out.Posting))
			writeJSON(w, out)
		case "DELETE":
			if err := s.provisioner.DeleteList(ctx, address); err != nil {
				return err
			}
			s.provisionAudit(r, "list-delete", address, "")
			writeJSON(w, map[string]any{"status": "Distribution list deleted."})
		}
		return nil
	})).Methods("GET", "PUT", "DELETE")
}

func orDefault(class string) string {
	if class == "" {
		return "(default)"
	}
	return class
}

// summarizeSettings is the settings a class or account sets, as JSON with
// the unset ones left out, for the audit log.
func summarizeSettings(s mailpolicy.Settings) string {
	data, err := json.Marshal(s)
	if err != nil || string(data) == "{}" {
		return "none"
	}
	return string(data)
}
