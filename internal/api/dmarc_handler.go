package api

// Received DMARC reports. Domain administrators read their own domains';
// choosing an address and reading a mailbox's old reports are for system
// administrators, since both reach into mail.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/gorilla/mux"
)

const (
	dmarcDefaultWindow = 30
	dmarcMaxWindow     = 400
)

// dmarcSelection is the domains and days a read covers, within the caller's
// scope. No domains means all, which only a system administrator gets.
func dmarcSelection(r *http.Request) ([]string, int, error) {
	sc, q := scopeOf(r), r.URL.Query()
	days := dmarcDefaultWindow
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > dmarcMaxWindow {
			return nil, 0, fmt.Errorf("%w: days is 1 to %d", provision.ErrInvalid, dmarcMaxWindow)
		}
		days = n
	}
	if v := q.Get("domain"); v != "" {
		domain, err := provision.DomainName(v)
		if err != nil {
			return nil, 0, err
		}
		if err := sc.checkDomain(domain); err != nil {
			return nil, 0, err
		}
		return []string{domain}, days, nil
	}
	if sc.all {
		return nil, days, nil
	}
	if len(sc.domains) == 0 {
		return nil, 0, errOutOfScope
	}
	return sc.domains, days, nil
}

func (s *Server) dmarcRoutes(protected *mux.Router) {
	protected.HandleFunc("/dmarc/addresses", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		all, err := c.DMARCAddresses(ctx)
		if err != nil {
			return err
		}
		sc, visible := scopeOf(r), []mailpolicy.DMARCAddress{}
		for _, a := range all {
			if sc.domain(a.Domain) {
				visible = append(visible, a)
			}
		}
		writeJSON(w, map[string]any{"addresses": visible})
		return nil
	})).Methods("GET")

	protected.HandleFunc("/dmarc/addresses/{domain}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := scopeOf(r).systemOnly(); err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		if r.Method == "DELETE" {
			// Not only a configured domain: one that was removed still needs
			// unregistering.
			domain, err := provision.DomainName(mux.Vars(r)["domain"])
			if err != nil {
				return err
			}
			if err := c.DeleteDMARCAddress(ctx, domain); err != nil {
				return err
			}
			s.provisionAudit(r, "dmarc-address-remove", domain, "")
			writeJSON(w, map[string]bool{"ok": true})
			return nil
		}
		domain, err := s.configuredDomain(ctx, r)
		if err != nil {
			return err
		}
		var in struct {
			Address string `json:"address"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		address, err := provision.Address(in.Address)
		if err != nil {
			return err
		}
		domains, err := s.provisioner.Domains(ctx)
		if err != nil {
			return err
		}
		_, host, _ := strings.Cut(address, "@")
		local := false
		for _, d := range domains {
			local = local || d.Configured && d.Name == host
		}
		if !local {
			return fmt.Errorf("%w: reports can only be read from an address on this server", provision.ErrInvalid)
		}
		out, err := c.SetDMARCAddress(ctx, domain, address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "dmarc-address", domain, address)
		writeJSON(w, out)
		return nil
	})).Methods("PUT", "DELETE")

	protected.HandleFunc("/dmarc/addresses/{domain}/backfill", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := scopeOf(r).systemOnly(); err != nil {
			return err
		}
		domain, err := s.configuredDomain(ctx, r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		addresses, err := c.DMARCAddresses(ctx)
		if err != nil {
			return err
		}
		address := ""
		for _, a := range addresses {
			if a.Domain == domain {
				address = a.Address
			}
		}
		if address == "" {
			return fmt.Errorf("%w: choose the domain's report address first", provision.ErrInvalid)
		}
		// It reads someone's mailbox, so it is recorded first or not done.
		entry := mailpolicy.AuditEntry{Actor: GetAuthContext(r).Username, Source: "dashboard", Client: s.loginAddr(r), Action: "dmarc-backfill", Target: domain, Detail: "reading reports sent to " + address}
		if err := s.provisioner.Audit(ctx, entry); err != nil {
			http.Error(w, errNotRecorded.Error(), http.StatusServiceUnavailable)
			return nil
		}
		if err := c.StartDMARCBackfill(ctx, domain); err != nil {
			return err
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]bool{"started": true})
		return nil
	})).Methods("POST")

	protected.HandleFunc("/dmarc/summary", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		domains, days, err := dmarcSelection(r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		out, err := c.DMARCSummary(ctx, domains, days)
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"days": days, "summary": out})
		return nil
	})).Methods("GET")

	protected.HandleFunc("/dmarc/sources", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		domains, days, err := dmarcSelection(r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		out, err := c.DMARCSources(ctx, domains, days)
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"days": days, "sources": out})
		return nil
	})).Methods("GET")
}
