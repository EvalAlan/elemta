package api

// Account support: the jobs that come with "I can't get into my mail". Every
// route is limited to the caller's domains and every change is audited.

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

// supportAccount is the account in the path. It must be named by its primary
// address: an alias in an assigned domain may point at an account in another
// one, and these routes change how that account signs in.
func (s *Server) supportAccount(ctx context.Context, r *http.Request) (provision.Account, error) {
	raw := mux.Vars(r)["address"]
	if err := scopeOf(r).checkAddress(raw); err != nil {
		return provision.Account{}, err
	}
	address, err := provision.Address(raw)
	if err != nil {
		return provision.Account{}, err
	}
	account, err := s.provisioner.Get(ctx, address)
	if err != nil {
		return provision.Account{}, err
	}
	if !strings.EqualFold(account.Address, address) {
		return provision.Account{}, fmt.Errorf("%w: use the account's primary address", provision.ErrInvalid)
	}
	account.Address = address
	return account, nil
}

func (s *Server) provisionSupportRoutes(protected *mux.Router) {
	protected.HandleFunc("/usage", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		all, err := c.Usage(ctx)
		if err != nil {
			return err
		}
		sc := scopeOf(r)
		visible := []mailpolicy.Usage{}
		for _, u := range all {
			if sc.address(u.Address) {
				visible = append(visible, u)
			}
		}
		writeJSON(w, map[string]any{"usage": visible})
		return nil
	})).Methods("GET")

	protected.HandleFunc("/accounts/{address}/security", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		out, err := c.AccountSecurity(ctx, account.Address)
		if err != nil {
			return err
		}
		// The mailbox can't read a disabled account's directory quota.
		if account.Status == "disabled" && out.QuotaBytes == 0 {
			out.QuotaBytes = account.QuotaBytes
		}
		writeJSON(w, out)
		return nil
	})).Methods("GET")

	protected.HandleFunc("/accounts/{address}/reset-two-factor", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		if err := s.provisioner.ResetTwoFactor(ctx, account.Address); err != nil {
			return err
		}
		s.provisionAudit(r, "two-factor-reset", account.Address, "")
		writeJSON(w, map[string]bool{"ok": true})
		return nil
	})).Methods("POST")

	protected.HandleFunc("/accounts/{address}/app-passwords", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		n, err := c.RevokeAppPasswords(ctx, account.Address)
		if err != nil {
			return err
		}
		s.provisionAudit(r, "app-password-revoke", account.Address, fmt.Sprintf("all (%d)", n))
		writeJSON(w, map[string]int64{"revoked": n})
		return nil
	})).Methods("DELETE")

	protected.HandleFunc("/accounts/{address}/app-passwords/{id}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
		if err != nil {
			return provision.ErrInvalid
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		if err := c.RevokeAppPassword(ctx, account.Address, id); err != nil {
			return err
		}
		s.provisionAudit(r, "app-password-revoke", account.Address, fmt.Sprintf("id %d", id))
		writeJSON(w, map[string]bool{"ok": true})
		return nil
	})).Methods("DELETE")

	protected.HandleFunc("/accounts/{address}/shares", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		shares, err := s.provisioner.Shares(ctx, account.Address)
		if err != nil {
			return err
		}
		writeJSON(w, shares)
		return nil
	})).Methods("GET")

	protected.HandleFunc("/accounts/{address}/shares/{member}", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		account, err := s.supportAccount(ctx, r)
		if err != nil {
			return err
		}
		member, err := provision.Address(mux.Vars(r)["member"])
		if err != nil {
			return err
		}
		if err := scopeOf(r).checkAddress(member); err != nil {
			return err
		}
		if r.Method == "DELETE" {
			if err := s.provisioner.RevokeShare(ctx, account.Address, member); err != nil {
				return err
			}
			s.provisionAudit(r, "mailbox-share-remove", account.Address, member)
			writeJSON(w, map[string]bool{"ok": true})
			return nil
		}
		var in struct {
			CanSend bool `json:"can_send"`
		}
		if !decodeJSONBody(w, r, &in) {
			return nil
		}
		share, err := s.provisioner.GrantShare(ctx, account.Address, member, in.CanSend)
		if err != nil {
			return err
		}
		detail := member + " read"
		if in.CanSend {
			detail = member + " read and send"
		}
		s.provisionAudit(r, "mailbox-share", account.Address, detail)
		writeJSON(w, share)
		return nil
	})).Methods("PUT", "DELETE")
}
