package mailbox

// The admin API: classes of service, domain and account policy, effective
// policy for enforcement elsewhere, and purging an account's data.
//
// It is served on the health port beside the account-security API, and like
// it refuses clients outside lmtp_allowed_networks. Unlike it, a request
// carries no user's credentials: it acts on any account. So it also needs
// the shared admin token (mailpolicy.TokenEnv), which only the MTA and the
// administration tools are given. Without a token configured the API is
// off, and every request gets 404, as if it didn't exist.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func (s *Service) adminAPI(mux *http.ServeMux) {
	handle := func(pattern string, fn func(*http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if s.adminToken == "" {
				http.NotFound(w, r)
				return
			}
			if !s.internalClient(r) {
				writeAdminError(w, http.StatusForbidden, "forbidden")
				return
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="mailbox-admin"`)
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			// Purging a large mailbox deletes many rows; everything else is
			// quick.
			ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
			defer cancel()
			out, err := fn(r.WithContext(ctx))
			if err != nil {
				status, msg := adminStatus(err)
				if status == http.StatusInternalServerError {
					s.log.Warn("mailbox admin API", "path", r.URL.Path, "error", err)
				}
				writeAdminError(w, status, msg)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	decode := func(r *http.Request, v any) error {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			return errors.Join(mailpolicy.ErrInvalid, err)
		}
		return nil
	}

	handle("GET /v1/admin/classes", func(r *http.Request) (any, error) {
		return s.engine.Classes(r.Context())
	})
	handle("GET /v1/admin/classes/{name}", func(r *http.Request) (any, error) {
		return s.engine.Class(r.Context(), r.PathValue("name"))
	})
	handle("PUT /v1/admin/classes/{name}", func(r *http.Request) (any, error) {
		var c mailpolicy.Class
		if err := decode(r, &c); err != nil {
			return nil, err
		}
		c.Name = r.PathValue("name")
		return s.engine.PutClass(r.Context(), c)
	})
	handle("DELETE /v1/admin/classes/{name}", func(r *http.Request) (any, error) {
		return map[string]bool{"ok": true}, s.engine.DeleteClass(r.Context(), r.PathValue("name"))
	})
	handle("GET /v1/admin/domains", func(r *http.Request) (any, error) {
		return s.engine.Domains(r.Context())
	})
	handle("PUT /v1/admin/domains/{domain}", func(r *http.Request) (any, error) {
		var d mailpolicy.DomainPolicy
		if err := decode(r, &d); err != nil {
			return nil, err
		}
		d.Domain = r.PathValue("domain")
		return s.engine.SetDomain(r.Context(), d)
	})
	handle("GET /v1/admin/accounts/{address}/policy", func(r *http.Request) (any, error) {
		a, err := s.directoryAccount(r.Context(), r.PathValue("address"))
		if err != nil {
			return nil, err
		}
		return s.accountView(r.Context(), a)
	})
	handle("PUT /v1/admin/accounts/{address}/policy", func(r *http.Request) (any, error) {
		a, err := s.directoryAccount(r.Context(), r.PathValue("address"))
		if err != nil {
			return nil, err
		}
		var p mailpolicy.AccountPolicy
		if err := decode(r, &p); err != nil {
			return nil, err
		}
		p.Address = a.Address
		if err := s.engine.PutAccountPolicy(r.Context(), p); err != nil {
			return nil, err
		}
		return s.accountView(r.Context(), a)
	})
	handle("GET /v1/admin/effective", func(r *http.Request) (any, error) {
		a, err := s.resolveLogin(r.Context(), r.URL.Query().Get("address"))
		if err != nil {
			return nil, err
		}
		return s.engine.EffectivePolicy(r.Context(), a.Address, a.Quota)
	})
	handle("POST /v1/admin/accounts/{address}/purge", func(r *http.Request) (any, error) {
		address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
		if !strings.Contains(address, "@") || len(address) > 320 {
			return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("enter the account's primary address"))
		}
		// Purging the data of an account that still exists would empty a
		// live mailbox; deleting it from the directory first is the
		// deliberate step that makes this safe.
		exists, err := s.auth.Exists(r.Context(), address)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.Join(ErrInUse, errors.New("the account still exists in the directory; delete it first"))
		}
		res, err := s.engine.PurgeAccount(r.Context(), address)
		if err == nil {
			s.log.Info("mailbox account purged", "address", address, "accounts", res.Accounts, "folders", res.Folders, "messages", res.Messages)
		}
		return res, err
	})
}

// directoryAccount finds the account an administrator names, which must be
// its primary address: policy is keyed by it, and accepting an alias would
// quietly store policy somewhere nothing reads it.
func (s *Service) directoryAccount(ctx context.Context, address string) (Account, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	a, err := s.auth.Resolve(ctx, address)
	if errors.Is(err, ErrCredentials) {
		exists, existsErr := s.auth.Exists(ctx, address)
		if existsErr == nil && exists {
			// A disabled account still has a policy to manage.
			return Account{Address: address}, nil
		}
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if a.Address != address {
		return Account{}, errors.Join(mailpolicy.ErrInvalid, errors.New(address+" is an alias of "+a.Address+"; use the primary address"))
	}
	return a, nil
}

// resolveLogin finds the account behind an address or login name, as mail
// protocols do, aliases and the default domain included.
func (s *Service) resolveLogin(ctx context.Context, user string) (Account, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	if !strings.Contains(user, "@") && s.cfg.Auth.DefaultDomain != "" {
		user += "@" + s.cfg.Auth.DefaultDomain
	}
	if user == "" || len(user) > 320 {
		return Account{}, ErrNotFound
	}
	a, err := s.auth.Resolve(ctx, user)
	if errors.Is(err, ErrCredentials) {
		return Account{}, ErrNotFound
	}
	return a, err
}

func (s *Service) accountView(ctx context.Context, a Account) (mailpolicy.AccountView, error) {
	p, err := s.engine.AccountPolicy(ctx, a.Address)
	if err != nil {
		return mailpolicy.AccountView{}, err
	}
	eff, err := s.engine.EffectivePolicy(ctx, a.Address, a.Quota)
	return mailpolicy.AccountView{Policy: p, Effective: eff}, err
}

func adminStatus(err error) (int, string) {
	switch {
	case errors.Is(err, mailpolicy.ErrInvalid):
		return http.StatusBadRequest, adminMessage(err)
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, adminMessage(err)
	case errors.Is(err, ErrInUse):
		return http.StatusConflict, adminMessage(err)
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "timed out"
	}
	return http.StatusInternalServerError, "unavailable"
}

// adminMessage is the most specific line of an error: errors.Join puts the
// sentinel first and the explanation after it.
func adminMessage(err error) string {
	lines := strings.Split(err.Error(), "\n")
	return lines[len(lines)-1]
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
