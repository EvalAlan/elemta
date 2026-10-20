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
	"io"
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
			limit := int64(64 << 10)
			if strings.HasSuffix(r.URL.Path, "/messages") {
				limit = s.engine.MaxBytes + 1
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
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
	handle("GET /v1/admin/routes", func(r *http.Request) (any, error) {
		return s.engine.Routes(r.Context())
	})
	handle("PUT /v1/admin/routes/{domain}", func(r *http.Request) (any, error) {
		var route mailpolicy.DomainRoute
		if err := decode(r, &route); err != nil {
			return nil, err
		}
		route.Domain = r.PathValue("domain")
		return s.engine.SetRoute(r.Context(), route)
	})
	handle("GET /v1/admin/lists", func(r *http.Request) (any, error) {
		return s.engine.Lists(r.Context())
	})
	handle("GET /v1/admin/lists/{address}", func(r *http.Request) (any, error) {
		return s.engine.List(r.Context(), r.PathValue("address"))
	})
	handle("PUT /v1/admin/lists/{address}", func(r *http.Request) (any, error) {
		var l mailpolicy.List
		if err := decode(r, &l); err != nil {
			return nil, err
		}
		l.Address = strings.ToLower(strings.TrimSpace(r.PathValue("address")))
		// A list can't take an address an account or alias already has:
		// mail to it would quietly go one way or the other.
		if taken, err := s.auth.Exists(r.Context(), l.Address); err != nil || taken {
			if err != nil {
				return nil, err
			}
			return nil, errors.Join(ErrInUse, errors.New(l.Address+" belongs to an account or alias"))
		}
		return s.engine.PutList(r.Context(), l)
	})
	handle("POST /v1/admin/lists/{address}/members", func(r *http.Request) (any, error) {
		var in struct{ Add, Remove []string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.engine.ChangeMembers(r.Context(), r.PathValue("address"), in.Add, in.Remove)
	})
	handle("DELETE /v1/admin/lists/{address}", func(r *http.Request) (any, error) {
		return map[string]bool{"ok": true}, s.engine.DeleteList(r.Context(), r.PathValue("address"))
	})
	handle("POST /v1/admin/accounts/{address}/messages", func(r *http.Request) (any, error) {
		return s.importMessage(r)
	})
	mux.HandleFunc("GET /v1/admin/accounts/{address}/held", func(w http.ResponseWriter, r *http.Request) {
		// Streams mbox, so it bypasses the JSON wrapper but not its checks.
		if s.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !s.internalClient(r) || !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
			writeAdminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
		w.Header().Set("Content-Type", "application/mbox")
		w.Header().Set("Cache-Control", "no-store")
		n, err := s.engine.ExportHeld(r.Context(), address, w)
		if err != nil {
			s.log.Warn("held mail export failed", "address", address, "exported", n, "error", err)
			return
		}
		s.log.Info("held mail exported", "address", address, "messages", n)
	})
	handle("GET /v1/admin/addresses/{address}", func(r *http.Request) (any, error) {
		return s.addressInfo(r.Context(), r.PathValue("address"))
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
		// So does a deleted one whose mailbox is kept, a legal hold most
		// of all: lifting it is what lets the mailbox be purged.
		var kept bool
		if err := s.engine.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_accounts WHERE address=$1)`, address).Scan(&kept); err == nil && kept {
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
	if err != nil {
		return mailpolicy.AccountView{}, err
	}
	held, err := s.engine.HeldCount(ctx, a.Address)
	return mailpolicy.AccountView{Policy: p, Effective: eff, Held: held}, err
}

func adminStatus(err error) (int, string) {
	switch {
	case errors.Is(err, mailpolicy.ErrInvalid):
		return http.StatusBadRequest, adminMessage(err)
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, adminMessage(err)
	case errors.Is(err, ErrInUse):
		return http.StatusConflict, adminMessage(err)
	case errors.Is(err, ErrTooLarge):
		return http.StatusRequestEntityTooLarge, adminMessage(err)
	case errors.Is(err, ErrQuota):
		return http.StatusInsufficientStorage, "the mailbox is over its quota"
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

// addressInfo says what owns an address, so the provisioning tools can keep
// accounts, aliases and lists from taking each other's addresses.
func (s *Service) addressInfo(ctx context.Context, raw string) (mailpolicy.AddressInfo, error) {
	address, err := normalAddress(raw)
	if err != nil {
		return mailpolicy.AddressInfo{}, err
	}
	info := mailpolicy.AddressInfo{Address: address}
	if a, err := s.auth.Resolve(ctx, address); err == nil {
		info.Kind, info.Account = "alias", a.Address
		if a.Address == address {
			info.Kind = "account"
		}
		return info, nil
	} else if !errors.Is(err, ErrCredentials) {
		return info, err
	}
	if exists, err := s.auth.Exists(ctx, address); err != nil {
		return info, err
	} else if exists {
		info.Kind = "account" // disabled: Resolve won't say which
		return info, nil
	}
	if isList, err := s.engine.isList(ctx, address); err != nil {
		return info, err
	} else if isList {
		info.Kind = "list"
	}
	return info, nil
}

// importMessage stores one message from a migration (internal/migrate) in
// an account's folder, with its original flags and date. The caller names
// each message with a key (its source and UID); the key becomes the
// delivery token, so importing the same message again, after an
// interrupted run, stores nothing new. Folders are created as needed.
// Quota applies as for any delivery: a migration that doesn't fit stops
// with a clear refusal rather than quietly overfilling the mailbox.
func (s *Service) importMessage(r *http.Request) (any, error) {
	a, err := s.directoryAccount(r.Context(), r.PathValue("address"))
	if err != nil {
		return nil, err
	}
	if a.ID == "" {
		return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("the account is disabled; enable it to import into it"))
	}
	q := r.URL.Query()
	folder := strings.TrimSpace(q.Get("folder"))
	if folder == "" {
		folder = "INBOX"
	}
	if !validMailbox(folder) {
		return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("invalid folder name"))
	}
	key := q.Get("key")
	if key == "" || len(key) > 1024 {
		return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("each imported message needs a key naming its source"))
	}
	var date time.Time
	if v := q.Get("date"); v != "" {
		if date, err = time.Parse(time.RFC3339, v); err != nil {
			return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("date must be RFC 3339"))
		}
	}
	var flags []string
	for _, f := range strings.Split(q.Get("flags"), ",") {
		if f = strings.TrimSpace(f); f != "" && !strings.EqualFold(f, `\Recent`) && len(f) <= 100 && !strings.ContainsAny(f, " ()\r\n") {
			flags = append(flags, f)
		}
	}
	raw, err := io.ReadAll(r.Body)
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) || int64(len(raw)) > s.engine.MaxBytes {
		return nil, errors.Join(ErrTooLarge, errors.New("message is larger than the mailbox accepts"))
	}
	if err != nil {
		return nil, err
	}
	if err := s.applyPolicy(r.Context(), &a); err != nil {
		return nil, err
	}
	if err := s.engine.EnsureAccount(r.Context(), a); err != nil {
		return nil, err
	}
	if folder != "INBOX" {
		if err := s.engine.Create(r.Context(), a.ID, folder); err != nil && !errors.Is(err, ErrExists) {
			return nil, err
		}
	}
	token := "import:" + sum(key)
	var seen bool
	if err := s.engine.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM mailbox_deliveries WHERE account=$1 AND token=$2)`, a.ID, token).Scan(&seen); err != nil {
		return nil, err
	}
	res, err := s.engine.Append(r.Context(), a.ID, folder, raw, flags, date, token)
	if errors.Is(err, ErrConflict) {
		return nil, errors.Join(ErrInUse, errors.New("a different message was already imported under this key"))
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"uid": res.UID, "uidvalidity": res.Validity, "folder": folder, "duplicate": seen}, nil
}
