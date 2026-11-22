package mailbox

// The account support side of the admin API (mailpolicy/support.go).

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Usage is the storage held under each address. An account being moved is
// read-only in the cell it leaves until that copy is purged, so counting
// only writable rows keeps a move from showing as twice the mail.
func (e *Engine) Usage(ctx context.Context) ([]mailpolicy.Usage, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT address, sum(used_bytes)::bigint FROM mailbox_accounts WHERE writable GROUP BY address ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.Usage{}
	for rows.Next() {
		var u mailpolicy.Usage
		if err := rows.Scan(&u.Address, &u.UsedBytes); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Service) accountSecurity(ctx context.Context, address string) (mailpolicy.AccountSecurity, error) {
	out := mailpolicy.AccountSecurity{AppPasswords: []mailpolicy.AppPassword{}}
	a, err := s.directoryAccount(ctx, address)
	if err != nil {
		return out, err
	}
	effective, err := s.engine.EffectivePolicy(ctx, a.Address, a.Quota)
	if err != nil {
		return out, err
	}
	out.QuotaBytes = effective.QuotaBytes
	id, err := s.directoryIdentity(ctx, a.Address)
	if errors.Is(err, ErrNotFound) {
		// An account that has never signed in or received mail has no
		// identity here yet, and so nothing set up.
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := s.engine.DB.QueryRowContext(ctx, `SELECT used_bytes FROM mailbox_accounts WHERE id=$1`, id.ID).Scan(&out.UsedBytes); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	state, err := s.engine.SecurityState(ctx, id.ID)
	if err != nil {
		return out, err
	}
	out.TOTP, out.RecoveryLeft, out.AppRequired = state.TOTP, state.RecoveryLeft, state.AppRequired
	for _, p := range state.AppPasswords {
		out.AppPasswords = append(out.AppPasswords, mailpolicy.AppPassword(p))
	}
	keys, err := s.engine.Passkeys(ctx, id.ID)
	if err != nil {
		return out, err
	}
	out.Passkeys = len(keys)
	return out, nil
}

func (s *Service) supportAPI(handle func(string, func(*http.Request) (any, error))) {
	handle("GET /v1/admin/usage", func(r *http.Request) (any, error) {
		return s.engine.Usage(r.Context())
	})
	handle("GET /v1/admin/accounts/{address}/security", func(r *http.Request) (any, error) {
		return s.accountSecurity(r.Context(), r.PathValue("address"))
	})
	handle("DELETE /v1/admin/accounts/{address}/app-passwords", func(r *http.Request) (any, error) {
		a, err := s.directoryIdentity(r.Context(), r.PathValue("address"))
		if err != nil {
			return nil, err
		}
		n, err := s.engine.DeleteAllAppPasswords(r.Context(), a.ID)
		return map[string]int64{"revoked": n}, err
	})
	handle("DELETE /v1/admin/accounts/{address}/app-passwords/{id}", func(r *http.Request) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("no such app password"))
		}
		a, err := s.directoryIdentity(r.Context(), r.PathValue("address"))
		if err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.DeleteAppPassword(r.Context(), a.ID, id)
	})
}
