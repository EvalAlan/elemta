package mailbox

// The internal account-security API the webmail uses (see security.go).
//
// It is served on the health port, which is never published, and refuses
// clients outside lmtp_allowed_networks, the same internal networks that may
// deliver mail. Every request carries the user's own credentials as HTTP
// Basic authentication, so the webmail holds no privilege of its own here:
// it can change only the account whose password it was given, which it has
// because that user is signed in. Settings are changed only with the account
// password, never an app password, so an app password leaked from a mail app
// can't remove the protection it is part of.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type securityAuth struct {
	account Account
	app     bool
	// admin is an administrator access token (admin_access.go), with the
	// administrator's name. Only the check accepts one.
	admin   string
	expires time.Time
}

func (s *Service) securityAPI(mux *http.ServeMux) {
	handle := func(pattern string, allowApp bool, fn func(http.ResponseWriter, *http.Request, securityAuth) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.internalClient(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			user, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="mailbox"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			limit := int64(4096)
			if r.URL.Path == "/v1/freebusy" {
				limit = 1 << 20 // a year of busy times
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			auth, err := s.securityLogin(ctx, user, password)
			if err == nil && auth.app && !allowApp {
				err = ErrCredentials
			}
			if err == nil && auth.admin != "" && pattern != "POST /v1/security/check" {
				err = ErrCredentials
			}
			if err != nil {
				writeSecurityError(w, err)
				return
			}
			out, err := fn(w, r.WithContext(ctx), auth)
			if err != nil {
				writeSecurityError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(r.Body).Decode(v); err != nil {
			return errBadRequest
		}
		return nil
	}

	// check tells the webmail how a sign-in that IMAP accepted must proceed.
	handle("POST /v1/security/check", true, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		if err != nil {
			return nil, err
		}
		kind := "password"
		if a.app {
			kind = "app"
		}
		if a.admin != "" {
			// Neither the MTA nor DAV accepts this kind; the webmail shows
			// whose session it is.
			kind = "admin"
		}
		// The class of service's switches travel with the answer: the
		// webmail applies webmail, DAV and two-step verification, and the
		// MTA submission. A class that requires app passwords counts as the
		// user having chosen it.
		out := map[string]any{"kind": kind, "totp": st.TOTP, "app_required": st.AppRequired, "account_id": a.account.ID}
		if a.admin != "" {
			out["administrator"] = a.admin
			out["expires"] = a.expires
		}
		if p := a.account.Policy; p != nil {
			out["app_required"] = st.AppRequired || p.RequireAppPasswords
			out["protocols"] = p.Protocols
			out["require_two_factor"] = p.RequireTwoFactor
			out["filters"] = p.Filters
		}
		return out, nil
	})
	// The address book of the user's own domain, for address autocomplete.
	handle("GET /v1/directory", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.directory(r.Context(), a.account.Address)
	})
	handle("GET /v1/security/shares", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.SharesForMember(r.Context(), a.account.ID)
	})
	// Free/busy: the webmail publishes the user's own busy times and reads
	// colleagues'.
	handle("PUT /v1/freebusy", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var fb FreeBusy
		if err := decode(r, &fb); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.PublishFreeBusy(r.Context(), a.account, fb)
	})
	handle("GET /v1/freebusy", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		q := r.URL.Query()
		from, err1 := time.Parse(time.RFC3339, q.Get("from"))
		to, err2 := time.Parse(time.RFC3339, q.Get("to"))
		if err1 != nil || err2 != nil {
			return nil, errBadFreeBusy
		}
		return s.freeBusy(r.Context(), a.account, q["address"], from, to)
	})
	handle("GET /v1/security", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		if p := a.account.Policy; err == nil && p != nil {
			st.AppRequiredByClass, st.TOTPRequired = p.RequireAppPasswords, p.RequireTwoFactor
		}
		return st, err
	})
	handle("POST /v1/security/verify", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		recovery, err := s.engine.VerifySecondFactor(r.Context(), a.account.ID, in.Code, time.Now())
		if errors.Is(err, ErrBadCode) {
			s.failLogin(key)
		}
		if err != nil {
			return nil, err
		}
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		return map[string]any{"recovery": recovery, "recovery_left": st.RecoveryLeft}, err
	})
	handle("POST /v1/security/totp/begin", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Issuer string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if in.Issuer == "" || len(in.Issuer) > 64 {
			in.Issuer = "Elemta Mail"
		}
		secret, uri, err := s.engine.BeginTOTP(r.Context(), a.account.ID, a.account.Address, in.Issuer)
		return map[string]string{"secret": secret, "uri": uri}, err
	})
	handle("POST /v1/security/totp/confirm", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		codes, err := s.engine.ConfirmTOTP(r.Context(), a.account.ID, in.Code, time.Now())
		if errors.Is(err, ErrBadCode) {
			s.failLogin(key)
		}
		return map[string]any{"recovery_codes": codes}, err
	})
	handle("POST /v1/security/totp/disable", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		if p := a.account.Policy; p != nil && p.RequireTwoFactor {
			return nil, &requestError{"two-step verification is required for this account"}
		}
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		if _, err := s.engine.VerifySecondFactor(r.Context(), a.account.ID, in.Code, time.Now()); err != nil {
			if errors.Is(err, ErrBadCode) {
				s.failLogin(key)
			}
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.DisableTOTP(r.Context(), a.account.ID)
	})
	handle("POST /v1/security/app-passwords", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Name string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		p, password, err := s.engine.CreateAppPassword(r.Context(), a.account.ID, in.Name)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, &requestError{err.Error()}
		}
		return map[string]any{"app_password": p, "password": password}, nil
	})
	handle("POST /v1/security/app-passwords/{id}/delete", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, errBadRequest
		}
		return map[string]bool{"ok": true}, s.engine.DeleteAppPassword(r.Context(), a.account.ID, id)
	})
	handle("POST /v1/security/app-required", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Required bool }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.SetAppPasswordsRequired(r.Context(), a.account.ID, in.Required)
	})
}

type requestError struct{ msg string }

func (e *requestError) Error() string { return e.msg }

var (
	errBadRequest = &requestError{"bad request"}
	errLimited    = errors.New("too many attempts")
)

func writeSecurityError(w http.ResponseWriter, err error) {
	var re *requestError
	switch {
	case errors.Is(err, ErrCredentials):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, ErrBadCode):
		http.Error(w, "invalid code", http.StatusUnprocessableEntity)
	case errors.Is(err, ErrTOTPActive):
		http.Error(w, "two-step verification is already enabled", http.StatusConflict)
	case errors.Is(err, errLimited):
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.As(err, &re):
		http.Error(w, re.msg, http.StatusBadRequest)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

// internalClient admits the internal networks only. The health port is
// never published, so this is the second of two barriers.
func (s *Service) internalClient(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range s.internalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// securityLogin authenticates an API request with the shared failure limit:
// an app password first (one indexed lookup), then the account password.
func (s *Service) securityLogin(ctx context.Context, user, password string) (securityAuth, error) {
	if strings.HasPrefix(password, adminTokenPrefix) {
		a, actor, expires, err := s.adminLogin(ctx, user, password)
		return securityAuth{account: a, admin: actor, expires: expires}, err
	}
	a, app, err := s.authenticate(ctx, user, password)
	return securityAuth{account: a, app: app}, err
}
