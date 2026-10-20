package api

// Delegated mail administration. A system administrator manages every
// domain; a user with the domain-admin role manages only the domains listed
// in their "domain:" entries (auth.DomainScope): their accounts, aliases,
// distribution lists, catch-alls and audit entries. Classes of service,
// domain routing, alias domains and a domain's default class stay with
// system administrators, since those change mail handling for everyone or
// let a domain raise its own limits.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
)

// mailScope is what the caller may administer.
type mailScope struct {
	all     bool
	domains []string
	set     map[string]bool
}

// errOutOfScope is a request for something outside a domain administrator's
// domains, or for a system-wide setting. It answers 403.
var errOutOfScope = errors.New("outside the domains you administer")

const mailScopeKey contextKey = "mail_scope"

// requireMailAdmin lets system administrators and domain administrators in,
// and puts their scope in the request context. Unlike RequirePermission it
// re-reads a domain administrator's domains on every request, so removing a
// domain applies at once.
func (s *Server) requireMailAdmin(next http.Handler) http.Handler {
	return s.authMiddleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := GetAuthContext(r)
		scope, err := s.scopeFor(r.Context(), ac)
		if err != nil {
			s.authMiddleware.writeError(w, http.StatusForbidden, "Insufficient permissions", err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mailScopeKey, scope)))
	}))
}

func (s *Server) scopeFor(ctx context.Context, ac *AuthContext) (*mailScope, error) {
	if ac == nil {
		return nil, errors.New("not signed in")
	}
	has := func(p auth.Permission) bool {
		for _, q := range ac.Permissions {
			if q == p {
				return true
			}
		}
		return false
	}
	if has(auth.PermissionSystemAdmin) {
		return &mailScope{all: true}, nil
	}
	if !has(auth.PermissionMailDomainAdmin) || s.authSystem == nil {
		return nil, errors.New("required permission: " + string(auth.PermissionSystemAdmin) + " or " + string(auth.PermissionMailDomainAdmin))
	}
	user, err := s.authSystem.GetUser(ctx, ac.Username)
	if err != nil {
		return nil, errors.New("your account could not be read")
	}
	domains := auth.DomainScope(user.Groups)
	if len(domains) == 0 {
		return nil, errors.New("no domains are assigned to your account")
	}
	sc := &mailScope{domains: domains, set: map[string]bool{}}
	for _, d := range domains {
		sc.set[d] = true
	}
	return sc, nil
}

func scopeOf(r *http.Request) *mailScope {
	if sc, ok := r.Context().Value(mailScopeKey).(*mailScope); ok {
		return sc
	}
	return &mailScope{} // nothing: the middleware always sets one
}

func (sc *mailScope) domain(d string) bool {
	return sc.all || sc.set[strings.ToLower(strings.TrimSpace(d))]
}

func (sc *mailScope) address(a string) bool {
	if sc.all {
		return true
	}
	a = strings.ToLower(strings.TrimSpace(a))
	i := strings.LastIndexByte(a, '@')
	return i > 0 && sc.set[a[i+1:]]
}

// checkAddress refuses an address outside the caller's domains.
func (sc *mailScope) checkAddress(addresses ...string) error {
	for _, a := range addresses {
		if !sc.address(a) {
			return fmt.Errorf("%w: %s", errOutOfScope, a)
		}
	}
	return nil
}

func (sc *mailScope) checkDomain(d string) error {
	if !sc.domain(d) {
		return fmt.Errorf("%w: %s", errOutOfScope, d)
	}
	return nil
}

// systemOnly refuses domain administrators.
func (sc *mailScope) systemOnly() error {
	if !sc.all {
		return fmt.Errorf("%w: only a system administrator can change this", errOutOfScope)
	}
	return nil
}

// view is the scope as the dashboard needs it.
func (sc *mailScope) view() map[string]any {
	if sc.all {
		return map[string]any{"all": true}
	}
	return map[string]any{"all": false, "domains": sc.domains}
}

func filterAccounts(sc *mailScope, in []provision.Account) []provision.Account {
	if sc.all {
		return in
	}
	out := []provision.Account{}
	for _, a := range in {
		if sc.address(a.Address) {
			out = append(out, a)
		}
	}
	return out
}

func filterLists(sc *mailScope, in []mailpolicy.List) []mailpolicy.List {
	if sc.all {
		return in
	}
	out := []mailpolicy.List{}
	for _, l := range in {
		if sc.address(l.Address) {
			out = append(out, l)
		}
	}
	return out
}
