package mailbox

// Addresses that aren't directory accounts: domain aliases, catch-alls and
// distribution lists (mailpolicy explains each). The directory keeps
// accounts and their aliases; these live here, beside classes of service,
// because they are routing the mailbox applies at delivery and the admin
// API manages.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// maxListMembers bounds a list, so one message can't fan out without limit.
const maxListMembers = 10000

func normalAddress(raw string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(raw))
	local, domain, ok := strings.Cut(a, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(a) > 254 || strings.ContainsAny(a, " \t\r\n<>(),;:\"[]\\") {
		return "", errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("%q isn't an email address", raw))
	}
	return a, nil
}

func normalDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if d == "" || len(d) > 253 || strings.ContainsAny(d, "@/ \t") || !strings.Contains(d, ".") {
		return "", errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("%q isn't a domain name", raw))
	}
	return d, nil
}

func domainOf(address string) string { return address[strings.LastIndex(address, "@")+1:] }

// ---- domain routes ----------------------------------------------------------

// Routes lists every domain with an alias target or a catch-all.
func (e *Engine) Routes(ctx context.Context) ([]mailpolicy.DomainRoute, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT domain, COALESCE(alias_of,''), COALESCE(catch_all,'') FROM mailbox_domain_routes ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DomainRoute{}
	for rows.Next() {
		var r mailpolicy.DomainRoute
		if err := rows.Scan(&r.Domain, &r.AliasOf, &r.CatchAll); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Route returns a domain's route; a domain without one has an empty route.
func (e *Engine) Route(ctx context.Context, domain string) (mailpolicy.DomainRoute, error) {
	r := mailpolicy.DomainRoute{Domain: strings.ToLower(domain)}
	err := e.DB.QueryRowContext(ctx, `SELECT COALESCE(alias_of,''), COALESCE(catch_all,'') FROM mailbox_domain_routes WHERE domain=$1`, r.Domain).Scan(&r.AliasOf, &r.CatchAll)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	return r, err
}

// SetRoute replaces a domain's route. Aliases don't chain: a domain that is
// itself an alias can't be a target, and a target can't become an alias,
// so resolution is always one step.
func (e *Engine) SetRoute(ctx context.Context, r mailpolicy.DomainRoute) (mailpolicy.DomainRoute, error) {
	var err error
	if r.Domain, err = normalDomain(r.Domain); err != nil {
		return r, err
	}
	if r.AliasOf != "" {
		if r.AliasOf, err = normalDomain(r.AliasOf); err != nil {
			return r, err
		}
		if r.AliasOf == r.Domain {
			return r, errors.Join(mailpolicy.ErrInvalid, errors.New("a domain can't be an alias of itself"))
		}
		target, err := e.Route(ctx, r.AliasOf)
		if err != nil {
			return r, err
		}
		if target.AliasOf != "" {
			return r, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("%s is itself an alias of %s; point at %s", r.AliasOf, target.AliasOf, target.AliasOf))
		}
		var aliased int
		if err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_domain_routes WHERE alias_of=$1`, r.Domain).Scan(&aliased); err != nil {
			return r, err
		}
		if aliased > 0 {
			return r, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("other domains are aliases of %s, so it can't become an alias itself", r.Domain))
		}
	}
	if r.CatchAll != "" {
		if r.CatchAll, err = normalAddress(r.CatchAll); err != nil {
			return r, err
		}
	}
	if r.AliasOf == "" && r.CatchAll == "" {
		_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_domain_routes WHERE domain=$1`, r.Domain)
		return r, err
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_domain_routes(domain,alias_of,catch_all) VALUES($1,NULLIF($2,''),NULLIF($3,''))
ON CONFLICT(domain) DO UPDATE SET alias_of=EXCLUDED.alias_of, catch_all=EXCLUDED.catch_all, updated=now()`, r.Domain, r.AliasOf, r.CatchAll)
	return r, err
}

// ---- distribution lists -----------------------------------------------------

func validPosting(p string) bool { return slices.Contains(mailpolicy.PostingPolicies, p) }

// Lists returns every list, without members, which can be many.
func (e *Engine) Lists(ctx context.Context) ([]mailpolicy.List, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT l.address, l.name, l.description, l.owner, l.posting,
 (SELECT count(*) FROM mailbox_list_members m WHERE m.list=l.address) FROM mailbox_lists l ORDER BY l.address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.List{}
	for rows.Next() {
		l := mailpolicy.List{Members: []string{}}
		if err := rows.Scan(&l.Address, &l.Name, &l.Description, &l.Owner, &l.Posting, &l.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListsOfMember returns the addresses of the lists that have address as a
// direct member.
func (e *Engine) ListsOfMember(ctx context.Context, address string) ([]string, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT list FROM mailbox_list_members WHERE member=$1 ORDER BY list`, strings.ToLower(strings.TrimSpace(address)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var list string
		if err := rows.Scan(&list); err != nil {
			return nil, err
		}
		out = append(out, list)
	}
	return out, rows.Err()
}

// List returns one list with its members, sorted.
func (e *Engine) List(ctx context.Context, address string) (mailpolicy.List, error) {
	l := mailpolicy.List{Address: strings.ToLower(strings.TrimSpace(address))}
	err := e.DB.QueryRowContext(ctx, `SELECT name, description, owner, posting FROM mailbox_lists WHERE address=$1`, l.Address).Scan(&l.Name, &l.Description, &l.Owner, &l.Posting)
	if errors.Is(err, sql.ErrNoRows) {
		return l, errors.Join(ErrNotFound, fmt.Errorf("no list %s", l.Address))
	}
	if err != nil {
		return l, err
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT member FROM mailbox_list_members WHERE list=$1 ORDER BY member`, l.Address)
	if err != nil {
		return l, err
	}
	defer rows.Close()
	l.Members = []string{}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return l, err
		}
		l.Members = append(l.Members, m)
	}
	l.MemberCount = len(l.Members)
	return l, rows.Err()
}

// isList reports whether an address is a list, cheaply, for delivery.
func (e *Engine) isList(ctx context.Context, address string) (bool, error) {
	var found bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_lists WHERE address=$1)`, address).Scan(&found)
	return found, err
}

func cleanMembers(list string, raw []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, m := range raw {
		if strings.TrimSpace(m) == "" {
			continue
		}
		a, err := normalAddress(m)
		if err != nil {
			return nil, err
		}
		if a == list {
			return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("a list can't be a member of itself"))
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// PutList creates a list or replaces its settings and members.
func (e *Engine) PutList(ctx context.Context, l mailpolicy.List) (mailpolicy.List, error) {
	var err error
	if l.Address, err = normalAddress(l.Address); err != nil {
		return l, err
	}
	if l.Posting == "" {
		l.Posting = mailpolicy.PostAnyone
	}
	if !validPosting(l.Posting) {
		return l, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("posting must be one of %s", strings.Join(mailpolicy.PostingPolicies, ", ")))
	}
	if l.Owner != "" {
		if l.Owner, err = normalAddress(l.Owner); err != nil {
			return l, err
		}
	}
	l.Name, l.Description = strings.TrimSpace(l.Name), strings.TrimSpace(l.Description)
	if len(l.Name) > 200 || len(l.Description) > 1000 {
		return l, errors.Join(mailpolicy.ErrInvalid, errors.New("keep the name under 200 and the description under 1000 characters"))
	}
	members, err := cleanMembers(l.Address, l.Members)
	if err != nil {
		return l, err
	}
	if len(members) > maxListMembers {
		return l, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("a list holds at most %d members", maxListMembers))
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return l, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_lists(address,name,description,owner,posting) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(address) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, owner=EXCLUDED.owner, posting=EXCLUDED.posting, updated=now()`,
		l.Address, l.Name, l.Description, l.Owner, l.Posting); err != nil {
		return l, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_list_members WHERE list=$1`, l.Address); err != nil {
		return l, err
	}
	for _, m := range members {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_list_members(list,member) VALUES($1,$2)`, l.Address, m); err != nil {
			return l, err
		}
	}
	if err := tx.Commit(); err != nil {
		return l, err
	}
	return e.List(ctx, l.Address)
}

// ChangeMembers adds and removes members, leaving the rest.
func (e *Engine) ChangeMembers(ctx context.Context, address string, add, remove []string) (mailpolicy.List, error) {
	l, err := e.List(ctx, address)
	if err != nil {
		return l, err
	}
	gone, err := cleanMembers(l.Address, remove)
	if err != nil {
		return l, err
	}
	members := slices.DeleteFunc(l.Members, func(m string) bool { return slices.Contains(gone, m) })
	l.Members = append(members, add...)
	return e.PutList(ctx, l)
}

// DeleteList removes a list and its members.
func (e *Engine) DeleteList(ctx context.Context, address string) error {
	res, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_lists WHERE address=$1`, strings.ToLower(strings.TrimSpace(address)))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Join(ErrNotFound, fmt.Errorf("no list %s", address))
	}
	_, _ = e.DB.ExecContext(ctx, `DELETE FROM mailbox_list_sent WHERE list=$1`, strings.ToLower(strings.TrimSpace(address)))
	return nil
}

// claimListSent records that a list sent a message on, so a retried
// delivery doesn't send it twice; it reports false when already claimed.
func (e *Engine) claimListSent(ctx context.Context, list, key string, ttl time.Duration) (bool, error) {
	res, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_list_sent(list,key,expires) VALUES($1,$2,now()+$3*interval '1 second')
ON CONFLICT(list,key) DO UPDATE SET expires=EXCLUDED.expires WHERE mailbox_list_sent.expires<now()`, list, key, int64(ttl/time.Second))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (e *Engine) listSent(ctx context.Context, list, key string) (bool, error) {
	var sent bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_list_sent WHERE list=$1 AND key=$2 AND expires>now())`, list, key).Scan(&sent)
	return sent, err
}
