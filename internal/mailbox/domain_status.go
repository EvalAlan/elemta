package mailbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// A domain's status works like an account's (statusAllows), for everyone in
// the domain at once:
//
//	active     signs in and receives mail
//	suspended  receives mail but nobody may sign in, on any protocol
//	disabled   neither: mail to the domain is refused
//
// It is enforced here rather than per protocol because every sign-in and
// every delivery lookup, including the re-check that ends a session already
// open, comes through the Authenticator. A domain with no row is active, so
// nothing changes for a domain until an administrator acts on it.

// DomainStatus returns a domain's status.
func (e *Engine) DomainStatus(ctx context.Context, domain string) (string, error) {
	var status string
	err := e.DB.QueryRowContext(ctx, `SELECT status FROM mailbox_domain_status WHERE domain=$1`, strings.ToLower(domain)).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return mailpolicy.DomainActive, nil
	}
	return status, err
}

// DomainStatuses lists every domain that isn't active.
func (e *Engine) DomainStatuses(ctx context.Context) ([]mailpolicy.DomainStatus, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT domain, status FROM mailbox_domain_status ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DomainStatus{}
	for rows.Next() {
		var d mailpolicy.DomainStatus
		if err := rows.Scan(&d.Domain, &d.Status); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomainStatus sets a domain's status.
func (e *Engine) SetDomainStatus(ctx context.Context, d mailpolicy.DomainStatus) (mailpolicy.DomainStatus, error) {
	var err error
	if d.Domain, err = normalDomain(d.Domain); err != nil {
		return d, err
	}
	switch d.Status {
	case mailpolicy.DomainActive:
		_, err = e.DB.ExecContext(ctx, `DELETE FROM mailbox_domain_status WHERE domain=$1`, d.Domain)
	case mailpolicy.DomainSuspended, mailpolicy.DomainDisabled:
		_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_domain_status(domain,status) VALUES($1,$2)
ON CONFLICT(domain) DO UPDATE SET status=EXCLUDED.status, updated=now()`, d.Domain, d.Status)
	default:
		return d, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("%q isn't a domain status", d.Status))
	}
	return d, err
}

// domainStatuses is the part of the Engine domainStatusAuth uses.
type domainStatuses interface {
	DomainStatus(context.Context, string) (string, error)
}

// domainStatusAuth applies domain status on top of the directory's answer.
type domainStatusAuth struct {
	Authenticator
	statuses domainStatuses
}

func (a domainStatusAuth) Login(ctx context.Context, user, password string) (Account, error) {
	account, err := a.Authenticator.Login(ctx, user, password)
	if err != nil {
		return Account{}, err
	}
	status, err := a.worst(ctx, account.Address)
	if err != nil {
		return Account{}, err
	}
	if status != mailpolicy.DomainActive {
		return Account{}, ErrCredentials
	}
	return account, nil
}

// Resolve checks the address asked for as well as the account's own, since an
// alias in a disabled domain can belong to an account in a healthy one.
func (a domainStatusAuth) Resolve(ctx context.Context, address string) (Account, error) {
	account, err := a.Authenticator.Resolve(ctx, address)
	if err != nil {
		return Account{}, err
	}
	status, err := a.worst(ctx, address, account.Address)
	if err != nil {
		return Account{}, err
	}
	switch status {
	case mailpolicy.DomainActive:
		return account, nil
	case mailpolicy.DomainSuspended:
		account.Suspended = true
		return account, nil
	default:
		return Account{}, ErrCredentials
	}
}

func (a domainStatusAuth) worst(ctx context.Context, addresses ...string) (string, error) {
	worst := mailpolicy.DomainActive
	for _, address := range addresses {
		at := strings.LastIndex(address, "@")
		if at < 0 {
			continue
		}
		status, err := a.statuses.DomainStatus(ctx, strings.TrimSpace(address[at+1:]))
		if err != nil {
			return "", err
		}
		if status == mailpolicy.DomainDisabled || (status == mailpolicy.DomainSuspended && worst == mailpolicy.DomainActive) {
			worst = status
		}
	}
	return worst, nil
}
