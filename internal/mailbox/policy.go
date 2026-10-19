package mailbox

// Classes of service and per-account policy (internal/mailpolicy explains
// the model). The mailbox service owns them because it already holds the
// shared, transactional state every replica reads, and because most of the
// rules are enforced here: which protocols may sign in, quota, the size of
// mail received, and filters. The MTA and the administration tools reach the
// same data through the admin API (admin_api.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/lib/pq"
)

// ErrInUse refuses deleting a class an account or domain still names.
var ErrInUse = errors.New("class of service is in use")

func decodeSettings(raw []byte) (mailpolicy.Settings, error) {
	var s mailpolicy.Settings
	if len(raw) == 0 {
		return s, nil
	}
	err := json.Unmarshal(raw, &s)
	return s, err
}

func encodeSettings(s mailpolicy.Settings) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func isEmpty(s mailpolicy.Settings) bool {
	data, _ := json.Marshal(s)
	return string(data) == "{}"
}

// Classes lists every class of service with how many accounts and domains
// name it.
func (e *Engine) Classes(ctx context.Context) ([]mailpolicy.Class, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT c.name, c.description, c.settings,
 (SELECT count(*) FROM mailbox_account_policy a WHERE a.class=c.name),
 (SELECT count(*) FROM mailbox_domain_policy d WHERE d.class=c.name)
FROM mailbox_classes c ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.Class{}
	for rows.Next() {
		var c mailpolicy.Class
		var raw []byte
		if err := rows.Scan(&c.Name, &c.Description, &raw, &c.Accounts, &c.Domains); err != nil {
			return nil, err
		}
		if c.Settings, err = decodeSettings(raw); err != nil {
			return nil, fmt.Errorf("class %s: %w", c.Name, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Class returns one class of service.
func (e *Engine) Class(ctx context.Context, name string) (mailpolicy.Class, error) {
	classes, err := e.Classes(ctx)
	if err != nil {
		return mailpolicy.Class{}, err
	}
	for _, c := range classes {
		if c.Name == name {
			return c, nil
		}
	}
	return mailpolicy.Class{}, errors.Join(ErrNotFound, fmt.Errorf("no class of service named %q", name))
}

// PutClass creates a class of service or replaces its settings.
func (e *Engine) PutClass(ctx context.Context, c mailpolicy.Class) (mailpolicy.Class, error) {
	if err := mailpolicy.ValidClass(c.Name); err != nil {
		return mailpolicy.Class{}, err
	}
	c.Description = strings.TrimSpace(c.Description)
	if len(c.Description) > 500 {
		return mailpolicy.Class{}, fmt.Errorf("%w: keep the description under 500 characters", mailpolicy.ErrInvalid)
	}
	raw, err := encodeSettings(c.Settings)
	if err != nil {
		return mailpolicy.Class{}, err
	}
	if _, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_classes(name,description,settings) VALUES($1,$2,$3)
ON CONFLICT(name) DO UPDATE SET description=EXCLUDED.description, settings=EXCLUDED.settings, updated=now()`, c.Name, c.Description, raw); err != nil {
		return mailpolicy.Class{}, err
	}
	return e.Class(ctx, c.Name)
}

// DeleteClass removes a class of service nothing names. The default class
// always stays.
func (e *Engine) DeleteClass(ctx context.Context, name string) error {
	if name == mailpolicy.DefaultClass {
		return errors.Join(ErrInUse, errors.New("the default class can't be deleted"))
	}
	res, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_classes WHERE name=$1`, name)
	if isForeignKey(err) {
		return errors.Join(ErrInUse, fmt.Errorf("class %q is still used by accounts or domains; move them first", name))
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Join(ErrNotFound, fmt.Errorf("no class of service named %q", name))
	}
	return nil
}

func isForeignKey(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23503"
}

// Domains lists the domains that name a class.
func (e *Engine) Domains(ctx context.Context) ([]mailpolicy.DomainPolicy, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT domain, class FROM mailbox_domain_policy ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DomainPolicy{}
	for rows.Next() {
		var d mailpolicy.DomainPolicy
		if err := rows.Scan(&d.Domain, &d.Class); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomain sets or (with an empty class) clears a domain's class.
func (e *Engine) SetDomain(ctx context.Context, d mailpolicy.DomainPolicy) (mailpolicy.DomainPolicy, error) {
	d.Domain = strings.ToLower(strings.TrimSpace(d.Domain))
	if d.Domain == "" || strings.ContainsAny(d.Domain, "@/ ") || len(d.Domain) > 253 {
		return d, fmt.Errorf("%w: enter a domain name", mailpolicy.ErrInvalid)
	}
	if d.Class == "" {
		_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_domain_policy WHERE domain=$1`, d.Domain)
		return d, err
	}
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_domain_policy(domain,class) VALUES($1,$2)
ON CONFLICT(domain) DO UPDATE SET class=EXCLUDED.class, updated=now()`, d.Domain, d.Class)
	if isForeignKey(err) {
		return d, errors.Join(ErrNotFound, fmt.Errorf("no class of service named %q", d.Class))
	}
	return d, err
}

// AccountPolicy returns what is stored for an account; an account with
// nothing stored has no class of its own and no overrides.
func (e *Engine) AccountPolicy(ctx context.Context, address string) (mailpolicy.AccountPolicy, error) {
	p := mailpolicy.AccountPolicy{Address: strings.ToLower(address)}
	var class sql.NullString
	var raw []byte
	err := e.DB.QueryRowContext(ctx, `SELECT class, settings FROM mailbox_account_policy WHERE address=$1`, p.Address).Scan(&class, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	p.Class = class.String
	p.Settings, err = decodeSettings(raw)
	return p, err
}

// PutAccountPolicy replaces an account's class and overrides. Clearing both
// removes the row, so an account with nothing of its own leaves no trace.
func (e *Engine) PutAccountPolicy(ctx context.Context, p mailpolicy.AccountPolicy) error {
	p.Address = strings.ToLower(strings.TrimSpace(p.Address))
	raw, err := encodeSettings(p.Settings)
	if err != nil {
		return err
	}
	if p.Class == "" && isEmpty(p.Settings) {
		_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_account_policy WHERE address=$1`, p.Address)
		return err
	}
	var class any
	if p.Class != "" {
		class = p.Class
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_account_policy(address,class,settings) VALUES($1,$2,$3)
ON CONFLICT(address) DO UPDATE SET class=EXCLUDED.class, settings=EXCLUDED.settings, updated=now()`, p.Address, class, raw)
	if isForeignKey(err) {
		return errors.Join(ErrNotFound, fmt.Errorf("no class of service named %q", p.Class))
	}
	return err
}

// EffectivePolicy works out an account's policy. directoryQuota is the
// quota the directory holds for the account (the one set when the account
// was created or modified); when set it outranks the classes, as an
// account-level setting, and only the account's own override beats it.
func (e *Engine) EffectivePolicy(ctx context.Context, address string, directoryQuota int64) (mailpolicy.Effective, error) {
	address = strings.ToLower(address)
	domain := address[strings.LastIndex(address, "@")+1:]
	var (
		defaultRaw, domainRaw, accountClassRaw, accountRaw []byte
		domainClass, accountClass                          sql.NullString
	)
	err := e.DB.QueryRowContext(ctx, `SELECT
 (SELECT settings FROM mailbox_classes WHERE name='default'),
 d.class, dc.settings, ap.class, ac.settings, ap.settings
FROM (SELECT 1) one
LEFT JOIN mailbox_domain_policy d ON d.domain=$2
LEFT JOIN mailbox_classes dc ON dc.name=d.class
LEFT JOIN mailbox_account_policy ap ON ap.address=$1
LEFT JOIN mailbox_classes ac ON ac.name=ap.class`, address, domain).Scan(&defaultRaw, &domainClass, &domainRaw, &accountClass, &accountClassRaw, &accountRaw)
	if err != nil {
		return mailpolicy.Effective{}, err
	}
	var layers []mailpolicy.Layer
	add := func(name string, raw []byte) error {
		s, err := decodeSettings(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		layers = append(layers, mailpolicy.Layer{Name: name, Settings: s})
		return nil
	}
	class := mailpolicy.DefaultClass
	if err := add("default class", defaultRaw); err != nil {
		return mailpolicy.Effective{}, err
	}
	if domainClass.Valid {
		class = domainClass.String
		if err := add("domain class "+domainClass.String, domainRaw); err != nil {
			return mailpolicy.Effective{}, err
		}
	}
	if accountClass.Valid {
		class = accountClass.String
		if err := add("class "+accountClass.String, accountClassRaw); err != nil {
			return mailpolicy.Effective{}, err
		}
	}
	if directoryQuota > 0 {
		layers = append(layers, mailpolicy.Layer{Name: "directory", Settings: mailpolicy.Settings{QuotaBytes: &directoryQuota}})
	}
	if err := add("account", accountRaw); err != nil {
		return mailpolicy.Effective{}, err
	}
	return mailpolicy.Resolve(address, class, layers...), nil
}

// PurgeResult counts what PurgeAccount removed.
type PurgeResult = mailpolicy.PurgeResult

// PurgeAccount removes every row held for an address: its accounts (an
// address recreated after a deletion has more than one directory ID), their
// folders, messages and change journal, delivery tokens, filters, security
// settings and app passwords, and its policy. Message bodies are left to the
// garbage collector, which deletes the ones nothing refers to any more after
// its grace period, so a body shared with another mailbox survives and a
// recent backup can still be restored. The caller makes sure the directory
// no longer has the account.
func (e *Engine) PurgeAccount(ctx context.Context, address string) (PurgeResult, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	out := PurgeResult{Address: address}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mailbox_accounts WHERE address=$1 FOR UPDATE`, address)
	if err != nil {
		return out, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return out, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return out, err
	}
	out.Accounts = len(ids)
	if len(ids) > 0 {
		list := pq.Array(ids)
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=ANY($1)`, list).Scan(&out.Messages); err != nil {
			return out, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_folders WHERE account=ANY($1)`, list).Scan(&out.Folders); err != nil {
			return out, err
		}
		for _, q := range []string{
			`DELETE FROM mailbox_changes WHERE folder IN (SELECT id FROM mailbox_folders WHERE account=ANY($1))`,
			`DELETE FROM mailbox_folders WHERE account=ANY($1)`, // messages cascade
			`DELETE FROM mailbox_deliveries WHERE account=ANY($1)`,
			`DELETE FROM mailbox_sieve_scripts WHERE account=ANY($1)`,
			`DELETE FROM mailbox_sieve_sent WHERE account=ANY($1)`,
			`DELETE FROM mailbox_accounts WHERE id=ANY($1)`, // security, app passwords, POP3 leases cascade
		} {
			if _, err := tx.ExecContext(ctx, q, list); err != nil {
				return out, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_account_policy WHERE address=$1`, address); err != nil {
		return out, err
	}
	// A purged account leaves the lists it was on, so they don't keep
	// sending to an address that is gone.
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_list_members WHERE member=$1`, address); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
