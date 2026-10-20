package mailbox

import (
	"context"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/lib/pq"
)

// Audit stores an administrative change and returns it as stored.
func (e *Engine) Audit(ctx context.Context, a mailpolicy.AuditEntry) (mailpolicy.AuditEntry, error) {
	if err := a.Validate(); err != nil {
		return a, err
	}
	err := e.DB.QueryRowContext(ctx, `INSERT INTO mailbox_audit(actor,source,client,action,target,domain,detail)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id, at`, a.Actor, a.Source, a.Client, a.Action, a.Target, a.Domain, a.Detail).Scan(&a.ID, &a.At)
	return a, err
}

// AuditLog returns entries matching q, newest first. The filters are fixed
// placeholders that an empty value switches off, so the query text never
// depends on the input.
func (e *Engine) AuditLog(ctx context.Context, q mailpolicy.AuditQuery) ([]mailpolicy.AuditEntry, error) {
	if q.Limit <= 0 || q.Limit > mailpolicy.MaxAuditPage {
		q.Limit = 100
	}
	domains := make([]string, 0, len(q.Domains))
	for _, d := range q.Domains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(d)))
	}
	var domainFilter any
	if len(q.Domains) > 0 {
		domainFilter = pq.Array(domains)
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT id, at, actor, source, client, action, target, domain, detail FROM mailbox_audit
WHERE ($1::text[] IS NULL OR domain = ANY($1::text[]))
  AND ($2 = '' OR actor = $2)
  AND ($3 = '' OR strpos(target, lower($3)) > 0)
  AND ($4 = '' OR starts_with(action, $4))
  AND ($5 = 0 OR id < $5)
ORDER BY id DESC LIMIT $6`, domainFilter, q.Actor, q.Target, q.Action, q.Before, q.Limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []mailpolicy.AuditEntry{}
	for rows.Next() {
		var a mailpolicy.AuditEntry
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Source, &a.Client, &a.Action, &a.Target, &a.Domain, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
