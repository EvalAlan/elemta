package mailpolicy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AuditEntry is one administrative change: who made it, from where, what
// they did and to what. The mailbox service stores entries append-only;
// nothing in its API edits or deletes them.
type AuditEntry struct {
	ID     int64     `json:"id,omitempty"`
	At     time.Time `json:"at,omitempty"`
	Actor  string    `json:"actor"`            // dashboard user, or "cli"
	Source string    `json:"source"`           // "dashboard", "cli", "migrate"
	Client string    `json:"client,omitempty"` // the dashboard client's address
	Action string    `json:"action"`           // e.g. "account-create"
	Target string    `json:"target"`           // address, domain or class acted on
	// Domain is the target's domain, so a domain administrator can be shown
	// the entries for their domains only. The service fills it from Target
	// when left empty.
	Domain string `json:"domain,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// AuditQuery selects entries, newest first. Domains, when set, keeps only
// entries for those domains; Before pages backwards by ID.
type AuditQuery struct {
	Domains []string
	Actor   string
	Target  string // substring
	Action  string // prefix
	Before  int64
	Limit   int
}

// MaxAuditPage is the most entries one query returns.
const MaxAuditPage = 500

// Validate bounds an entry's fields, which come from administrators but end
// up in a table kept forever.
func (e *AuditEntry) Validate() error {
	e.Actor, e.Source, e.Action, e.Target = strings.TrimSpace(e.Actor), strings.TrimSpace(e.Source), strings.TrimSpace(e.Action), strings.ToLower(strings.TrimSpace(e.Target))
	if e.Actor == "" || e.Action == "" {
		return errors.Join(ErrInvalid, errors.New("an audit entry needs an actor and an action"))
	}
	for _, f := range []struct {
		v   string
		max int
	}{{e.Actor, 256}, {e.Source, 32}, {e.Client, 128}, {e.Action, 64}, {e.Target, 512}, {e.Domain, 253}, {e.Detail, 4096}} {
		if len(f.v) > f.max {
			return errors.Join(ErrInvalid, errors.New("an audit field is too long"))
		}
	}
	if e.Domain == "" {
		e.Domain = AuditDomain(e.Target)
	}
	e.Domain = strings.ToLower(e.Domain)
	return nil
}

// AuditDomain is the domain an audit target belongs to: the part after @ of
// an address, a bare domain itself, and "" for anything else (a class name).
func AuditDomain(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	if i := strings.LastIndexByte(target, '@'); i >= 0 {
		return target[i+1:]
	}
	if strings.Contains(target, ".") {
		return target
	}
	return ""
}

// Audit records an administrative change.
func (c *Client) Audit(ctx context.Context, e AuditEntry) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/audit", e, nil)
}

// AuditLog returns entries matching q, newest first.
func (c *Client) AuditLog(ctx context.Context, q AuditQuery) ([]AuditEntry, error) {
	v := url.Values{}
	for _, d := range q.Domains {
		v.Add("domain", d)
	}
	if q.Actor != "" {
		v.Set("actor", q.Actor)
	}
	if q.Target != "" {
		v.Set("target", q.Target)
	}
	if q.Action != "" {
		v.Set("action", q.Action)
	}
	if q.Before > 0 {
		v.Set("before", strconv.FormatInt(q.Before, 10))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	var out []AuditEntry
	path := "/v1/admin/audit"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}
