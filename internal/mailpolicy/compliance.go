package mailpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Compliance search finds mail across every mailbox for an investigation or
// a legal request, including mail kept by a legal hold after its owner
// deleted it, and exports it for review tools. The mailbox service answers
// it from its search index; the administration tools decide who may ask and
// record every search in the audit log.

// MaxComplianceHits bounds one page of search results; an export has no
// page and takes everything that matches, up to MaxComplianceExport.
const (
	MaxComplianceHits   = 500
	MaxComplianceExport = 100000
)

// ComplianceQuery selects mail. Every criterion given must match. Text
// matches words in the readable body text by prefix, as the webmail's
// search does; the address and subject criteria are case-insensitive
// substrings.
type ComplianceQuery struct {
	// Domains confines the search to accounts in these domains: the
	// searcher's scope, set by the administration tools, not the user.
	Domains []string `json:"domains,omitempty"`
	// Accounts are primary addresses, matched exactly.
	Accounts []string  `json:"accounts,omitempty"`
	From     string    `json:"from,omitempty"`
	To       string    `json:"to,omitempty"` // To, Cc or Bcc
	Subject  string    `json:"subject,omitempty"`
	Text     string    `json:"text,omitempty"`
	Since    time.Time `json:"since,omitzero"`  // received on or after
	Before   time.Time `json:"before,omitzero"` // received before
	// ExcludeHeld leaves out mail kept only by a legal hold.
	ExcludeHeld bool `json:"exclude_held,omitempty"`
	Limit       int  `json:"limit,omitempty"`
}

// Normalize trims and lower-cases the query, and refuses one that names
// nothing to look for: searching every message on the server is never what
// someone meant by leaving the form empty.
func (q *ComplianceQuery) Normalize() error {
	clean := func(list []string) []string {
		var out []string
		for _, v := range list {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	q.Domains, q.Accounts = clean(q.Domains), clean(q.Accounts)
	q.From, q.To = strings.TrimSpace(q.From), strings.TrimSpace(q.To)
	q.Subject, q.Text = strings.TrimSpace(q.Subject), strings.TrimSpace(q.Text)
	if len(q.Accounts) > 1000 {
		return errors.Join(ErrInvalid, errors.New("name at most 1000 accounts"))
	}
	for _, s := range []string{q.From, q.To, q.Subject, q.Text} {
		if len(s) > 500 {
			return errors.Join(ErrInvalid, errors.New("search terms are limited to 500 characters"))
		}
	}
	if len(q.Accounts) == 0 && q.From == "" && q.To == "" && q.Subject == "" && q.Text == "" && q.Since.IsZero() && q.Before.IsZero() {
		return errors.Join(ErrInvalid, errors.New("give at least one account, address, subject, words or date"))
	}
	if !q.Since.IsZero() && !q.Before.IsZero() && !q.Since.Before(q.Before) {
		return errors.Join(ErrInvalid, errors.New("the start date must be before the end date"))
	}
	if q.Limit < 1 || q.Limit > MaxComplianceHits {
		q.Limit = MaxComplianceHits
	}
	return nil
}

// Describe is the query in words, for the audit log.
func (q ComplianceQuery) Describe() string {
	var parts []string
	add := func(name, v string) {
		if v != "" {
			parts = append(parts, fmt.Sprintf("%s %q", name, v))
		}
	}
	if len(q.Accounts) > 0 {
		accounts := q.Accounts
		if len(accounts) > 10 {
			accounts = append(append([]string{}, accounts[:10]...), fmt.Sprintf("and %d more", len(q.Accounts)-10))
		}
		parts = append(parts, "accounts "+strings.Join(accounts, ", "))
	}
	add("from", q.From)
	add("to", q.To)
	add("subject", q.Subject)
	add("words", q.Text)
	if !q.Since.IsZero() {
		parts = append(parts, "since "+q.Since.UTC().Format("2006-01-02"))
	}
	if !q.Before.IsZero() {
		parts = append(parts, "before "+q.Before.UTC().Format("2006-01-02"))
	}
	if q.ExcludeHeld {
		parts = append(parts, "without held mail")
	}
	if len(q.Domains) > 0 {
		parts = append(parts, "in "+strings.Join(q.Domains, ", "))
	}
	return strings.Join(parts, "; ")
}

// ComplianceHit is one message found. Ref names it for downloading.
type ComplianceHit struct {
	Ref     string     `json:"ref"`
	Account string     `json:"account"`
	Folder  string     `json:"folder"`
	Held    bool       `json:"held,omitempty"` // kept by a legal hold after deletion
	HeldAt  *time.Time `json:"held_at,omitempty"`
	Date    time.Time  `json:"date"` // received
	From    string     `json:"from"`
	To      string     `json:"to"`
	Subject string     `json:"subject"`
	Size    int64      `json:"size"`
}

// ComplianceResult is one page of hits. Total counts every match;
// Unindexed counts messages in the searched accounts and dates that the
// index hasn't reached yet, which a search can't see.
type ComplianceResult struct {
	Hits      []ComplianceHit `json:"hits"`
	Total     int             `json:"total"`
	Unindexed int             `json:"unindexed"`
}

// ComplianceSearch runs a search.
func (c *Client) ComplianceSearch(ctx context.Context, q ComplianceQuery) (ComplianceResult, error) {
	var out ComplianceResult
	err := c.do(ctx, http.MethodPost, "/v1/admin/compliance/search", q, &out)
	return out, err
}

// ComplianceExport writes every match as mbox to w.
func (c *Client) ComplianceExport(ctx context.Context, q ComplianceQuery, w io.Writer) error {
	_, err := c.stream(ctx, http.MethodPost, "/v1/admin/compliance/export", q, w)
	return err
}

// ComplianceAccountHeader names the account a message belongs to.
const ComplianceAccountHeader = "X-Elemta-Account"

// ComplianceMessage writes one found message, as it was received, to w, and
// returns the account it belongs to. Domains confines it as for a search.
func (c *Client) ComplianceMessage(ctx context.Context, ref string, domains []string, w io.Writer) (string, error) {
	v := url.Values{"ref": {ref}}
	for _, d := range domains {
		v.Add("domain", d)
	}
	h, err := c.stream(ctx, http.MethodGet, "/v1/admin/compliance/message?"+v.Encode(), nil, w)
	if err != nil {
		return "", err
	}
	return h.Get(ComplianceAccountHeader), nil
}
