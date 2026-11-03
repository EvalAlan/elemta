package mailbox

// Compliance search across every mailbox (mailpolicy.ComplianceQuery).
//
// It reads the same index as IMAP SEARCH (searchindex.go), over all
// accounts at once, and over mail a legal hold kept after its owner deleted
// it, since that is the mail an investigation most often needs. Mail the
// index hasn't reached is counted rather than scanned: scanning every body
// on the server is not something to do inside a request, and a search that
// silently missed mail would be worse than one that says what it couldn't
// see. Calendar, contacts, tasks and settings folders hold the webmail's
// data, not mail, and are left out as retention leaves them out.

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
	"github.com/lib/pq"
)

// complianceHits is every message and held message, with the account it
// belongs to. Refs are "m:<folder id>:<uid>" and "h:<held id>".
const complianceHits = `WITH hits AS (
 SELECT 'm:'||m.folder||':'||m.uid AS ref, a.address, f.name AS folder, false AS held, NULL::timestamptz AS held_at, m.internal_date AS date, m.body
 FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder JOIN mailbox_accounts a ON a.id=f.account
 WHERE lower(f.name) NOT IN ('calendar','contacts','tasks','settings')
 UNION ALL
 SELECT 'h:'||h.id, a.address, h.folder, true, h.held_at, h.internal_date, h.body
 FROM mailbox_held h JOIN mailbox_accounts a ON a.id=h.account
 WHERE lower(h.folder) NOT IN ('calendar','contacts','tasks','settings') AND NOT $2
)
`

// complianceWhere builds the conditions of q. Arguments start at $3: $1 is
// the summary version and $2 whether held mail is left out. Every fragment
// is fixed text; values are parameters. scopeOnly leaves out the conditions
// on content, for counting what the index can't answer.
func complianceWhere(q mailpolicy.ComplianceQuery, scopeOnly bool) (string, []any, error) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args)+2)
	}
	if len(q.Domains) > 0 {
		conds = append(conds, "split_part(x.address,'@',2) = ANY("+arg(pq.Array(q.Domains))+")")
	}
	if len(q.Accounts) > 0 {
		conds = append(conds, "x.address = ANY("+arg(pq.Array(q.Accounts))+")")
	}
	if !q.Since.IsZero() {
		conds = append(conds, "x.date >= "+arg(q.Since))
	}
	if !q.Before.IsZero() {
		conds = append(conds, "x.date < "+arg(q.Before))
	}
	if !scopeOnly {
		if q.From != "" {
			conds = append(conds, "s.hdr_from ILIKE "+arg(likePattern(q.From)))
		}
		if q.To != "" {
			p := arg(likePattern(q.To))
			conds = append(conds, "(s.hdr_to ILIKE "+p+" OR s.hdr_cc ILIKE "+p+" OR s.hdr_bcc ILIKE "+p+")")
		}
		if q.Subject != "" {
			conds = append(conds, "s.hdr_subject ILIKE "+arg(likePattern(q.Subject)))
		}
		if q.Text != "" {
			ts := tsPrefixQuery(q.Text)
			if ts == "" {
				return "", nil, errors.Join(mailpolicy.ErrInvalid, errors.New("search words need letters or digits, and at most 32 of them"))
			}
			conds = append(conds, "s.body_tsv @@ to_tsquery('simple',"+arg(ts)+")")
		}
	}
	if len(conds) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

// ComplianceSearch returns the newest matches of q, up to its limit.
func (e *Engine) ComplianceSearch(ctx context.Context, q mailpolicy.ComplianceQuery) (mailpolicy.ComplianceResult, error) {
	out := mailpolicy.ComplianceResult{Hits: []mailpolicy.ComplianceHit{}}
	if err := q.Normalize(); err != nil {
		return out, err
	}
	where, args, err := complianceWhere(q, false)
	if err != nil {
		return out, err
	}
	args = append([]any{summaryVersion, q.ExcludeHeld}, args...)
	limit := "$" + strconv.Itoa(len(args)+1)
	args = append(args, q.Limit)
	// #nosec G202 -- where is built from fixed fragments; values are parameters
	rows, err := e.DB.QueryContext(ctx, complianceHits+`SELECT x.ref, x.address, x.folder, x.held, x.held_at, x.date, s.data, b.size, count(*) OVER ()
FROM hits x JOIN mailbox_summaries s ON s.body=x.body AND s.version=$1 JOIN mailbox_bodies b ON b.key=x.body`+where+`
ORDER BY x.date DESC, x.ref LIMIT `+limit, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var h mailpolicy.ComplianceHit
		var heldAt sql.NullTime
		var data []byte
		if err := rows.Scan(&h.Ref, &h.Account, &h.Folder, &h.Held, &heldAt, &h.Date, &data, &h.Size, &out.Total); err != nil {
			return out, err
		}
		if heldAt.Valid {
			t := heldAt.Time.UTC()
			h.HeldAt = &t
		}
		h.Date = h.Date.UTC()
		if sum, err := decodeSummary(data); err == nil && sum.Envelope != nil {
			h.Subject = sum.Envelope.Subject
			h.From = addressList(sum.Envelope.From)
			h.To = addressList(append(append(sum.Envelope.To, sum.Envelope.Cc...), sum.Envelope.Bcc...))
		}
		out.Hits = append(out.Hits, h)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Unindexed, err = e.complianceUnindexed(ctx, q)
	return out, err
}

// complianceUnindexed counts the messages in q's accounts and dates that
// have no current index entry, and so can't match anything.
func (e *Engine) complianceUnindexed(ctx context.Context, q mailpolicy.ComplianceQuery) (int, error) {
	where, args, err := complianceWhere(q, true)
	if err != nil {
		return 0, err
	}
	cond := " WHERE s.body IS NULL"
	if where != "" {
		cond = where + " AND s.body IS NULL"
	}
	var n int
	// #nosec G202 -- where is built from fixed fragments; values are parameters
	err = e.DB.QueryRowContext(ctx, complianceHits+`SELECT count(*) FROM hits x LEFT JOIN mailbox_summaries s ON s.body=x.body AND s.version=$1`+cond,
		append([]any{summaryVersion, q.ExcludeHeld}, args...)...).Scan(&n)
	return n, err
}

// ComplianceExport writes every match of q as mbox, oldest first, each
// message headed by an X-Elemta-Compliance line naming its account and
// folder. It refuses more than mailpolicy.MaxComplianceExport messages
// before writing anything, so an export is either whole or not started.
func (e *Engine) ComplianceExport(ctx context.Context, q mailpolicy.ComplianceQuery, w io.Writer) (int, error) {
	if err := q.Normalize(); err != nil {
		return 0, err
	}
	where, args, err := complianceWhere(q, false)
	if err != nil {
		return 0, err
	}
	args = append([]any{summaryVersion, q.ExcludeHeld}, args...)
	limit := "$" + strconv.Itoa(len(args)+1)
	args = append(args, mailpolicy.MaxComplianceExport+1)
	// #nosec G202 -- where is built from fixed fragments; values are parameters
	rows, err := e.DB.QueryContext(ctx, complianceHits+`SELECT x.address, x.folder, x.held_at, x.date, x.body
FROM hits x JOIN mailbox_summaries s ON s.body=x.body AND s.version=$1`+where+`
ORDER BY x.date, x.ref LIMIT `+limit, args...)
	if err != nil {
		return 0, err
	}
	type item struct {
		account, folder, body string
		heldAt                sql.NullTime
		date                  time.Time
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.account, &it.folder, &it.heldAt, &it.date, &it.body); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(items) > mailpolicy.MaxComplianceExport {
		return 0, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("more than %d messages match; narrow the search, or export it in parts by date", mailpolicy.MaxComplianceExport))
	}
	bw := bufio.NewWriter(w)
	for i, it := range items {
		raw, err := e.Bodies.Get(ctx, it.body, e.MaxBytes+1)
		if err != nil {
			return i, fmt.Errorf("message body %s: %w", it.body, err)
		}
		note := fmt.Sprintf("account=%q; folder=%q", it.account, it.folder)
		if it.heldAt.Valid {
			note += "; held " + it.heldAt.Time.UTC().Format(time.RFC3339)
		}
		writeMbox(bw, it.date, "X-Elemta-Compliance: "+note, raw)
	}
	return len(items), bw.Flush()
}

// ComplianceMessage returns one message found by a search, and the account
// it belongs to. domains, when set, confines it as Domains does a search.
func (e *Engine) ComplianceMessage(ctx context.Context, ref string, domains []string) ([]byte, string, error) {
	var row *sql.Row
	kind, rest, _ := strings.Cut(ref, ":")
	switch kind {
	case "m":
		f, u, ok := strings.Cut(rest, ":")
		folder, err1 := strconv.ParseInt(f, 10, 64)
		uid, err2 := strconv.ParseInt(u, 10, 64)
		if !ok || err1 != nil || err2 != nil {
			return nil, "", ErrNotFound
		}
		row = e.DB.QueryRowContext(ctx, `SELECT m.body, a.address FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder
JOIN mailbox_accounts a ON a.id=f.account WHERE m.folder=$1 AND m.uid=$2`, folder, uid)
	case "h":
		id, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			return nil, "", ErrNotFound
		}
		row = e.DB.QueryRowContext(ctx, `SELECT h.body, a.address FROM mailbox_held h JOIN mailbox_accounts a ON a.id=h.account WHERE h.id=$1`, id)
	default:
		return nil, "", ErrNotFound
	}
	var body, account string
	if err := row.Scan(&body, &account); errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	} else if err != nil {
		return nil, "", err
	}
	if len(domains) > 0 {
		_, domain, _ := strings.Cut(account, "@")
		inScope := false
		for _, d := range domains {
			inScope = inScope || strings.EqualFold(strings.TrimSpace(d), domain)
		}
		// Out of scope reads as missing, so refs can't be used to probe.
		if !inScope {
			return nil, "", ErrNotFound
		}
	}
	raw, err := e.Bodies.Get(ctx, body, e.MaxBytes+1)
	return raw, account, err
}

// addressList shows addresses as "Name <addr>", or the address alone,
// joined by commas.
func addressList(list []imap.Address) string {
	var out []string
	for _, a := range list {
		if a.IsGroupStart() || a.IsGroupEnd() {
			continue
		}
		s := a.Addr()
		if a.Name != "" {
			s = a.Name + " <" + s + ">"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// writeMbox writes one message in mboxrd form: a From line, an optional
// header line of our own, and the message with its From lines quoted.
func writeMbox(bw *bufio.Writer, date time.Time, extra string, raw []byte) {
	fmt.Fprintf(bw, "From MAILER-DAEMON %s\n", date.UTC().Format(time.ANSIC))
	if extra != "" {
		_, _ = bw.WriteString(strings.NewReplacer("\r", " ", "\n", " ").Replace(extra) + "\n")
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, line := range strings.SplitAfter(text, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, ">"), "From ") {
			line = ">" + line
		}
		_, _ = bw.WriteString(line)
	}
	if !strings.HasSuffix(text, "\n") {
		_ = bw.WriteByte('\n')
	}
	_ = bw.WriteByte('\n')
}
