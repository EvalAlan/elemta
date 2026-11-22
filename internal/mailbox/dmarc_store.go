package mailbox

// Storage for received DMARC reports (dmarc.go).

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/dmarcrpt"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/lib/pq"
)

const (
	dmarcKeep = 400 * 24 * time.Hour

	// Anyone can mail a report address, and a verified sender only proves
	// they own some domain, so what one domain can be made to store in a day
	// is bounded, unverified reports far more tightly.
	dmarcVerifiedRowsPerDay   = 200_000
	dmarcUnverifiedRowsPerDay = 10_000
	dmarcUnverifiedPerDay     = 200
	dmarcVerifiedPerDay       = 5000
	dmarcSummaryLimit         = 20_000
	dmarcBackfillStale        = dmarcBackfillTime + time.Minute
)

const dmarcAddressColumns = `domain,address,backfill_started,backfill_finished,backfill_read,backfill_stored,backfill_unindexed,backfill_error`

func scanDMARCAddress(row interface{ Scan(...any) error }) (mailpolicy.DMARCAddress, error) {
	var a mailpolicy.DMARCAddress
	var started, finished sql.NullTime
	err := row.Scan(&a.Domain, &a.Address, &started, &finished, &a.BackfillRead, &a.BackfillStored, &a.BackfillUnindexed, &a.BackfillError)
	if started.Valid {
		a.BackfillStarted = &started.Time
	}
	if finished.Valid {
		a.BackfillFinished = &finished.Time
	}
	return a, err
}

// DMARCAddresses lists the registered report addresses.
func (e *Engine) DMARCAddresses(ctx context.Context) ([]mailpolicy.DMARCAddress, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT `+dmarcAddressColumns+` FROM mailbox_dmarc_addresses ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DMARCAddress{}
	for rows.Next() {
		a, err := scanDMARCAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetDMARCAddress registers where domain's reports arrive. A new address
// starts with no backfill state.
func (e *Engine) SetDMARCAddress(ctx context.Context, domain, address string) (mailpolicy.DMARCAddress, error) {
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_dmarc_addresses(domain,address) VALUES($1,$2)
ON CONFLICT(domain) DO UPDATE SET address=EXCLUDED.address, backfill_started=NULL, backfill_finished=NULL,
 backfill_read=0, backfill_stored=0, backfill_unindexed=0, backfill_error=''
WHERE mailbox_dmarc_addresses.address<>EXCLUDED.address`, domain, address)
	if err != nil {
		return mailpolicy.DMARCAddress{}, err
	}
	return scanDMARCAddress(e.DB.QueryRowContext(ctx, `SELECT `+dmarcAddressColumns+` FROM mailbox_dmarc_addresses WHERE domain=$1`, domain))
}

// DeleteDMARCAddress unregisters it. Reports already stored age out.
func (e *Engine) DeleteDMARCAddress(ctx context.Context, domain string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_dmarc_addresses WHERE domain=$1`, domain)
	return err
}

// startDMARCBackfill claims the backfill and returns the address to read.
// One that a restart cut short can be claimed again once it's stale.
func (e *Engine) startDMARCBackfill(ctx context.Context, domain string, now time.Time) (string, error) {
	var address string
	err := e.DB.QueryRowContext(ctx, `UPDATE mailbox_dmarc_addresses
SET backfill_started=$2, backfill_finished=NULL, backfill_read=0, backfill_stored=0, backfill_unindexed=0, backfill_error=''
WHERE domain=$1 AND (backfill_started IS NULL OR backfill_finished IS NOT NULL OR backfill_started<$3)
RETURNING address`, domain, now, now.Add(-dmarcBackfillStale)).Scan(&address)
	if !errors.Is(err, sql.ErrNoRows) {
		return address, err
	}
	var exists bool
	if err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_dmarc_addresses WHERE domain=$1)`, domain).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return "", errors.Join(ErrInUse, errors.New("that domain's reports are already being read"))
	}
	return "", ErrNotFound
}

func (e *Engine) finishDMARCBackfill(ctx context.Context, domain, address string, res backfillResult, problem string) error {
	_, err := e.DB.ExecContext(ctx, `UPDATE mailbox_dmarc_addresses
SET backfill_finished=now(), backfill_read=$3, backfill_stored=$4, backfill_unindexed=$5, backfill_error=$6
WHERE domain=$1 AND address=$2`, domain, address, res.read, res.stored, res.unindexed, problem)
	return err
}

// storeDMARCReport stores a report once. It reports false for one already
// stored, too old to keep, or over the day's limits.
func (e *Engine) storeDMARCReport(ctx context.Context, r dmarcReport, now time.Time) (stored bool, err error) {
	f := r.feedback
	begins := time.Unix(f.ReportMetadata.DateRange.Begin, 0).UTC()
	if now.Sub(begins) > dmarcKeep {
		return false, nil
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	day := r.received.UTC().Truncate(24 * time.Hour)
	var reports, records int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(records),0) FROM mailbox_dmarc_reports
WHERE domain=$1 AND verified=$2 AND received>=$3 AND received<$4`, r.domain, r.verified, day, day.Add(24*time.Hour)).Scan(&reports, &records); err != nil {
		return false, err
	}
	maxReports, maxRows := int64(dmarcVerifiedPerDay), int64(dmarcVerifiedRowsPerDay)
	if !r.verified {
		maxReports, maxRows = dmarcUnverifiedPerDay, dmarcUnverifiedRowsPerDay
	}
	if reports >= maxReports || records+int64(len(f.Records)) > maxRows {
		return false, nil
	}
	p, m := f.PolicyPublished, f.ReportMetadata
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO mailbox_dmarc_reports(domain,policy_domain,verified,sender,report_id,org,p,sp,pct,begins,ends,received,records)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT(verified,sender,policy_domain,report_id) DO NOTHING RETURNING id`,
		r.domain, p.Domain, r.verified, r.sender, m.ReportID, m.OrgName, p.P, p.SP, p.Pct, begins,
		time.Unix(m.DateRange.End, 0).UTC(), r.received, len(f.Records)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n := len(f.Records)
	ips, froms, dispositions := make([]string, n), make([]string, n), make([]string, n)
	dkims, spfs, dkimDomains, spfDomains := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	counts := make([]int64, n)
	for i, rec := range f.Records {
		ips[i], froms[i], counts[i] = rec.Row.SourceIP, rec.Identifiers.HeaderFrom, rec.Row.Count
		e := rec.Row.PolicyEvaluated
		dispositions[i], dkims[i], spfs[i] = e.Disposition, e.DKIM, e.SPF
		dkimDomains[i] = authDomain(rec.AuthResults.DKIM)
		for _, a := range rec.AuthResults.SPF {
			if a.Domain != "" {
				spfDomains[i] = a.Domain
				break
			}
		}
	}
	if n > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO mailbox_dmarc_rows(report,source_ip,header_from,messages,disposition,dkim,spf,dkim_domain,spf_domain)
SELECT $1,v.* FROM unnest($2::text[],$3::text[],$4::bigint[],$5::text[],$6::text[],$7::text[],$8::text[],$9::text[]) AS v(source_ip,header_from,messages,disposition,dkim,spf,dkim_domain,spf_domain)`,
			id, pq.Array(ips), pq.Array(froms), pq.Array(counts), pq.Array(dispositions), pq.Array(dkims), pq.Array(spfs), pq.Array(dkimDomains), pq.Array(spfDomains)); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// authDomain is the signature that best names a source: one that passed, or
// failing that the first.
func authDomain(sigs []dmarcrpt.DKIMResult) string {
	first := ""
	for _, a := range sigs {
		if a.Domain == "" {
			continue
		}
		if a.Result == "pass" {
			return a.Domain
		}
		if first == "" {
			first = a.Domain
		}
	}
	return first
}

// DMARCSummary is the counts by domain, day and reporter since a time.
func (e *Engine) DMARCSummary(ctx context.Context, domains []string, since time.Time) ([]mailpolicy.DMARCDay, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT r.domain, r.policy_domain, to_char(r.begins AT TIME ZONE 'UTC','YYYY-MM-DD') AS day, r.sender, max(r.org), r.verified,
 (array_agg(r.p ORDER BY r.begins DESC))[1], (array_agg(r.sp ORDER BY r.begins DESC))[1], (array_agg(r.pct ORDER BY r.begins DESC))[1],
 count(*), coalesce(sum(t.messages),0)::bigint, coalesce(sum(t.aligned),0)::bigint, coalesce(sum(t.quarantined),0)::bigint, coalesce(sum(t.rejected),0)::bigint
FROM mailbox_dmarc_reports r
LEFT JOIN LATERAL (SELECT sum(messages) AS messages,
  sum(messages) FILTER (WHERE dkim='pass' OR spf='pass') AS aligned,
  sum(messages) FILTER (WHERE disposition='quarantine') AS quarantined,
  sum(messages) FILTER (WHERE disposition='reject') AS rejected
 FROM mailbox_dmarc_rows WHERE report=r.id) t ON true
WHERE r.begins>=$1 AND (cardinality($2::text[])=0 OR r.domain=ANY($2))
GROUP BY r.domain, r.policy_domain, day, r.sender, r.verified
ORDER BY r.verified DESC, day DESC, r.domain, r.sender LIMIT $3`, since, pq.Array(nonNil(domains)), dmarcSummaryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DMARCDay{}
	for rows.Next() {
		var d mailpolicy.DMARCDay
		if err := rows.Scan(&d.Domain, &d.PolicyDomain, &d.Day, &d.Sender, &d.Org, &d.Verified, &d.P, &d.SP, &d.Pct,
			&d.Reports, &d.Messages, &d.Aligned, &d.Quarantined, &d.Rejected); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DMARCSources is the busiest sources since a time. Verified ones come
// first, so a flood of made-up reports can't push them past the limit.
func (e *Engine) DMARCSources(ctx context.Context, domains []string, since time.Time) ([]mailpolicy.DMARCSource, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT r.domain, t.source_ip, t.header_from, t.disposition, t.dkim, t.spf, t.dkim_domain, t.spf_domain, r.verified, sum(t.messages)::bigint AS total
FROM mailbox_dmarc_reports r JOIN mailbox_dmarc_rows t ON t.report=r.id
WHERE r.begins>=$1 AND (cardinality($2::text[])=0 OR r.domain=ANY($2))
GROUP BY r.domain, t.source_ip, t.header_from, t.disposition, t.dkim, t.spf, t.dkim_domain, t.spf_domain, r.verified
ORDER BY r.verified DESC, total DESC, t.source_ip LIMIT $3`, since, pq.Array(nonNil(domains)), mailpolicy.DMARCSourceLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mailpolicy.DMARCSource{}
	for rows.Next() {
		var d mailpolicy.DMARCSource
		if err := rows.Scan(&d.Domain, &d.SourceIP, &d.HeaderFrom, &d.Disposition, &d.DKIM, &d.SPF, &d.DKIMDomain, &d.SPFDomain, &d.Verified, &d.Messages); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// nonNil keeps "all domains" from reaching Postgres as NULL, which has no
// cardinality.
func nonNil(v []string) []string {
	out := []string{}
	for _, s := range v {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func (e *Engine) deleteOldDMARC(ctx context.Context, now time.Time) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_dmarc_reports WHERE begins<$1`, now.Add(-dmarcKeep))
	return err
}
