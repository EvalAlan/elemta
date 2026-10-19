package mailbox

// Verify checks that the metadata and the body store agree: every body a
// message refers to exists with the recorded size and checksum, and each
// account's quota usage matches its messages. Run it after a restore, and
// now and then against production, sampling on large stores.

import (
	"context"
	"database/sql"
	"fmt"
)

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Checked int
	// Missing and Corrupt list body keys that couldn't be read or whose
	// size or checksum didn't match.
	Missing, Corrupt []string
	// QuotaDrift lists accounts whose recorded usage differs from the sum
	// of their messages.
	QuotaDrift []string
}

func (r VerifyReport) OK() bool {
	return len(r.Missing) == 0 && len(r.Corrupt) == 0 && len(r.QuotaDrift) == 0
}

// Verify checks referenced bodies (a random sample of that many when
// sample > 0) and quota usage. progress, if set, is called every 1000
// bodies.
func (e *Engine) Verify(ctx context.Context, sample int, progress func(done int)) (VerifyReport, error) {
	var r VerifyReport
	query := `SELECT b.key,b.size,b.checksum FROM mailbox_bodies b WHERE EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=b.key) ORDER BY b.key`
	args := []any{}
	if sample > 0 {
		query = `SELECT b.key,b.size,b.checksum FROM mailbox_bodies b WHERE EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=b.key) ORDER BY random() LIMIT $1`
		args = append(args, sample)
	}
	rows, err := e.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return r, err
	}
	var todo []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.Body, &m.Size, &m.Checksum); err != nil {
			rows.Close()
			return r, err
		}
		todo = append(todo, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	for _, m := range todo {
		raw, err := e.Bodies.Get(ctx, m.Body, m.Size)
		switch {
		case err != nil:
			r.Missing = append(r.Missing, m.Body)
		case int64(len(raw)) != m.Size || checksumOf(raw) != m.Checksum:
			r.Corrupt = append(r.Corrupt, m.Body)
		}
		r.Checked++
		if progress != nil && r.Checked%1000 == 0 {
			progress(r.Checked)
		}
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
	}
	qrows, err := e.DB.QueryContext(ctx, `SELECT a.address FROM mailbox_accounts a
LEFT JOIN (SELECT f.account, sum(b.size) AS used FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder JOIN mailbox_bodies b ON b.key=m.body GROUP BY f.account) u ON u.account=a.id
WHERE a.used_bytes <> coalesce(u.used,0)`)
	if err != nil {
		return r, fmt.Errorf("quota check: %w", err)
	}
	defer qrows.Close()
	for qrows.Next() {
		var addr sql.NullString
		if err := qrows.Scan(&addr); err != nil {
			return r, err
		}
		r.QuotaDrift = append(r.QuotaDrift, addr.String)
	}
	return r, qrows.Err()
}
