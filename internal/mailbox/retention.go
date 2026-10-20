package mailbox

// Retention and legal hold, set by class of service (internal/mailpolicy).
//
// Retention deletes old mail on a schedule: Trash and Junk after a number
// of days in the folder, and optionally everything older than a number of
// days by the message's own date. It runs hourly on one replica at a time
// and deletes through the normal expunge, so quota, the change journal and
// connected clients see it like any other delete.
//
// Legal hold keeps everything for an account under investigation or
// litigation. The user still sees and uses their mailbox normally, but
// anything removed for good (an expunge, a deleted folder, a POP3 delete)
// is first copied into mailbox_held, where no protocol can reach it, with
// its body kept alive. Retention skips held accounts and purging them is
// refused. An administrator exports the held mail as mbox (ExportHeld).

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lib/pq"
)

// onHold reports whether an account's class of service puts it on legal
// hold. An account the mailbox has no address for isn't held.
func (e *Engine) onHold(ctx context.Context, account string) (bool, error) {
	var address string
	err := e.DB.QueryRowContext(ctx, `SELECT address FROM mailbox_accounts WHERE id=$1`, account).Scan(&address)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	eff, err := e.EffectivePolicy(ctx, address, 0)
	return eff.LegalHold, err
}

// holdMessages copies messages of folder f about to be removed into the
// hold, inside the removing transaction, so a message is never gone without
// its held copy. A nil uids holds the whole folder.
func holdMessages(ctx context.Context, tx *sql.Tx, account string, f Folder, uids []int64, reason string) error {
	q := `INSERT INTO mailbox_held(account,folder,body,flags,internal_date,reason)
SELECT $1,$2,m.body,m.flags,m.internal_date,$3 FROM mailbox_messages m WHERE m.folder=$4`
	args := []any{account, f.Name, reason, f.ID}
	if uids != nil {
		q += ` AND m.uid=ANY($5)`
		args = append(args, pq.Array(uids))
	}
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

// HeldCount is how many messages an account has on hold.
func (e *Engine) HeldCount(ctx context.Context, address string) (int, error) {
	var n int
	err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_held h JOIN mailbox_accounts a ON a.id=h.account WHERE a.address=$1`, strings.ToLower(address)).Scan(&n)
	return n, err
}

// ExportHeld writes an address's held mail as mbox (one message after
// another, each after a "From " line, with ">From " quoting), the format
// every mail tool and e-discovery product reads. An X-Elemta-Held header
// records the folder it was deleted from and when.
func (e *Engine) ExportHeld(ctx context.Context, address string, w io.Writer) (int, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT h.body, h.folder, h.internal_date, h.held_at, h.reason FROM mailbox_held h
JOIN mailbox_accounts a ON a.id=h.account WHERE a.address=$1 ORDER BY h.id`, strings.ToLower(address))
	if err != nil {
		return 0, err
	}
	type item struct {
		body, folder, reason string
		date, heldAt         time.Time
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.body, &it.folder, &it.date, &it.heldAt, &it.reason); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	bw := bufio.NewWriter(w)
	n := 0
	for _, it := range items {
		raw, err := e.Bodies.Get(ctx, it.body, e.MaxBytes+1)
		if err != nil {
			return n, fmt.Errorf("held message body %s: %w", it.body, err)
		}
		fmt.Fprintf(bw, "From MAILER-DAEMON %s\n", it.date.UTC().Format(time.ANSIC))
		fmt.Fprintf(bw, "X-Elemta-Held: folder=%q; %s; held %s\n", it.folder, it.reason, it.heldAt.UTC().Format(time.RFC3339))
		for _, line := range strings.SplitAfter(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, ">"), "From ") {
				line = ">" + line
			}
			_, _ = bw.WriteString(line)
		}
		if !strings.HasSuffix(string(raw), "\n") {
			_ = bw.WriteByte('\n')
		}
		_ = bw.WriteByte('\n')
		n++
	}
	return n, bw.Flush()
}

// RetentionReport counts one retention pass.
type RetentionReport struct {
	Accounts int
	Deleted  int
}

// maxRetentionBatch bounds one pass's deletes per folder, so a first pass
// over years of mail doesn't hold locks for long; the next pass continues.
const maxRetentionBatch = 1000

// Retention applies every account's retention rules once. It takes a
// session-level advisory lock so only one replica works at a time; the
// others return at once.
func (e *Engine) Retention(ctx context.Context, now time.Time) (RetentionReport, error) {
	var rep RetentionReport
	conn, err := e.DB.Conn(ctx)
	if err != nil {
		return rep, err
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended('elemta-mailbox-retention',0))`).Scan(&locked); err != nil || !locked {
		return rep, err
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended('elemta-mailbox-retention',0))`)
	}()

	rows, err := e.DB.QueryContext(ctx, `SELECT id, address FROM mailbox_accounts ORDER BY id`)
	if err != nil {
		return rep, err
	}
	type acct struct{ id, address string }
	var accounts []acct
	for rows.Next() {
		var a acct
		if err := rows.Scan(&a.id, &a.address); err != nil {
			_ = rows.Close()
			return rep, err
		}
		accounts = append(accounts, a)
	}
	if err := rows.Close(); err != nil {
		return rep, err
	}
	for _, a := range accounts {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		eff, err := e.EffectivePolicy(ctx, a.address, 0)
		if err != nil {
			return rep, err
		}
		if eff.LegalHold || eff.TrashDays == 0 && eff.JunkDays == 0 && eff.RetentionDays == 0 {
			continue
		}
		rep.Accounts++
		day := 24 * time.Hour
		rules := []struct {
			folders []string
			days    int
			column  string
		}{
			{[]string{"Trash", "Deleted Items", "Deleted Messages"}, eff.TrashDays, "added"},
			{[]string{"Junk", "Spam", "Junk E-mail"}, eff.JunkDays, "added"},
		}
		for _, r := range rules {
			if r.days == 0 {
				continue
			}
			for _, folder := range r.folders {
				n, err := e.expireFolder(ctx, a.id, folder, r.column, now.Add(-time.Duration(r.days)*day))
				if err != nil {
					return rep, err
				}
				rep.Deleted += n
			}
		}
		if eff.RetentionDays > 0 {
			folders, err := e.Folders(ctx, a.id)
			if err != nil {
				return rep, err
			}
			for _, f := range folders {
				n, err := e.expireFolder(ctx, a.id, f.Name, "internal_date", now.Add(-time.Duration(eff.RetentionDays)*day))
				if err != nil {
					return rep, err
				}
				rep.Deleted += n
			}
		}
	}
	return rep, nil
}

// expireQueries are the two ways a message's age is measured, written out
// whole rather than built from the column name.
var expireQueries = map[string]string{
	"added": `SELECT m.uid FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder
WHERE f.account=$1 AND f.name=$2 AND COALESCE(m.added,m.internal_date)<$3 ORDER BY m.uid LIMIT $4`,
	"internal_date": `SELECT m.uid FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder
WHERE f.account=$1 AND f.name=$2 AND m.internal_date<$3 ORDER BY m.uid LIMIT $4`,
}

// expireFolder deletes a folder's messages whose column (added or
// internal_date) is before cutoff. A folder the account doesn't have is
// nothing to do.
func (e *Engine) expireFolder(ctx context.Context, account, folder, column string, cutoff time.Time) (int, error) {
	query, ok := expireQueries[column]
	if !ok {
		return 0, errors.New("retention: unknown date column")
	}
	rows, err := e.DB.QueryContext(ctx, query, account, folder, cutoff, maxRetentionBatch)
	if err != nil {
		return 0, err
	}
	var uids []uint32
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			_ = rows.Close()
			return 0, err
		}
		uids = append(uids, uint32(uid)) // #nosec G115 -- IMAP UIDs are 32-bit
	}
	if err := rows.Close(); err != nil || len(uids) == 0 {
		return 0, err
	}
	removed, err := e.expunge(ctx, account, folder, uids, false, "")
	return len(removed), err
}
