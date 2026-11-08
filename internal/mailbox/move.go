package mailbox

// Moving one mailbox from its cell to another (cells.go).
//
// Unlike a restore, a move keeps everything as it was: folders keep their
// UIDVALIDITY, messages their UIDs, flags and modification sequences, so
// mail apps carry on without downloading the mailbox again. Settings,
// filters, two-step sign-in, passkeys, app passwords, shares it grants,
// push subscriptions, PGP keys and the rest go too; what is only a cache
// or a moment's state (the change journal, POP3 locks, sign-in challenges,
// admin access grants) stays behind.
//
// The source is frozen first: the account is made read-only, which waits
// for writes in progress (each takes the account row's lock) and makes
// later ones fail; deliveries meanwhile get a temporary failure, so the
// MTA retries them, by then to the new cell. Bodies are copied through
// both cells' body stores (each decrypts and encrypts with its own keys)
// and checked against their checksums; then the metadata is written in one
// transaction on the destination, and counted against the source.
//
// MoveAccount only copies. The caller then places the account in the new
// cell in the directory (SetCell), waits for routers' caches to expire,
// and purges the source. Until it does, the source stays read-only; run
// again, a move that stopped part way starts over cleanly.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// MoveReport says what a move copied.
type MoveReport struct {
	Address  string         `json:"address"`
	Account  string         `json:"account"`
	Folders  int            `json:"folders"`
	Messages int            `json:"messages"`
	Bodies   int            `json:"bodies"`
	Bytes    int64          `json:"bytes"`
	Rows     map[string]int `json:"rows"`
	// Skipped are rows that couldn't come because they name an account
	// in another cell (shares with someone who stays behind).
	Skipped map[string]int `json:"skipped,omitempty"`
}

// moveTables are copied by account, in this order. key is the column
// naming the account ("address" means its address, not its ID).
var moveTables = []struct{ table, key string }{
	{"mailbox_security", "account"},
	{"mailbox_app_passwords", "account"},
	{"mailbox_passkeys", "account"},
	{"mailbox_session_tokens", "account"},
	{"mailbox_pgp_keys", "account"},
	{"mailbox_pgp_pins", "account"},
	{"mailbox_sieve_scripts", "account"},
	{"mailbox_sieve_sent", "account"},
	{"mailbox_sender_rules", "account"},
	{"mailbox_category_rules", "account"},
	{"mailbox_deliveries", "account"},
	{"mailbox_freebusy", "account"},
	{"mailbox_push_subscriptions", "account"},
	{"mailbox_push_reminders", "account"},
	{"mailbox_resources", "account"},
	{"mailbox_spam_feedback", "account"},
	{"mailbox_held", "account"},
	{"mailbox_shares", "mailbox"},
	{"mailbox_calendar_shares", "owner"},
	{"mailbox_account_policy", "address"},
}

// errMoveTarget is a destination that already holds the account for real.
var errMoveTarget = errors.New("the destination cell already has this mailbox")

// MoveAccount copies address's mailbox from src to dst, leaving src
// read-only. progress, if set, hears what it is doing.
func MoveAccount(ctx context.Context, src, dst *Engine, address string, progress func(string)) (MoveReport, error) {
	say := func(format string, args ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, args...))
		}
	}
	address = strings.ToLower(strings.TrimSpace(address))
	r := MoveReport{Address: address, Rows: map[string]int{}, Skipped: map[string]int{}}
	ctx = context.WithValue(ctx, skippedKey{}, r.Skipped)
	var id string
	err := src.DB.QueryRowContext(ctx, `SELECT id FROM mailbox_accounts WHERE address=$1`, address).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.Account = id

	// A destination row that is read-only is a move that stopped part way:
	// clear it and start again. A writable one is a real mailbox.
	var dstWritable bool
	switch err := dst.DB.QueryRowContext(ctx, `SELECT writable FROM mailbox_accounts WHERE id=$1`, id).Scan(&dstWritable); {
	case err == nil && dstWritable:
		return r, errMoveTarget
	case err == nil:
		say("clearing an earlier, unfinished copy")
		if err := clearAccount(ctx, dst.DB, id, address); err != nil {
			return r, err
		}
	case !errors.Is(err, sql.ErrNoRows):
		return r, err
	}

	say("freezing the mailbox in its cell")
	if _, err := src.DB.ExecContext(ctx, `UPDATE mailbox_accounts SET writable=false WHERE id=$1`, id); err != nil {
		return r, err
	}

	// Bodies first, outside the transaction: they are the slow part.
	keys, err := moveBodyKeys(ctx, src.DB, id)
	if err != nil {
		return r, err
	}
	say("copying %d message bodies", len(keys))
	for i, k := range keys {
		n, err := moveBody(ctx, src, dst, k)
		if err != nil {
			return r, fmt.Errorf("body %s: %w", k.key, err)
		}
		r.Bodies++
		r.Bytes += n
		if (i+1)%500 == 0 {
			say("copied %d of %d bodies", i+1, len(keys))
		}
	}

	say("copying folders, messages and settings")
	tx, err := dst.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer func() { _ = tx.Rollback() }()
	// The account arrives read-only and becomes writable last, in the same
	// transaction, so a copy that fails part way is visibly unfinished.
	if _, err := copyRows(ctx, src.DB, tx, "mailbox_accounts", "id=$1", []any{id}, nil, map[string]string{"writable": "false", "reserved_bytes": "0"}); err != nil {
		return r, err
	}
	folders, err := moveFolders(ctx, src.DB, tx, id)
	if err != nil {
		return r, err
	}
	r.Folders = len(folders)
	for old, folder := range folders {
		n, err := copyRows(ctx, src.DB, tx, "mailbox_messages", "folder=$1", []any{old}, nil, map[string]string{"folder": fmt.Sprint(folder)})
		if err != nil {
			return r, err
		}
		r.Messages += n
	}
	// Scheduled sends and snoozes name their message by folder ID, so they
	// follow it folder by folder, after it. Any claim is left behind: the
	// source account is read-only from here, and the scheduler skips
	// read-only accounts, so only the new cell acts on them.
	for _, table := range []string{"mailbox_scheduled_sends", "mailbox_snoozes"} {
		total := 0
		for old, folder := range folders {
			n, err := copyRows(ctx, src.DB, tx, table, "folder=$1", []any{old}, map[string]bool{"claimed_until": true}, map[string]string{"folder": fmt.Sprint(folder)})
			if err != nil {
				return r, fmt.Errorf("%s: %w", table, err)
			}
			total += n
		}
		r.Rows[table] = total
	}
	passkeys := map[string]string{}
	for _, t := range moveTables {
		arg := any(id)
		if t.key == "address" {
			arg = address
		}
		var n int
		switch t.table {
		case "mailbox_passkeys":
			n, err = movePasskeys(ctx, src.DB, tx, id, passkeys)
		case "mailbox_session_tokens":
			n, err = moveSessionTokens(ctx, src.DB, tx, id, passkeys)
		default:
			n, err = copyRows(ctx, src.DB, tx, t.table, pq.QuoteIdentifier(t.key)+"=$1", []any{arg}, serialColumns(t.table), nil)
		}
		if err != nil {
			return r, fmt.Errorf("%s: %w", t.table, err)
		}
		r.Rows[t.table] = n
	}
	// Check before it counts: the same messages, the same bytes.
	var srcCount, dstCount int
	var srcUsed, dstUsed int64
	if err := src.DB.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1`, id).Scan(&srcCount); err != nil {
		return r, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1`, id).Scan(&dstCount); err != nil {
		return r, err
	}
	if err := src.DB.QueryRowContext(ctx, `SELECT used_bytes FROM mailbox_accounts WHERE id=$1`, id).Scan(&srcUsed); err != nil {
		return r, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM mailbox_accounts WHERE id=$1`, id).Scan(&dstUsed); err != nil {
		return r, err
	}
	if srcCount != dstCount || srcUsed != dstUsed {
		return r, fmt.Errorf("copy doesn't match: %d messages and %d bytes in the source, %d and %d copied", srcCount, srcUsed, dstCount, dstUsed)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mailbox_accounts SET writable=true WHERE id=$1`, id); err != nil {
		return r, err
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	say("copied %d folders, %d messages, %d bodies (%d bytes)", r.Folders, r.Messages, r.Bodies, r.Bytes)
	return r, nil
}

// clearAccount removes an unfinished copy of an account.
func clearAccount(ctx context.Context, db *sql.DB, id, address string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i := len(moveTables) - 1; i >= 0; i-- {
		t := moveTables[i]
		arg := any(id)
		if t.key == "address" {
			arg = address
		}
		// #nosec G202 -- table and column names are this file's constants, quoted
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+pq.QuoteIdentifier(t.table)+` WHERE `+pq.QuoteIdentifier(t.key)+`=$1`, arg); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`DELETE FROM mailbox_messages WHERE folder IN (SELECT id FROM mailbox_folders WHERE account=$1)`,
		`DELETE FROM mailbox_folders WHERE account=$1`,
		`DELETE FROM mailbox_accounts WHERE id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type movingBody struct {
	key, checksum string
	size          int64
}

// moveBodyKeys lists the bodies the account's messages and held mail use.
func moveBodyKeys(ctx context.Context, db *sql.DB, account string) ([]movingBody, error) {
	rows, err := db.QueryContext(ctx, `SELECT b.key,b.checksum,b.size FROM mailbox_bodies b WHERE b.key IN (
		SELECT m.body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1
		UNION SELECT body FROM mailbox_held WHERE account=$1) ORDER BY b.key`, account)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []movingBody
	for rows.Next() {
		var b movingBody
		if err := rows.Scan(&b.key, &b.checksum, &b.size); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// moveBody copies one body and its summary, keeping its key. A body the
// destination already has (an earlier attempt) is left as it is.
func moveBody(ctx context.Context, src, dst *Engine, b movingBody) (int64, error) {
	var have bool
	if err := dst.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_bodies WHERE key=$1 AND state='ready')`, b.key).Scan(&have); err != nil {
		return 0, err
	}
	if have {
		return 0, nil
	}
	raw, err := src.Bodies.Get(ctx, b.key, b.size)
	if err != nil {
		return 0, err
	}
	if !matchesBody(raw, b.size, b.checksum) {
		return 0, errors.New("checksum mismatch in the source")
	}
	if err := dst.Bodies.Put(ctx, b.key, raw); err != nil {
		return 0, err
	}
	if _, err := dst.DB.ExecContext(ctx, `INSERT INTO mailbox_bodies(key,size,checksum,store,state) VALUES($1,$2,$3,$4,'ready')
		ON CONFLICT (key) DO UPDATE SET state='ready', store=EXCLUDED.store`, b.key, b.size, b.checksum, dst.Bodies.Identity()); err != nil {
		return 0, err
	}
	// The summary is the search index's row; without it the message
	// would be found only once a backfill ran.
	tx, err := dst.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_summaries WHERE body=$1`, b.key); err != nil {
		return 0, err
	}
	if _, err := copyRows(ctx, src.DB, tx, "mailbox_summaries", "body=$1", []any{b.key}, nil, nil); err != nil {
		return 0, err
	}
	return b.size, tx.Commit()
}

// moveFolders copies the account's folders, keeping UIDVALIDITY, next UID
// and MODSEQ, and returns their new IDs by old. The change journal stays
// behind: journal_floor at the current MODSEQ makes any session that knew
// the old cell take a fresh look.
func moveFolders(ctx context.Context, src *sql.DB, tx *sql.Tx, account string) (map[int64]int64, error) {
	rows, err := src.QueryContext(ctx, `SELECT id,name FROM mailbox_folders WHERE account=$1 ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	type folder struct {
		id   int64
		name string
	}
	var folders []folder
	for rows.Next() {
		var f folder
		if err := rows.Scan(&f.id, &f.name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		folders = append(folders, f)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[int64]int64{}
	for _, f := range folders {
		if _, err := copyRows(ctx, src, tx, "mailbox_folders", "id=$1", []any{f.id}, map[string]bool{"id": true}, nil); err != nil {
			return nil, err
		}
		var id int64
		if err := tx.QueryRowContext(ctx, `UPDATE mailbox_folders SET journal_floor=modseq WHERE account=$1 AND name=$2 RETURNING id`, account, f.name).Scan(&id); err != nil {
			return nil, err
		}
		out[f.id] = id
	}
	return out, nil
}

// movePasskeys copies passkeys under new IDs, recording them by old ID for
// the sessions that signed in with them.
func movePasskeys(ctx context.Context, src *sql.DB, tx *sql.Tx, account string, ids map[string]string) (int, error) {
	rows, err := src.QueryContext(ctx, `SELECT id::text FROM mailbox_passkeys WHERE account=$1 ORDER BY id`, account)
	if err != nil {
		return 0, err
	}
	var old []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		old = append(old, id)
	}
	_ = rows.Close()
	for _, id := range old {
		if _, err := copyRows(ctx, src, tx, "mailbox_passkeys", "id=$1::bigint", []any{id}, map[string]bool{"id": true}, nil); err != nil {
			return 0, err
		}
		var newID string
		if err := tx.QueryRowContext(ctx, `SELECT max(id)::text FROM mailbox_passkeys WHERE account=$1`, account).Scan(&newID); err != nil {
			return 0, err
		}
		ids[id] = newID
	}
	return len(old), nil
}

// moveSessionTokens copies "stay signed in" sessions, pointing those that
// signed in with a passkey at its new ID.
func moveSessionTokens(ctx context.Context, src *sql.DB, tx *sql.Tx, account string, passkeys map[string]string) (int, error) {
	n, err := copyRows(ctx, src, tx, "mailbox_session_tokens", "account=$1", []any{account}, nil, nil)
	if err != nil {
		return 0, err
	}
	for old, id := range passkeys {
		if _, err := tx.ExecContext(ctx, `UPDATE mailbox_session_tokens SET passkey=$3::bigint WHERE account=$1 AND passkey=$2::bigint`, account, old, id); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// serialColumns are a table's generated IDs, which the destination
// numbers afresh. Nothing that moves refers to them.
func serialColumns(table string) map[string]bool {
	switch table {
	case "mailbox_app_passwords", "mailbox_push_subscriptions", "mailbox_held":
		return map[string]bool{"id": true}
	}
	return nil
}

// copyRows copies the rows of table matching where from src into tx, the
// columns both databases have, as text cast back to each column's type,
// so any type survives. omit leaves columns to their defaults; set
// replaces a column's value with a literal (cast to its type). Rows the
// destination already has (by a unique key) are skipped.
func copyRows(ctx context.Context, src *sql.DB, tx *sql.Tx, table, where string, args []any, omit map[string]bool, set map[string]string) (int, error) {
	cols, types, err := sharedColumns(ctx, src, tx, table)
	if err != nil {
		return 0, err
	}
	var keep []int
	for i, c := range cols {
		if !omit[c] {
			keep = append(keep, i)
		}
	}
	sel := make([]string, len(keep))
	ins := make([]string, len(keep))
	vals := make([]string, len(keep))
	for j, i := range keep {
		q := pq.QuoteIdentifier(cols[i])
		sel[j] = q + "::text"
		ins[j] = q
		vals[j] = fmt.Sprintf("$%d::%s", j+1, types[i])
	}
	// #nosec G202 -- table and column names come from the code and the catalog, quoted
	rows, err := src.QueryContext(ctx, `SELECT `+strings.Join(sel, ",")+` FROM `+pq.QuoteIdentifier(table)+` WHERE `+where, args...)
	if err != nil {
		return 0, err
	}
	var batch [][]any
	for rows.Next() {
		row := make([]sql.NullString, len(keep))
		ptrs := make([]any, len(keep))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			_ = rows.Close()
			return 0, err
		}
		vs := make([]any, len(keep))
		for j, i := range keep {
			if v, ok := set[cols[i]]; ok {
				vs[j] = v
				continue
			}
			if row[j].Valid {
				vs[j] = row[j].String
			}
		}
		batch = append(batch, vs)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// #nosec G202 -- as above
	stmt := `INSERT INTO ` + pq.QuoteIdentifier(table) + `(` + strings.Join(ins, ",") + `) VALUES(` + strings.Join(vals, ",") + `) ON CONFLICT DO NOTHING`
	n := 0
	for _, vs := range batch {
		// A row naming an account the destination doesn't have (a share
		// with someone who stays in the old cell) can't come, and couldn't
		// work across cells: it is left out and counted.
		if _, err := tx.ExecContext(ctx, `SAVEPOINT move_row`); err != nil {
			return n, err
		}
		res, err := tx.ExecContext(ctx, stmt, vs...)
		var pe *pq.Error
		if errors.As(err, &pe) && pe.Code == "23503" {
			if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT move_row`); err != nil {
				return n, err
			}
			moveSkipped(ctx, table)
			continue
		}
		if err != nil {
			return n, err
		}
		if k, _ := res.RowsAffected(); k > 0 {
			n++
		}
	}
	return n, nil
}

type skippedKey struct{}

// moveSkipped counts a row left out, in the counter MoveAccount put in ctx.
func moveSkipped(ctx context.Context, table string) {
	if m, ok := ctx.Value(skippedKey{}).(map[string]int); ok {
		m[table]++
	}
}

// sharedColumns lists the columns table has in both databases, with their
// types in the destination.
func sharedColumns(ctx context.Context, src *sql.DB, tx *sql.Tx, table string) ([]string, []string, error) {
	const q = `SELECT a.attname, format_type(a.atttypid,a.atttypmod) FROM pg_attribute a
		WHERE a.attrelid=to_regclass($1) AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`
	have := map[string]bool{}
	rows, err := src.QueryContext(ctx, q, table)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		have[name] = true
	}
	_ = rows.Close()
	rows, err = tx.QueryContext(ctx, q, table)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	var cols, types []string
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return nil, nil, err
		}
		if have[name] {
			cols, types = append(cols, name), append(types, typ)
		}
	}
	if len(cols) == 0 {
		return nil, nil, fmt.Errorf("table %s isn't in both cells", table)
	}
	return cols, types, rows.Err()
}

// Placement is the directory client a service uses, for moving accounts
// between cells; false when the service has none (tests).
func (s *Service) Placement() (LDAPAuth, bool) {
	auth := s.auth
	if d, ok := auth.(domainStatusAuth); ok {
		auth = d.Authenticator
	}
	a, ok := auth.(LDAPAuth)
	return a, ok
}
