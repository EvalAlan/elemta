package mailbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrNotFound = errors.New("mailbox not found")
	ErrExists   = errors.New("mailbox already exists")
	ErrTooLarge = errors.New("message exceeds configured limit")
	ErrQuota    = errors.New("mailbox quota exceeded")
	ErrReadOnly = errors.New("mailbox is read-only")
	ErrConflict = errors.New("operation token already used for different content")
)

//go:embed schema.sql
var schema string

type Account struct {
	ID, Address string
	Quota       int64
	// Policy is the account's effective class of service, filled in at
	// login and delivery (Service.applyPolicy). Nil elsewhere.
	Policy *mailpolicy.Effective
}
type Folder struct {
	ID             int64
	Name           string
	Validity, Next uint32
	ModSeq         uint64
	Subscribed     bool
}
type Message struct {
	UID      uint32
	Body     string
	Flags    []string
	Date     time.Time
	ModSeq   uint64
	Size     int64
	Checksum string
}
type AppendResult struct{ Validity, UID uint32 }
type Engine struct {
	DB          *sql.DB
	Bodies      BodyStore
	MaxBytes    int64
	requireSync bool
	bodySlots   chan struct{}
	totpKeys    []totpKey
	// bodyGrace is how long a body stays after it was first seen without
	// any message referring to it. It must exceed the backup retention,
	// or restoring an older metadata backup finds bodies already gone.
	bodyGrace     time.Duration
	readinessMu   sync.Mutex
	lastBodyCheck time.Time
}

func NewEngine(ctx context.Context, db *sql.DB, bodies BodyStore, c Config) (*Engine, error) {
	c = c.WithDefaults()
	keys, err := parseTOTPKeys(os.Getenv("ELEMTA_MAILBOX_TOTP_KEYS"))
	if err != nil {
		return nil, err
	}
	e := &Engine{DB: db, Bodies: bodies, MaxBytes: int64(c.Limits.MaxMessageMB) << 20, requireSync: c.Metadata.RequireSynchronousReplication, bodySlots: make(chan struct{}, c.Limits.MaxConcurrentBodies), bodyGrace: time.Duration(c.Maintenance.BodyGraceHours) * time.Hour, totpKeys: keys}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('elemta-mailbox-schema-v1',0))`); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	if err = e.migrateTOTPSecrets(ctx, tx); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	var incompatible bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_bodies b WHERE b.store<>$1 AND EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=b.key))`, bodies.Identity()).Scan(&incompatible); err != nil {
		return nil, err
	}
	if incompatible {
		return nil, errors.New("metadata references another body store; migrate bodies before switching backends")
	}
	return e, e.Ready(ctx)
}
func (e *Engine) Ready(ctx context.Context) error {
	if err := e.DB.PingContext(ctx); err != nil {
		return err
	}
	var recovery bool
	var commit, names string
	if err := e.DB.QueryRowContext(ctx, `SELECT pg_is_in_recovery(),current_setting('synchronous_commit'),current_setting('synchronous_standby_names')`).Scan(&recovery, &commit, &names); err != nil {
		return err
	}
	if recovery {
		return ErrReadOnly
	}
	if e.requireSync {
		if names == "" || (commit != "on" && commit != "remote_apply") {
			return errors.New("synchronous durability policy is not configured")
		}
		var n int
		if err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state IN ('sync','quorum')`).Scan(&n); err != nil {
			return err
		}
		required, err := requiredStandbys(names)
		if err != nil {
			return err
		}
		if n < required {
			return errors.New("no synchronous standby available")
		}
	}
	e.readinessMu.Lock()
	defer e.readinessMu.Unlock()
	if time.Since(e.lastBodyCheck) < 10*time.Second {
		return nil
	}
	if err := e.Bodies.Check(ctx); err != nil {
		return err
	}
	e.lastBodyCheck = time.Now()
	return nil
}
func (e *Engine) tx(ctx context.Context, account string, fn func(*sql.Tx) error) error {
	conn, err := e.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='20s'; SET LOCAL lock_timeout='5s'`); err != nil {
		return err
	}
	if e.requireSync {
		if _, err = tx.ExecContext(ctx, `SET LOCAL synchronous_commit='on'`); err != nil {
			return err
		}
		var names string
		if err = tx.QueryRowContext(ctx, `SHOW synchronous_standby_names`).Scan(&names); err != nil {
			return err
		}
		if names == "" {
			return errors.New("synchronous durability policy unavailable")
		}
	}
	var writable bool
	if err = tx.QueryRowContext(ctx, `SELECT writable FROM mailbox_accounts WHERE id=$1 FOR UPDATE`, account).Scan(&writable); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if !writable {
		return ErrReadOnly
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return e.replicationBarrier(ctx, conn)
}

var syncCountPattern = regexp.MustCompile(`(?i)^\s*(?:ANY|FIRST)\s+([0-9]+)\s*\(`)

func requiredStandbys(names string) (int, error) {
	if strings.TrimSpace(names) == "" {
		return 0, errors.New("synchronous standby policy is empty")
	}
	if match := syncCountPattern.FindStringSubmatch(names); match != nil {
		n, err := strconv.Atoi(match[1])
		if err != nil || n < 1 {
			return 0, errors.New("invalid synchronous standby count")
		}
		return n, nil
	}
	// PostgreSQL's legacy comma-separated priority list requires one standby.
	return 1, nil
}

// A cancellation during PostgreSQL's synchronous commit wait can leave a
// local commit whose remote durability is uncertain. Before acknowledging,
// keep the original primary connection and prove its post-commit WAL position
// reached the configured synchronous write quorum. Never reconnect this check
// to a newly promoted server that might not contain the original transaction.
func (e *Engine) replicationBarrier(ctx context.Context, conn *sql.Conn) error {
	if !e.requireSync {
		return nil
	}
	var lsn string
	if err := conn.QueryRowContext(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&lsn); err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var names string
		var recovery bool
		var durable int
		if err := conn.QueryRowContext(ctx, `SELECT pg_is_in_recovery(),current_setting('synchronous_standby_names'),(SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state IN ('sync','quorum') AND flush_lsn >= $1::pg_lsn)`, lsn).Scan(&recovery, &names, &durable); err != nil {
			return err
		}
		if recovery {
			return ErrReadOnly
		}
		required, err := requiredStandbys(names)
		if err != nil {
			return err
		}
		if durable >= required {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (e *Engine) EnsureAccount(ctx context.Context, a Account) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if a.ID == "" || a.Address == "" || a.Quota < 0 {
		return errors.New("invalid account identity")
	}
	// Every RCPT and login lands here. When the account is already as the
	// directory describes it, a read answers without taking the account
	// row's lock, which deliveries to that account hold while they commit.
	var current bool
	err := e.DB.QueryRowContext(ctx, `SELECT a.address=$2 AND a.quota_bytes=$3 AND EXISTS(SELECT 1 FROM mailbox_folders f WHERE f.account=a.id AND f.name='INBOX')
FROM mailbox_accounts a WHERE a.id=$1`, a.ID, strings.ToLower(a.Address), a.Quota).Scan(&current)
	if err == nil && current {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// The immutable directory ID, not a login alias, owns all mailbox rows.
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_accounts(id,address,quota_bytes) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET address=EXCLUDED.address,quota_bytes=EXCLUDED.quota_bytes WHERE mailbox_accounts.address IS DISTINCT FROM EXCLUDED.address OR mailbox_accounts.quota_bytes IS DISTINCT FROM EXCLUDED.quota_bytes`, a.ID, strings.ToLower(a.Address), a.Quota)
	if err != nil {
		return err
	}
	return e.tx(ctx, a.ID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_folders(account,name) VALUES($1,'INBOX') ON CONFLICT DO NOTHING`, a.ID)
		return err
	})
}
func canonicalMailbox(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	return strings.TrimSuffix(name, "/")
}
func validMailbox(name string) bool {
	return name != "" && len(name) <= 512 && !strings.ContainsAny(name, "\x00\r\n") && !strings.HasPrefix(name, "/")
}

type rowScanner interface{ Scan(...any) error }

func scanFolder(row rowScanner) (Folder, error) {
	var f Folder
	err := row.Scan(&f.ID, &f.Name, &f.Validity, &f.Next, &f.ModSeq, &f.Subscribed)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return f, err
}

const folderCols = `id,name,uidvalidity,next_uid,modseq,subscribed`

func folderTx(ctx context.Context, tx *sql.Tx, account, name string) (Folder, error) {
	return scanFolder(tx.QueryRowContext(ctx, `SELECT `+folderCols+` FROM mailbox_folders WHERE account=$1 AND name=$2`, account, canonicalMailbox(name)))
}
func (e *Engine) Folder(ctx context.Context, account, name string) (Folder, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return scanFolder(e.DB.QueryRowContext(ctx, `SELECT `+folderCols+` FROM mailbox_folders WHERE account=$1 AND name=$2`, account, canonicalMailbox(name)))
}
func (e *Engine) Folders(ctx context.Context, account string) ([]Folder, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	rows, err := e.DB.QueryContext(ctx, `SELECT `+folderCols+` FROM mailbox_folders WHERE account=$1 ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Folder
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (e *Engine) Create(ctx context.Context, account, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	name = canonicalMailbox(name)
	if !validMailbox(name) {
		return errors.New("invalid mailbox name")
	}
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_folders(account,name) VALUES($1,$2)`, account, name)
		var pe *pq.Error
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrExists
		}
		return err
	})
}
func (e *Engine) Subscribe(ctx context.Context, account, name string, value bool) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `UPDATE mailbox_folders SET subscribed=$3 WHERE account=$1 AND name=$2`, account, canonicalMailbox(name), value)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}
func (e *Engine) DeleteFolder(ctx context.Context, account, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if canonicalMailbox(name) == "INBOX" {
		return errors.New("cannot delete INBOX")
	}
	held, err := e.onHold(ctx, account)
	if err != nil {
		return err
	}
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		f, err := folderTx(ctx, tx, account, name)
		if err != nil {
			return err
		}
		if held {
			if err := holdMessages(ctx, tx, account, f, nil, "folder deleted"); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET used_bytes=used_bytes-COALESCE((SELECT sum(b.size) FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body WHERE m.folder=$2),0) WHERE id=$1`, account, f.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_bodies SET expires=now() WHERE key IN (SELECT body FROM mailbox_messages WHERE folder=$1)`, f.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM mailbox_folders WHERE id=$1`, f.ID); err != nil {
			return err
		}
		return nil
	})
}
func (e *Engine) Rename(ctx context.Context, account, old, newName string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	old = canonicalMailbox(old)
	newName = canonicalMailbox(newName)
	if old == "INBOX" || !validMailbox(newName) || strings.HasPrefix(newName, old+"/") {
		return errors.New("invalid mailbox rename")
	}
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		if _, err := folderTx(ctx, tx, account, old); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE mailbox_folders SET name=$3||substring(name from length($2)+1) WHERE account=$1 AND (name=$2 OR starts_with(name,$2||'/'))`, account, old, newName)
		var pe *pq.Error
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrExists
		}
		return err
	})
}

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func scanMessages(ctx context.Context, q querier, folder int64) ([]Message, error) {
	return scanMessagesWhere(ctx, q, `m.folder=$1`, folder)
}

func scanMessagesWhere(ctx context.Context, q querier, where string, args ...any) ([]Message, error) {
	rows, err := q.QueryContext(ctx, `SELECT m.uid,m.body,m.flags,m.internal_date,m.modseq,b.size,b.checksum FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body WHERE `+where+` ORDER BY m.uid`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.UID, &m.Body, pq.Array(&m.Flags), &m.Date, &m.ModSeq, &m.Size, &m.Checksum); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (e *Engine) Snapshot(ctx context.Context, account, name string) (Folder, []Message, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tx, err := e.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Folder{}, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	f, err := folderTx(ctx, tx, account, name)
	if err != nil {
		return f, nil, err
	}
	msgs, err := scanMessages(ctx, tx, f.ID)
	if err != nil {
		return f, nil, err
	}
	return f, msgs, tx.Commit()
}
func (e *Engine) Read(ctx context.Context, m Message) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	select {
	case e.bodySlots <- struct{}{}:
		defer func() { <-e.bodySlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Lowering the upload limit must not make previously accepted mail
	// unreadable. Reads still have the service's hard 100 MiB safety bound.
	if m.Size < 0 || m.Size > 100<<20 {
		return nil, ErrTooLarge
	}
	raw, err := e.Bodies.Get(ctx, m.Body, m.Size)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if int64(len(raw)) != m.Size || hex.EncodeToString(sum[:]) != m.Checksum {
		return nil, errors.New("message body checksum mismatch")
	}
	return raw, nil
}
func (e *Engine) Append(ctx context.Context, account, name string, raw []byte, flags []string, date time.Time, token string) (result AppendResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if int64(len(raw)) > e.MaxBytes {
		return result, ErrTooLarge
	}
	select {
	case e.bodySlots <- struct{}{}:
		defer func() { <-e.bodySlots }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	key := strings.ReplaceAll(uuid.NewString(), "-", "")
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	if date.IsZero() {
		date = time.Now().UTC()
	}
	// Reserve quota under the account lock before publishing a body. This
	// keeps concurrent uploads from each passing the same free-space check.
	var duplicate, reserved bool
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		if token != "" {
			var oldHash string
			err := tx.QueryRowContext(ctx, `SELECT checksum,uidvalidity,uid FROM mailbox_deliveries WHERE account=$1 AND token=$2`, account, token).Scan(&oldHash, &result.Validity, &result.UID)
			if err == nil {
				if oldHash != hash {
					return ErrConflict
				}
				duplicate = true
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		f, err := folderTx(ctx, tx, account, name)
		if err != nil {
			return err
		}
		if f.Next == 0 || f.Next == ^uint32(0) {
			return errors.New("mailbox UID space exhausted")
		}
		var quota, used, pending int64
		if err := tx.QueryRowContext(ctx, `SELECT quota_bytes,used_bytes,reserved_bytes FROM mailbox_accounts WHERE id=$1`, account).Scan(&quota, &used, &pending); err != nil {
			return err
		}
		if quota > 0 && int64(len(raw)) > quota-used-pending {
			return ErrQuota
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET reserved_bytes=reserved_bytes+$2 WHERE id=$1`, account, len(raw))
		return err
	})
	if err != nil || duplicate {
		return result, err
	}
	reserved = true
	defer func() {
		if !reserved {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = e.DB.ExecContext(cleanup, `UPDATE mailbox_accounts SET reserved_bytes=reserved_bytes-$2 WHERE id=$1`, account, len(raw))
	}()
	staged, published := false, false
	defer func() {
		if !staged || published {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if e.Bodies.Delete(cleanup, key) == nil {
			_, _ = e.DB.ExecContext(cleanup, `DELETE FROM mailbox_summaries WHERE body=$1`, key)
			_, _ = e.DB.ExecContext(cleanup, `DELETE FROM mailbox_bodies WHERE key=$1 AND state='staging'`, key)
		}
	}()
	// A staging record precedes body publication. Cleanup can fence an expired
	// upload, and attaching the body checks that state under the same row lock.
	if _, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_bodies(key,size,checksum,store) VALUES($1,$2,$3,$4)`, key, len(raw), hash, e.Bodies.Identity()); err != nil {
		return result, err
	}
	staged = true
	if err = e.Bodies.Put(ctx, key, raw); err != nil {
		return result, err
	}
	// The summary (and its search vector, the costly part) is stored before
	// the account transaction, so deliveries to one account don't queue
	// behind each other's indexing. It is a cache keyed by the body: if the
	// transaction fails, cleanup removes it with the unused body.
	if err = storeSummary(ctx, e.DB, key, summarize(raw)); err != nil {
		return result, err
	}
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		if token != "" {
			var oldHash string
			err := tx.QueryRowContext(ctx, `SELECT checksum,uidvalidity,uid FROM mailbox_deliveries WHERE account=$1 AND token=$2`, account, token).Scan(&oldHash, &result.Validity, &result.UID)
			if err == nil {
				if oldHash != hash {
					return ErrConflict
				}
				duplicate = true
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		f, err := folderTx(ctx, tx, account, name)
		if err != nil {
			return err
		}
		if f.Next == 0 || f.Next == ^uint32(0) {
			return errors.New("mailbox UID space exhausted")
		}
		var quota, used int64
		if err = tx.QueryRowContext(ctx, `SELECT quota_bytes,used_bytes FROM mailbox_accounts WHERE id=$1`, account).Scan(&quota, &used); err != nil {
			return err
		}
		if quota > 0 && used+int64(len(raw)) > quota {
			return ErrQuota
		}
		var state string
		var live bool
		if err = tx.QueryRowContext(ctx, `SELECT state,expires>now() FROM mailbox_bodies WHERE key=$1 FOR UPDATE`, key).Scan(&state, &live); err != nil {
			return err
		}
		if state != "staging" || !live {
			return errors.New("upload lease expired")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_bodies SET state='ready' WHERE key=$1`, key); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mailbox_messages(folder,uid,body,flags,internal_date,modseq) VALUES($1,$2,$3,$4,$5,$6)`, f.ID, f.Next, key, pq.Array(normalizeFlags(flags)), date, f.ModSeq+1); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_folders SET next_uid=next_uid+1,modseq=modseq+1 WHERE id=$1`, f.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET used_bytes=used_bytes+$2,reserved_bytes=reserved_bytes-$2 WHERE id=$1`, account, len(raw)); err != nil {
			return err
		}
		if err = change(ctx, tx, f.ID, f.ModSeq+1, "append", f.Next); err != nil {
			return err
		}
		result = AppendResult{Validity: f.Validity, UID: f.Next}
		if token != "" {
			_, err = tx.ExecContext(ctx, `INSERT INTO mailbox_deliveries(account,token,checksum,uidvalidity,uid) VALUES($1,$2,$3,$4,$5)`, account, token, hash, f.Validity, result.UID)
		}
		return err
	})
	if err == nil && !duplicate {
		reserved = false
		published = true
	}
	return result, err
}
func change(ctx context.Context, tx *sql.Tx, folder int64, modseq uint64, kind string, uid uint32) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_changes(folder,modseq,kind,uid) VALUES($1,$2,$3,$4)`, folder, modseq, kind, uid)
	return err
}
func normalizeFlags(flags []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, f := range flags {
		f = strings.ToLower(f)
		if f == "\\recent" || f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}
func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

// MutateFlags and Expunge operate on UIDs resolved from a session's own
// sequence view, never on fresh sequence numbers another replica may shift.
func (e *Engine) MutateFlags(ctx context.Context, account, name string, uids []uint32, flags []string, op int) error {
	_, err := e.MutateFlagsIf(ctx, account, name, uids, flags, op, 0)
	return err
}

// MutateFlagsIf changes flags only on messages whose MODSEQ is at most
// unchangedSince (CONDSTORE's STORE UNCHANGEDSINCE; 0 means always), and
// returns the UIDs it left alone because they changed since.
func (e *Engine) MutateFlagsIf(ctx context.Context, account, name string, uids []uint32, flags []string, op int, unchangedSince uint64) (modified []uint32, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// Set-based: one read, one update and one journal insert whatever the
	// number of messages, so "mark all as read" on a large folder holds the
	// account lock (and delays its deliveries) for milliseconds, not seconds.
	ids := make([]int64, len(uids))
	for i, u := range uids {
		ids[i] = int64(u)
	}
	want := normalizeFlags(flags)
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		modified = modified[:0]
		f, err := folderTx(ctx, tx, account, name)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT uid,flags,modseq FROM mailbox_messages WHERE folder=$1 AND uid=ANY($2) ORDER BY uid`, f.ID, pq.Array(ids))
		if err != nil {
			return err
		}
		var changedUIDs, changedSeqs []int64
		var changedFlags []string
		for rows.Next() {
			var uid uint32
			var old []string
			var modseq uint64
			if err := rows.Scan(&uid, pq.Array(&old), &modseq); err != nil {
				rows.Close()
				return err
			}
			if unchangedSince != 0 && modseq > unchangedSince {
				modified = append(modified, uid)
				continue
			}
			next := want
			switch op {
			case 1:
				next = normalizeFlags(append(append([]string(nil), old...), want...))
			case 2:
				next = []string{}
				for _, v := range old {
					if !hasFlag(want, v) {
						next = append(next, v)
					}
				}
				next = normalizeFlags(next)
			}
			if slices.Equal(old, next) {
				continue
			}
			lit, err := pq.Array(next).Value()
			if err != nil {
				rows.Close()
				return err
			}
			f.ModSeq++
			changedUIDs = append(changedUIDs, int64(uid))
			changedSeqs = append(changedSeqs, int64(f.ModSeq)) // #nosec G115 -- MODSEQs are BIGINT in the database
			changedFlags = append(changedFlags, lit.(string))
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(changedUIDs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mailbox_messages m SET flags=v.f::text[],modseq=v.ms
FROM unnest($2::bigint[],$3::bigint[],$4::text[]) AS v(uid,ms,f) WHERE m.folder=$1 AND m.uid=v.uid`,
			f.ID, pq.Array(changedUIDs), pq.Array(changedSeqs), pq.Array(changedFlags)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_changes(folder,modseq,kind,uid)
SELECT $1,v.ms,'flags',v.uid FROM unnest($2::bigint[],$3::bigint[]) AS v(uid,ms)`, f.ID, pq.Array(changedUIDs), pq.Array(changedSeqs)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_folders SET modseq=$2 WHERE id=$1`, f.ID, f.ModSeq)
		return err
	})
	return modified, err
}
func (e *Engine) Expunge(ctx context.Context, account, name string, uids []uint32) (removed []uint32, err error) {
	return e.expunge(ctx, account, name, uids, true, "")
}

func (e *Engine) expunge(ctx context.Context, account, name string, uids []uint32, requireDeleted bool, popOwner string) (removed []uint32, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	held, err := e.onHold(ctx, account)
	if err != nil {
		return nil, err
	}
	// Set-based, like MutateFlagsIf: emptying a large Trash is a few
	// statements, not several per message. Bodies that lose their last
	// message are found and given their grace by cleanup.
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		if popOwner != "" {
			var owner string
			if err := tx.QueryRowContext(ctx, `SELECT owner FROM mailbox_pop3_leases WHERE account=$1 AND owner=$2 AND expires>now() FOR UPDATE`, account, popOwner).Scan(&owner); err != nil {
				return errors.New("POP3 lease unavailable")
			}
		}
		removed = removed[:0]
		f, err := folderTx(ctx, tx, account, name)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT m.uid,b.size FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body
WHERE m.folder=$1 AND m.uid=ANY($2) AND (NOT $3::boolean OR '\deleted'=ANY(m.flags)) ORDER BY m.uid`, f.ID, pq.Array(uidArray(uids)), requireDeleted)
		if err != nil {
			return err
		}
		var freed int64
		var ids, seqs []int64
		for rows.Next() {
			var uid uint32
			var size int64
			if err := rows.Scan(&uid, &size); err != nil {
				rows.Close()
				return err
			}
			f.ModSeq++
			removed = append(removed, uid)
			ids = append(ids, int64(uid))
			seqs = append(seqs, int64(f.ModSeq)) // #nosec G115 -- MODSEQs are BIGINT in the database
			freed += size
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if held {
			if err := holdMessages(ctx, tx, account, f, ids, "deleted"); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM mailbox_messages WHERE folder=$1 AND uid=ANY($2)`, f.ID, pq.Array(ids)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET used_bytes=used_bytes-$2 WHERE id=$1`, account, freed); err != nil {
			return err
		}
		if err = changes(ctx, tx, f.ID, "expunge", ids, seqs); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_folders SET modseq=$2 WHERE id=$1`, f.ID, f.ModSeq)
		return err
	})
	return
}

// changes journals one change per message in one statement.
func changes(ctx context.Context, tx *sql.Tx, folder int64, kind string, uids, modseqs []int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_changes(folder,modseq,kind,uid)
SELECT $1,v.ms,$2,v.uid FROM unnest($3::bigint[],$4::bigint[]) AS v(uid,ms)`, folder, kind, pq.Array(uids), pq.Array(modseqs))
	return err
}

func uidArray(uids []uint32) []int64 {
	out := make([]int64, len(uids))
	for i, u := range uids {
		out[i] = int64(u)
	}
	return out
}

func (e *Engine) CopyMove(ctx context.Context, account, src, dst string, uids []uint32, move bool) (validity uint32, from, to []uint32, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		from, to = from[:0], to[:0]
		s, err := folderTx(ctx, tx, account, src)
		if err != nil {
			return err
		}
		d, err := folderTx(ctx, tx, account, dst)
		if err != nil {
			return err
		}
		if s.ID == d.ID {
			return errors.New("source and destination must differ")
		}
		validity = d.Validity
		// Locking the bodies keeps cleanup from retiring one mid-copy.
		rows, err := tx.QueryContext(ctx, `SELECT m.uid,m.body,m.flags::text,m.internal_date,b.size,b.state FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body
WHERE m.folder=$1 AND m.uid=ANY($2) ORDER BY m.uid FOR UPDATE OF b`, s.ID, pq.Array(uidArray(uids)))
		if err != nil {
			return err
		}
		var (
			newUIDs, destSeqs, oldUIDs, srcSeqs []int64
			bodies, flags, dates                []string
			total                               int64
		)
		for rows.Next() {
			var uid uint32
			var body, flagLit, state string
			var date time.Time
			var size int64
			if err := rows.Scan(&uid, &body, &flagLit, &date, &size, &state); err != nil {
				rows.Close()
				return err
			}
			if state != "ready" {
				rows.Close()
				return errors.New("body is retiring")
			}
			if d.Next == ^uint32(0) {
				rows.Close()
				return errors.New("mailbox UID space exhausted")
			}
			d.ModSeq++
			newUIDs = append(newUIDs, int64(d.Next))
			destSeqs = append(destSeqs, int64(d.ModSeq)) // #nosec G115 -- MODSEQs are BIGINT in the database
			bodies = append(bodies, body)
			flags = append(flags, flagLit)
			dates = append(dates, date.UTC().Format(time.RFC3339Nano))
			from = append(from, uid)
			to = append(to, d.Next)
			oldUIDs = append(oldUIDs, int64(uid))
			if move {
				s.ModSeq++
				srcSeqs = append(srcSeqs, int64(s.ModSeq)) // #nosec G115 -- MODSEQs are BIGINT in the database
			}
			total += size
			d.Next++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(newUIDs) == 0 {
			return nil
		}
		if !move {
			var q, u int64
			if err = tx.QueryRowContext(ctx, `SELECT quota_bytes,used_bytes FROM mailbox_accounts WHERE id=$1`, account).Scan(&q, &u); err != nil {
				return err
			}
			if q > 0 && u+total > q {
				return ErrQuota
			}
			if _, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET used_bytes=used_bytes+$2 WHERE id=$1`, account, total); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mailbox_messages(folder,uid,body,flags,internal_date,modseq)
SELECT $1,v.uid,v.body,v.flags::text[],v.date::timestamptz,v.ms FROM unnest($2::bigint[],$3::text[],$4::text[],$5::text[],$6::bigint[]) AS v(uid,body,flags,date,ms)`,
			d.ID, pq.Array(newUIDs), pq.Array(bodies), pq.Array(flags), pq.Array(dates), pq.Array(destSeqs)); err != nil {
			return err
		}
		if err = changes(ctx, tx, d.ID, "append", newUIDs, destSeqs); err != nil {
			return err
		}
		if move {
			if _, err = tx.ExecContext(ctx, `DELETE FROM mailbox_messages WHERE folder=$1 AND uid=ANY($2)`, s.ID, pq.Array(oldUIDs)); err != nil {
				return err
			}
			if err = changes(ctx, tx, s.ID, "expunge", oldUIDs, srcSeqs); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mailbox_folders SET next_uid=$2,modseq=$3 WHERE id=$1`, d.ID, d.Next, d.ModSeq); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_folders SET modseq=$2 WHERE id=$1`, s.ID, s.ModSeq)
		return err
	})
	return
}
func (e *Engine) Quota(ctx context.Context, account string) (used, limit int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	err = e.DB.QueryRowContext(ctx, `SELECT used_bytes,quota_bytes FROM mailbox_accounts WHERE id=$1`, account).Scan(&used, &limit)
	return
}

// GC retains durable tombstones and retries deletion: even a stalled uploader
// that resumes after retirement cannot publish metadata or permanently hide
// its late orphan from subsequent collection. No inventory guesses are used.
// Ready bodies get a full day of grace for readers and short-term recovery.
func (e *Engine) GC(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	conn, err := e.DB.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// The grace period runs from when a body was first seen unreferenced,
	// not from its upload: a years-old message deleted today must survive
	// as long as a backup taken yesterday might be restored. Bodies are
	// marked on one pass and only collected after the grace on a later one.
	if _, err := tx.ExecContext(ctx, `UPDATE mailbox_bodies b SET orphaned_at=now() WHERE b.key IN (
SELECT key FROM mailbox_bodies x WHERE x.store=$1 AND x.state='ready' AND x.orphaned_at IS NULL
AND NOT EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=x.key)
AND NOT EXISTS(SELECT 1 FROM mailbox_held h WHERE h.body=x.key) LIMIT 1000)`, e.Bodies.Identity()); err != nil {
		return 0, err
	}
	// A body referenced again (after restoring older metadata, say) starts
	// its grace afresh if it is ever orphaned again.
	if _, err := tx.ExecContext(ctx, `UPDATE mailbox_bodies b SET orphaned_at=NULL WHERE b.key IN (
SELECT key FROM mailbox_bodies x WHERE x.store=$1 AND x.orphaned_at IS NOT NULL AND x.state='ready'
AND (EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=x.key) OR EXISTS(SELECT 1 FROM mailbox_held h WHERE h.body=x.key)) LIMIT 1000)`, e.Bodies.Identity()); err != nil {
		return 0, err
	}
	grace := e.bodyGrace
	if grace <= 0 {
		grace = 7 * 24 * time.Hour
	}
	rows, err := tx.QueryContext(ctx, `SELECT key FROM mailbox_bodies b WHERE store=$1 AND ((state='staging' AND expires<now()) OR (state='ready' AND orphaned_at<now()-$2*interval '1 second' AND NOT EXISTS(SELECT 1 FROM mailbox_messages m WHERE m.body=b.key) AND NOT EXISTS(SELECT 1 FROM mailbox_held h WHERE h.body=b.key))) ORDER BY expires LIMIT 100 FOR UPDATE SKIP LOCKED`, e.Bodies.Identity(), int64(grace/time.Second))
	if err != nil {
		return 0, err
	}
	var candidates []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return 0, err
		}
		candidates = append(candidates, key)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	for _, key := range candidates {
		// Recheck references after acquiring the body lock, using a fresh
		// READ COMMITTED snapshot. A copy that committed while we waited wins.
		var referenced bool
		// Mail under legal hold (retention.go) keeps its body too.
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_messages WHERE body=$1) OR EXISTS(SELECT 1 FROM mailbox_held WHERE body=$1)`, key).Scan(&referenced); err != nil {
			return 0, err
		}
		if !referenced {
			if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_summaries WHERE body=$1`, key); err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE mailbox_bodies SET state='retiring',expires=now() WHERE key=$1`, key); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	rows, err = e.DB.QueryContext(ctx, `SELECT key FROM mailbox_bodies WHERE store=$1 AND state='retiring' AND expires<=now() ORDER BY expires LIMIT 100`, e.Bodies.Identity())
	if err != nil {
		return 0, err
	}
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return 0, err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	if err := e.replicationBarrier(ctx, conn); err != nil {
		return 0, err
	}
	n := 0
	for _, key := range keys {
		if err := e.Bodies.Delete(ctx, key); err != nil {
			return n, err
		}
		if _, err := e.DB.ExecContext(ctx, `UPDATE mailbox_bodies SET expires=now()+interval '1 day' WHERE key=$1 AND state='retiring'`, key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (e *Engine) String() string {
	return fmt.Sprintf("mailbox engine (max message %d bytes)", e.MaxBytes)
}
