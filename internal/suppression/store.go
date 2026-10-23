// Package suppression records addresses that must not be mailed again.
//
// Bulk sending without this is how a sender's reputation is destroyed. A
// campaign that keeps mailing addresses which permanently failed last week is
// the clearest signal a receiver has that the sender does not manage their
// lists, and it is the signal they act on: bounce rate is a headline input to
// every major provider's filtering decision.
//
// So a permanent failure is recorded here, and the campaign runner asks before
// it sends. The queue's ordinary retry logic is untouched — this is about not
// starting again tomorrow, not about the message in flight.
package suppression

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"  // the Postgres queue's driver
	_ "modernc.org/sqlite" // same driver the queue uses, so no new dependency
)

// Source says why an address is suppressed, because the answer changes what an
// operator does about it.
type Source string

const (
	// SourceBounce: the receiving server refused it permanently.
	SourceBounce Source = "bounce"
	// SourceComplaint: the recipient reported it as spam. Worse than a bounce —
	// the address works, and the person does not want the mail.
	SourceComplaint Source = "complaint"
	// SourceManual: an operator added it.
	SourceManual Source = "manual"
)

// Entry is one suppressed address.
type Entry struct {
	Address   string    `json:"address"`
	Source    Source    `json:"source"`
	Reason    string    `json:"reason,omitempty"`
	Code      string    `json:"code,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Store is the durable list.
//
// It has to be shared: the SMTP node records the bounce and the web process
// reads it when a campaign runs. With a file queue those are containers on one
// volume and SQLite in WAL mode lets both hold it open. With the Postgres
// queue there are several MTAs, each with its own disk, so the list lives in
// the queue's database instead; otherwise a complaint taken by one MTA would
// not stop the others mailing the address.
type Store struct {
	db       *sql.DB
	postgres bool
}

// schema is valid in both SQLite and Postgres.
const schema = `
	CREATE TABLE IF NOT EXISTS suppressed (
		address    TEXT PRIMARY KEY,
		source     TEXT NOT NULL,
		reason     TEXT,
		code       TEXT,
		created_at BIGINT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS suppressed_created_at ON suppressed(created_at);`

// Open creates or opens the store at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open suppression store: %w", err)
	}

	// Addresses are the primary key, so recording the same bounce twice is not
	// an error and does not need a read first.
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create suppression schema: %w", err)
	}

	return &Store{db: db}, nil
}

// OpenPostgres opens the list in the Postgres database at dsn, the one the
// queue uses, creating its table if needed.
func OpenPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open suppression store: %w", err)
	}
	// Lookups are one row by key; a few connections per process is plenty
	// beside the queue's own pool.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create suppression schema: %w", err)
	}
	return &Store{db: db, postgres: true}, nil
}

// OpenForQueue opens the list where the queue keeps its state: the queue's
// Postgres database for the postgres backend, otherwise suppression.db in the
// queue directory. Where returns a description for the log.
//
// Moving to Postgres takes the entries a local suppression.db already holds
// with it, once: the file is renamed afterwards so the next start does not
// import it again, and kept rather than deleted in case it is needed.
func OpenForQueue(ctx context.Context, backend, dsn, queueDir string) (store *Store, where string, err error) {
	local := ""
	if queueDir != "" {
		local = filepath.Join(queueDir, "suppression.db")
	}
	if strings.EqualFold(strings.TrimSpace(backend), "postgres") && strings.TrimSpace(dsn) != "" {
		store, err = OpenPostgres(dsn)
		if err != nil {
			return nil, "the queue database", err
		}
		if local != "" {
			if _, statErr := os.Stat(local); statErr == nil {
				n, importErr := store.importFile(ctx, local)
				if importErr != nil {
					slog.Default().Warn("Could not move the local suppression list into the queue database; it stays where it is and the import is retried at the next start",
						"component", "suppression", "path", local, "error", importErr)
				} else {
					slog.Default().Info("Moved the local suppression list into the queue database",
						"component", "suppression", "path", local, "entries", n)
				}
			}
		}
		return store, "the queue database", nil
	}
	if local == "" {
		return nil, "", fmt.Errorf("no queue directory for the suppression list")
	}
	store, err = Open(local)
	return store, local, err
}

// importFile copies a SQLite list into s and renames the file once done.
func (s *Store) importFile(ctx context.Context, path string) (int, error) {
	old, err := Open(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for offset := 0; ; {
		entries, _, err := old.List(ctx, "", 500, offset)
		if err != nil {
			_ = old.Close()
			return n, err
		}
		for _, entry := range entries {
			if err := s.Add(ctx, entry); err != nil {
				_ = old.Close()
				return n, err
			}
			n++
		}
		if len(entries) < 500 {
			break
		}
		offset += len(entries)
	}
	if err := old.Close(); err != nil {
		return n, err
	}
	// WAL side files go with it, so the renamed copy opens complete.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = os.Rename(path+suffix, path+".imported"+suffix)
		}
	}
	return n, os.Rename(path, path+".imported")
}

// q writes a statement's ? placeholders as $1, $2... for Postgres.
func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Normalize puts an address into the form the list is keyed by.
//
// Lower-cased, including the local part. RFC 5321 says the local part is
// case-sensitive and in theory alice@ and Alice@ are different mailboxes; in
// practice essentially no provider treats them that way, and the costs here are
// wildly asymmetric. Suppressing a case variant nobody uses costs one address.
// Mailing someone who bounced or complained because their address arrived
// capitalised differently costs reputation.
func Normalize(address string) string {
	address = strings.TrimSpace(address)
	address = strings.Trim(address, "<>")
	return strings.ToLower(address)
}

// Add records an address. Recording one that is already listed keeps the
// original entry: the first reason is the one that explains it, and a later
// bounce should not overwrite an earlier complaint.
func (s *Store) Add(ctx context.Context, entry Entry) error {
	if s == nil || s.db == nil {
		return nil
	}
	address := Normalize(entry.Address)
	if address == "" {
		return fmt.Errorf("cannot suppress an empty address")
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(ctx, s.q(
		`INSERT INTO suppressed (address, source, reason, code, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(address) DO NOTHING`),
		address, string(entry.Source), truncate(entry.Reason, 500), entry.Code, entry.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("suppress %s: %w", address, err)
	}
	return nil
}

// IsSuppressed reports whether an address must not be mailed.
//
// A store that cannot be read returns false rather than an error to the
// caller's send path: failing closed here would stop all mail because a
// database file was briefly locked, which is a worse outcome than sending one
// message to an address that bounced. The error is returned so it can be
// logged.
func (s *Store) IsSuppressed(ctx context.Context, address string) (Entry, bool, error) {
	if s == nil || s.db == nil {
		return Entry{}, false, nil
	}

	var entry Entry
	var created int64
	var source, reason, code sql.NullString
	err := s.db.QueryRowContext(ctx,
		s.q(`SELECT address, source, reason, code, created_at FROM suppressed WHERE address = ?`),
		Normalize(address)).Scan(&entry.Address, &source, &reason, &code, &created)
	if err == sql.ErrNoRows {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}

	entry.Source = Source(source.String)
	entry.Reason = reason.String
	entry.Code = code.String
	entry.CreatedAt = time.Unix(created, 0).UTC()
	return entry, true, nil
}

// List returns suppressed addresses, newest first, optionally filtered by a
// substring of the address.
func (s *Store) List(ctx context.Context, query string, limit, offset int) ([]Entry, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// Two complete statements rather than a base query with a clause appended.
	// The filter is a constant either way and every value is a parameter, so the
	// concatenated form was safe — but "safe SQL built by concatenation" is a
	// pattern that stops being true the first time someone extends it, and it
	// is what a scanner flags. Writing both out costs a few lines and removes
	// the question.
	const (
		countAll      = `SELECT COUNT(*) FROM suppressed`
		countFiltered = `SELECT COUNT(*) FROM suppressed WHERE address LIKE ?`
		selectAll     = `SELECT address, source, reason, code, created_at FROM suppressed
		                 ORDER BY created_at DESC LIMIT ? OFFSET ?`
		selectFiltered = `SELECT address, source, reason, code, created_at FROM suppressed
		                  WHERE address LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	)

	var (
		total int
		rows  *sql.Rows
		err   error
	)
	if filter := strings.TrimSpace(query); filter != "" {
		pattern := "%" + strings.ToLower(filter) + "%"
		if err = s.db.QueryRowContext(ctx, s.q(countFiltered), pattern).Scan(&total); err != nil {
			return nil, 0, err
		}
		rows, err = s.db.QueryContext(ctx, s.q(selectFiltered), pattern, limit, offset)
	} else {
		if err = s.db.QueryRowContext(ctx, countAll).Scan(&total); err != nil {
			return nil, 0, err
		}
		rows, err = s.db.QueryContext(ctx, s.q(selectAll), limit, offset)
	}
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]Entry, 0, limit)
	for rows.Next() {
		var entry Entry
		var created int64
		var source, reason, code sql.NullString
		if err := rows.Scan(&entry.Address, &source, &reason, &code, &created); err != nil {
			return nil, 0, err
		}
		entry.Source = Source(source.String)
		entry.Reason = reason.String
		entry.Code = code.String
		entry.CreatedAt = time.Unix(created, 0).UTC()
		entries = append(entries, entry)
	}
	return entries, total, rows.Err()
}

// Remove takes an address off the list.
//
// There is no automatic expiry. A permanent failure is permanent by
// definition, and quietly re-admitting addresses after some interval would
// re-create the problem the list exists to prevent. Addresses do get recycled,
// so removal is deliberate and manual.
func (s *Store) Remove(ctx context.Context, address string) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, s.q(`DELETE FROM suppressed WHERE address = ?`), Normalize(address))
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// Count is the total, for the dashboard.
func (s *Store) Count(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM suppressed").Scan(&total)
	return total, err
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// SuppressedWithReason answers the question a campaign runner asks, in the
// shape it needs.
//
// The error is handled here rather than returned. A list that cannot be read
// must not stop a campaign: failing closed would halt all sending because a
// database file was briefly locked, which is worse than sending one message to
// an address that bounced. The failure is logged so it is not silent.
func (s *Store) SuppressedWithReason(ctx context.Context, address string) (bool, string) {
	entry, suppressed, err := s.IsSuppressed(ctx, address)
	if err != nil {
		slog.Default().Warn("Could not check the suppression list; treating the address as sendable",
			"component", "suppression", "address", address, "error", err)
		return false, ""
	}
	if !suppressed {
		return false, ""
	}
	reason := string(entry.Source)
	if entry.Reason != "" {
		reason += ": " + entry.Reason
	}
	return true, reason
}
