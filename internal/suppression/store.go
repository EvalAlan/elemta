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
	"strings"
	"time"

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
// SQLite because it has to be shared: the SMTP node records the bounce and the
// web process reads it when a campaign runs, and in the shipped deployment
// those are different containers on one volume. WAL lets both hold it open.
type Store struct {
	db *sql.DB
}

// Open creates or opens the store at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open suppression store: %w", err)
	}

	// Addresses are the primary key, so recording the same bounce twice is not
	// an error and does not need a read first.
	const schema = `
		CREATE TABLE IF NOT EXISTS suppressed (
			address    TEXT PRIMARY KEY,
			source     TEXT NOT NULL,
			reason     TEXT,
			code       TEXT,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS suppressed_created_at ON suppressed(created_at);`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create suppression schema: %w", err)
	}

	return &Store{db: db}, nil
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

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO suppressed (address, source, reason, code, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(address) DO NOTHING`,
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
		`SELECT address, source, reason, code, created_at FROM suppressed WHERE address = ?`,
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

	where, args := "", []interface{}{}
	if q := strings.TrimSpace(query); q != "" {
		where = " WHERE address LIKE ?"
		args = append(args, "%"+strings.ToLower(q)+"%")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM suppressed"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT address, source, reason, code, created_at FROM suppressed"+where+
			" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
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
	result, err := s.db.ExecContext(ctx, `DELETE FROM suppressed WHERE address = ?`, Normalize(address))
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
