package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStorageBackend implements StorageBackend using SQLite.
type SQLiteStorageBackend struct {
	dbPath string
	db     *sql.DB
}

// Ensure SQLiteStorageBackend implements StorageBackend interface.
var _ StorageBackend = (*SQLiteStorageBackend)(nil)

// NewSQLiteStorageBackend creates a new sqlite-backed storage implementation.
func NewSQLiteStorageBackend(dbPath string, busyTimeoutMS int, journalMode, synchronous string) (*SQLiteStorageBackend, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, fmt.Errorf("sqlite database path is required")
	}

	if busyTimeoutMS <= 0 {
		busyTimeoutMS = 5000
	}
	journalMode = normalizeSQLiteJournalMode(journalMode)
	synchronous = normalizeSQLiteSynchronous(synchronous)

	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sqlite directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// SQLite handles concurrent writes poorly with large connection pools.
	// Keep a single shared connection so busy_timeout and WAL behavior are predictable.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	backend := &SQLiteStorageBackend{
		dbPath: dbPath,
		db:     db,
	}

	if err := backend.applyPragmas(busyTimeoutMS, journalMode, synchronous); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := backend.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := os.Chmod(dbPath, 0600); err != nil && !os.IsNotExist(err) {
		// Best-effort hardening: do not fail startup if chmod isn't possible.
		_ = err
	}

	return backend, nil
}

func (s *SQLiteStorageBackend) applyPragmas(busyTimeoutMS int, journalMode, synchronous string) error {
	if _, err := s.db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("failed to set sqlite foreign_keys pragma: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMS)); err != nil {
		return fmt.Errorf("failed to set sqlite busy_timeout pragma: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA journal_mode = %s", journalMode)); err != nil {
		return fmt.Errorf("failed to set sqlite journal_mode pragma: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA synchronous = %s", synchronous)); err != nil {
		return fmt.Errorf("failed to set sqlite synchronous pragma: %w", err)
	}
	return nil
}

func (s *SQLiteStorageBackend) ensureSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS queue_messages (
  id TEXT PRIMARY KEY,
  queue_type TEXT NOT NULL,
  metadata TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_queue_messages_queue_type ON queue_messages(queue_type);
CREATE INDEX IF NOT EXISTS idx_queue_messages_created_at ON queue_messages(created_at);

CREATE TABLE IF NOT EXISTS queue_contents (
  id TEXT PRIMARY KEY,
  content BLOB NOT NULL
);
`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize sqlite schema: %w", err)
	}

	return nil
}

// Store saves a message metadata record.
func (s *SQLiteStorageBackend) Store(msg Message) error {
	if msg.ID == "" {
		return fmt.Errorf("message id is required")
	}

	now := time.Now().UTC()
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = now
	}
	if msg.UpdatedAt.IsZero() {
		msg.UpdatedAt = now
	}

	if msg.QueueType == "" {
		msg.QueueType = Active
	}

	metadata, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message metadata: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO queue_messages (id, queue_type, metadata, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		msg.ID,
		string(msg.QueueType),
		string(metadata),
		msg.CreatedAt.UTC().Format(time.RFC3339Nano),
		msg.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("failed to store message metadata: %w", err)
	}

	return nil
}

// Retrieve loads a message from sqlite storage.
func (s *SQLiteStorageBackend) Retrieve(id string) (Message, error) {
	var queueType string
	var metadata string

	err := s.db.QueryRow(`SELECT queue_type, metadata FROM queue_messages WHERE id = ?`, id).Scan(&queueType, &metadata)
	if err != nil {
		if err == sql.ErrNoRows {
			return Message{}, fmt.Errorf("message not found: %s", id)
		}
		return Message{}, fmt.Errorf("failed to retrieve message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal([]byte(metadata), &msg); err != nil {
		return Message{}, fmt.Errorf("failed to decode message metadata: %w", err)
	}

	msg.ID = id
	msg.QueueType = QueueType(queueType)
	return msg, nil
}

// Update saves changes to an existing message.
func (s *SQLiteStorageBackend) Update(msg Message) error {
	metadata, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message metadata: %w", err)
	}

	if msg.UpdatedAt.IsZero() {
		msg.UpdatedAt = time.Now().UTC()
	}

	res, err := s.db.Exec(
		`UPDATE queue_messages SET queue_type = ?, metadata = ?, updated_at = ? WHERE id = ?`,
		string(msg.QueueType),
		string(metadata),
		msg.UpdatedAt.UTC().Format(time.RFC3339Nano),
		msg.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update message metadata: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed checking update result: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("message not found: %s", msg.ID)
	}

	return nil
}

// Delete removes a message metadata record.
func (s *SQLiteStorageBackend) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM queue_messages WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed checking delete result: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("message not found: %s", id)
	}

	return nil
}

// List returns all messages in a specific queue.
func (s *SQLiteStorageBackend) List(queueType QueueType) ([]Message, error) {
	rows, err := s.db.Query(`SELECT metadata FROM queue_messages WHERE queue_type = ?`, string(queueType))
	if err != nil {
		return nil, fmt.Errorf("failed to list queue messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0)
	for rows.Next() {
		var metadata string
		if err := rows.Scan(&metadata); err != nil {
			return nil, fmt.Errorf("failed scanning queue row: %w", err)
		}

		var msg Message
		if err := json.Unmarshal([]byte(metadata), &msg); err != nil {
			continue
		}
		msg.QueueType = queueType
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating queue rows: %w", err)
	}

	return messages, nil
}

// Count returns message count for a queue type.
func (s *SQLiteStorageBackend) Count(queueType QueueType) (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM queue_messages WHERE queue_type = ?`, string(queueType)).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count queue messages: %w", err)
	}
	return count, nil
}

// DeleteAll removes all messages from a queue and their content records.
func (s *SQLiteStorageBackend) DeleteAll(queueType QueueType) error {
	ids, err := s.listIDsByQueueType(queueType)
	if err != nil {
		return err
	}

	if _, err := s.db.Exec(`DELETE FROM queue_messages WHERE queue_type = ?`, string(queueType)); err != nil {
		return fmt.Errorf("failed to delete queue messages: %w", err)
	}

	for _, id := range ids {
		if _, err := s.db.Exec(`DELETE FROM queue_contents WHERE id = ?`, id); err != nil {
			return fmt.Errorf("failed to delete queue content for %s: %w", id, err)
		}
	}

	return nil
}

// Move transfers a message between queues.
func (s *SQLiteStorageBackend) Move(id string, fromQueue, toQueue QueueType) error {
	res, err := s.db.Exec(
		`UPDATE queue_messages SET queue_type = ?, updated_at = ? WHERE id = ? AND queue_type = ?`,
		string(toQueue),
		time.Now().UTC().Format(time.RFC3339Nano),
		id,
		string(fromQueue),
	)
	if err != nil {
		return fmt.Errorf("failed to move message: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed checking move result: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("message not found in queue %s: %s", fromQueue, id)
	}

	return nil
}

// StoreContent saves message content data.
func (s *SQLiteStorageBackend) StoreContent(id string, data []byte) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO queue_contents (id, content) VALUES (?, ?)`, id, data)
	if err != nil {
		return fmt.Errorf("failed to store message content: %w", err)
	}
	return nil
}

// RetrieveContent loads message content data.
func (s *SQLiteStorageBackend) RetrieveContent(id string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT content FROM queue_contents WHERE id = ?`, id).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("content not found for message: %s", id)
		}
		return nil, fmt.Errorf("failed to retrieve message content: %w", err)
	}
	return data, nil
}

// DeleteContent removes message content data.
func (s *SQLiteStorageBackend) DeleteContent(id string) error {
	if _, err := s.db.Exec(`DELETE FROM queue_contents WHERE id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete message content: %w", err)
	}
	return nil
}

// Cleanup removes old messages based on retention policy.
func (s *SQLiteStorageBackend) Cleanup(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention hours must be positive")
	}

	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour)
	cutoffStr := cutoff.UTC().Format(time.RFC3339Nano)

	ids, err := s.listIDsOlderThan(cutoffStr)
	if err != nil {
		return 0, err
	}

	if len(ids) == 0 {
		return 0, nil
	}

	if _, err := s.db.Exec(`DELETE FROM queue_messages WHERE created_at < ?`, cutoffStr); err != nil {
		return 0, fmt.Errorf("failed to cleanup old messages: %w", err)
	}

	for _, id := range ids {
		if _, err := s.db.Exec(`DELETE FROM queue_contents WHERE id = ?`, id); err != nil {
			return 0, fmt.Errorf("failed to cleanup message content for %s: %w", id, err)
		}
	}

	return len(ids), nil
}

func (s *SQLiteStorageBackend) listIDsByQueueType(queueType QueueType) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM queue_messages WHERE queue_type = ?`, string(queueType))
	if err != nil {
		return nil, fmt.Errorf("failed to list message ids: %w", err)
	}
	defer rows.Close()

	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed scanning message id: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating message ids: %w", err)
	}

	return ids, nil
}

func (s *SQLiteStorageBackend) listIDsOlderThan(cutoffRFC3339 string) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM queue_messages WHERE created_at < ?`, cutoffRFC3339)
	if err != nil {
		return nil, fmt.Errorf("failed to list old message ids: %w", err)
	}
	defer rows.Close()

	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed scanning old message id: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating old message ids: %w", err)
	}

	return ids, nil
}

func normalizeSQLiteJournalMode(mode string) string {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	switch mode {
	case "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF":
		return mode
	default:
		return "WAL"
	}
}

func normalizeSQLiteSynchronous(mode string) string {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	switch mode {
	case "OFF", "NORMAL", "FULL", "EXTRA":
		return mode
	default:
		return "NORMAL"
	}
}
