package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PostgresStorageBackend implements StorageBackend with PostgreSQL.
type PostgresStorageBackend struct {
	db *sql.DB
}

// PostgresStorageStats holds postgres-backed storage usage metrics.
type PostgresStorageStats struct {
	MessageRows        int64
	ContentRows        int64
	ContentBytes       int64
	TotalRelationBytes int64
}

// Ensure PostgresStorageBackend implements StorageBackend interface.
var _ StorageBackend = (*PostgresStorageBackend)(nil)

// NewPostgresStorageBackend creates a PostgreSQL-backed storage implementation.
func NewPostgresStorageBackend(cfg PostgresConfig) (*PostgresStorageBackend, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("postgres dsn is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetimeSeconds > 0 {
		db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeSeconds) * time.Second)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	backend := &PostgresStorageBackend{db: db}
	if err := backend.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return backend, nil
}

func (p *PostgresStorageBackend) ensureSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS queue_messages (
  id TEXT PRIMARY KEY,
  queue_type TEXT NOT NULL,
  metadata JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_queue_messages_queue_type ON queue_messages(queue_type);
CREATE INDEX IF NOT EXISTS idx_queue_messages_created_at ON queue_messages(created_at);

CREATE TABLE IF NOT EXISTS queue_contents (
  id TEXT PRIMARY KEY REFERENCES queue_messages(id) ON DELETE CASCADE,
  content BYTEA NOT NULL
);
`

	if _, err := p.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize postgres schema: %w", err)
	}
	return nil
}

func (p *PostgresStorageBackend) Store(msg Message) error {
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

	_, err = p.db.Exec(
		`INSERT INTO queue_messages (id, queue_type, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3::jsonb, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET
		   queue_type = EXCLUDED.queue_type,
		   metadata = EXCLUDED.metadata,
		   created_at = EXCLUDED.created_at,
		   updated_at = EXCLUDED.updated_at`,
		msg.ID,
		string(msg.QueueType),
		string(metadata),
		msg.CreatedAt.UTC(),
		msg.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to store message metadata: %w", err)
	}
	return nil
}

func (p *PostgresStorageBackend) Retrieve(id string) (Message, error) {
	var queueType string
	var metadata []byte

	err := p.db.QueryRow(`SELECT queue_type, metadata FROM queue_messages WHERE id = $1`, id).Scan(&queueType, &metadata)
	if err != nil {
		if err == sql.ErrNoRows {
			return Message{}, fmt.Errorf("message not found: %s", id)
		}
		return Message{}, fmt.Errorf("failed to retrieve message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(metadata, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to decode message metadata: %w", err)
	}
	msg.ID = id
	msg.QueueType = QueueType(queueType)
	return msg, nil
}

func (p *PostgresStorageBackend) Update(msg Message) error {
	if msg.ID == "" {
		return fmt.Errorf("message id is required")
	}
	if msg.UpdatedAt.IsZero() {
		msg.UpdatedAt = time.Now().UTC()
	}

	metadata, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message metadata: %w", err)
	}

	res, err := p.db.Exec(
		`UPDATE queue_messages SET queue_type = $1, metadata = $2::jsonb, updated_at = $3 WHERE id = $4`,
		string(msg.QueueType),
		string(metadata),
		msg.UpdatedAt.UTC(),
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

func (p *PostgresStorageBackend) Delete(id string) error {
	_, err := p.db.Exec(`DELETE FROM queue_messages WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return nil
}

func (p *PostgresStorageBackend) List(queueType QueueType) ([]Message, error) {
	rows, err := p.db.Query(`SELECT id, metadata FROM queue_messages WHERE queue_type = $1`, string(queueType))
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0)
	for rows.Next() {
		var id string
		var metadata []byte
		if err := rows.Scan(&id, &metadata); err != nil {
			return nil, fmt.Errorf("failed scanning message row: %w", err)
		}

		var msg Message
		if err := json.Unmarshal(metadata, &msg); err != nil {
			return nil, fmt.Errorf("failed decoding message metadata: %w", err)
		}
		msg.ID = id
		msg.QueueType = queueType
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating messages: %w", err)
	}
	return messages, nil
}

func (p *PostgresStorageBackend) Count(queueType QueueType) (int, error) {
	var count int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM queue_messages WHERE queue_type = $1`, string(queueType)).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count messages: %w", err)
	}
	return count, nil
}

func (p *PostgresStorageBackend) DeleteAll(queueType QueueType) error {
	_, err := p.db.Exec(`DELETE FROM queue_messages WHERE queue_type = $1`, string(queueType))
	if err != nil {
		return fmt.Errorf("failed to delete queue %s: %w", queueType, err)
	}
	return nil
}

func (p *PostgresStorageBackend) Move(id string, fromQueue, toQueue QueueType) error {
	res, err := p.db.Exec(`UPDATE queue_messages SET queue_type = $1, updated_at = $2 WHERE id = $3 AND queue_type = $4`, string(toQueue), time.Now().UTC(), id, string(fromQueue))
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

func (p *PostgresStorageBackend) StoreContent(id string, data []byte) error {
	_, err := p.db.Exec(
		`INSERT INTO queue_contents (id, content) VALUES ($1, $2)
		 ON CONFLICT (id) DO UPDATE SET content = EXCLUDED.content`,
		id, data,
	)
	if err != nil {
		return fmt.Errorf("failed to store message content: %w", err)
	}
	return nil
}

func (p *PostgresStorageBackend) RetrieveContent(id string) ([]byte, error) {
	var data []byte
	err := p.db.QueryRow(`SELECT content FROM queue_contents WHERE id = $1`, id).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("content not found for message: %s", id)
		}
		return nil, fmt.Errorf("failed to retrieve message content: %w", err)
	}
	return data, nil
}

func (p *PostgresStorageBackend) DeleteContent(id string) error {
	_, err := p.db.Exec(`DELETE FROM queue_contents WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete message content: %w", err)
	}
	return nil
}

func (p *PostgresStorageBackend) Cleanup(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention hours must be positive")
	}

	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour).UTC()
	res, err := p.db.Exec(`DELETE FROM queue_messages WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old messages: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed checking cleanup result: %w", err)
	}
	return int(affected), nil
}

// StorageStats returns storage-level diagnostics for postgres backend.
func (p *PostgresStorageBackend) StorageStats() (PostgresStorageStats, error) {
	stats := PostgresStorageStats{}

	if err := p.db.QueryRow(`SELECT COUNT(*) FROM queue_messages`).Scan(&stats.MessageRows); err != nil {
		return stats, fmt.Errorf("failed to count queue_messages: %w", err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM queue_contents`).Scan(&stats.ContentRows); err != nil {
		return stats, fmt.Errorf("failed to count queue_contents: %w", err)
	}
	if err := p.db.QueryRow(`SELECT COALESCE(SUM(OCTET_LENGTH(content)), 0) FROM queue_contents`).Scan(&stats.ContentBytes); err != nil {
		return stats, fmt.Errorf("failed to sum queue_contents bytes: %w", err)
	}
	if err := p.db.QueryRow(`SELECT COALESCE(pg_total_relation_size('queue_messages') + pg_total_relation_size('queue_contents'), 0)`).Scan(&stats.TotalRelationBytes); err != nil {
		return stats, fmt.Errorf("failed to query relation sizes: %w", err)
	}

	return stats, nil
}
