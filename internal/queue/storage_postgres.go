package queue

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PostgresStorageBackend implements StorageBackend with PostgreSQL.
type PostgresStorageBackend struct {
	// Zero value keeps the tombstone body. See tombstoneBodyPolicy.
	tombstoneBody tombstoneBodyPolicy
	db            *sql.DB
}

// PostgresStorageStats holds postgres-backed storage usage metrics.
type PostgresStorageStats struct {
	MessageRows        int64
	ContentRows        int64
	ContentBytes       int64
	TotalRelationBytes int64
}

const postgresEnqueueLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

const postgresCreateMessageSQL = `INSERT INTO queue_messages(id, queue_type, metadata, created_at, updated_at)
VALUES ($1,$2,$3::jsonb,$4,$5) ON CONFLICT (id) DO NOTHING`

// The body is deliberately not stored; the digest is what the conflict check
// needs. See internal/queue/tombstone.go.
const postgresInsertTombstoneSQL = `INSERT INTO queue_enqueue_tombstones(id, metadata, content, consumed_at, content_digest)
VALUES ($1,$2::jsonb,$3,NOW(),$4) ON CONFLICT(id) DO NOTHING`

const postgresTombstoneSchemaSQL = `CREATE TABLE IF NOT EXISTS queue_enqueue_tombstones (
  id TEXT PRIMARY KEY,
  metadata JSONB NOT NULL,
  content BYTEA NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  content_digest TEXT NOT NULL DEFAULT ''
)`

// CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so a
// queue created before tombstones carried a digest needs the column added.
const postgresTombstoneMigrationSQL = `ALTER TABLE queue_enqueue_tombstones
ADD COLUMN IF NOT EXISTS content_digest TEXT NOT NULL DEFAULT ''`

const postgresTombstoneIndexSQL = `CREATE INDEX IF NOT EXISTS idx_queue_tombstones_consumed_at
ON queue_enqueue_tombstones(consumed_at)`

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
  updated_at TIMESTAMPTZ NOT NULL,
  claimed_by TEXT,
  claim_until TIMESTAMPTZ
);

ALTER TABLE queue_messages ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE queue_messages ADD COLUMN IF NOT EXISTS claim_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_queue_messages_queue_type ON queue_messages(queue_type);
CREATE INDEX IF NOT EXISTS idx_queue_messages_created_at ON queue_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_queue_messages_claim_until ON queue_messages(claim_until);
CREATE INDEX IF NOT EXISTS idx_queue_messages_queue_claim ON queue_messages(queue_type, claim_until);

CREATE TABLE IF NOT EXISTS queue_contents (
  id TEXT PRIMARY KEY REFERENCES queue_messages(id) ON DELETE CASCADE,
  content BYTEA NOT NULL
);
`

	if _, err := p.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize postgres schema: %w", err)
	}
	if _, err := p.db.Exec(postgresTombstoneSchemaSQL); err != nil {
		return fmt.Errorf("failed to initialize postgres tombstone schema: %w", err)
	}
	if _, err := p.db.Exec(postgresTombstoneMigrationSQL); err != nil {
		return fmt.Errorf("failed to add tombstone digest column: %w", err)
	}
	if _, err := p.db.Exec(postgresTombstoneIndexSQL); err != nil {
		return fmt.Errorf("failed to index tombstone consumed_at: %w", err)
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

func (p *PostgresStorageBackend) CreateMessageIfAbsent(msg Message, content []byte) (bool, error) {
	if strings.TrimSpace(msg.ID) == "" {
		return false, fmt.Errorf("message id is required")
	}
	now := time.Now().UTC()
	if msg.QueueType == "" {
		msg.QueueType = Active
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = now
	}
	if msg.UpdatedAt.IsZero() {
		msg.UpdatedAt = now
	}
	tx, err := p.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(postgresEnqueueLockSQL, msg.ID); err != nil {
		return false, err
	}
	metadata, err := json.Marshal(msg)
	if err != nil {
		return false, err
	}
	var tombMetadata, tombContent []byte
	var tombDigest string
	err = tx.QueryRow(`SELECT metadata, content, content_digest FROM queue_enqueue_tombstones WHERE id=$1`, msg.ID).Scan(&tombMetadata, &tombContent, &tombDigest)
	if err == nil {
		var existing Message
		if json.Unmarshal(tombMetadata, &existing) != nil || !sameEnqueueMessage(existing, msg) || !sameTombstoneContent(tombDigest, tombContent, content) {
			return false, fmt.Errorf("message ID %q conflicts with consumed enqueue identity", msg.ID)
		}
		return false, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	res, err := tx.Exec(postgresCreateMessageSQL, msg.ID, string(msg.QueueType), string(metadata), msg.CreatedAt.UTC(), msg.UpdatedAt.UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	created := n == 1
	if !created {
		var raw []byte
		if err := tx.QueryRow(`SELECT metadata FROM queue_messages WHERE id=$1 FOR UPDATE`, msg.ID).Scan(&raw); err != nil {
			return false, err
		}
		var existing Message
		if json.Unmarshal(raw, &existing) != nil || !sameEnqueueMessage(existing, msg) {
			return false, fmt.Errorf("message ID %q conflicts with existing metadata", msg.ID)
		}
	}
	var old []byte
	err = tx.QueryRow(`SELECT content FROM queue_contents WHERE id=$1`, msg.ID).Scan(&old)
	if err == nil && !bytes.Equal(old, content) {
		return false, fmt.Errorf("message ID %q conflicts with existing content", msg.ID)
	}
	if err == sql.ErrNoRows {
		_, err = tx.Exec(`INSERT INTO queue_contents(id, content) VALUES ($1,$2)`, msg.ID, content)
	}
	if err != nil {
		return false, err
	}
	return created, tx.Commit()
}

func (p *PostgresStorageBackend) DeleteMessageWithTombstone(msg Message, content []byte) error {
	if strings.TrimSpace(msg.ID) == "" {
		return fmt.Errorf("message id is required")
	}
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.Exec(postgresEnqueueLockSQL, msg.ID); err != nil {
		return err
	}

	// Lock and validate the complete live pair so a stale worker cannot record
	// the wrong immutable identity or silently consume an incomplete row.
	var liveMetadata, liveContent []byte
	if err = tx.QueryRow(`SELECT m.metadata, c.content
FROM queue_messages m JOIN queue_contents c ON c.id=m.id
WHERE m.id=$1 FOR UPDATE OF m, c`, msg.ID).Scan(&liveMetadata, &liveContent); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("message not found or incomplete: %s", msg.ID)
		}
		return err
	}
	var live Message
	if json.Unmarshal(liveMetadata, &live) != nil || !sameEnqueueMessage(live, msg) || !bytes.Equal(liveContent, content) {
		return fmt.Errorf("message ID %q changed before consume", msg.ID)
	}

	metadata, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	// Preserve the first consumed identity rather than allowing a later caller
	// to replace it. Everything remains in this transaction with the live delete.
	if _, err = tx.Exec(postgresInsertTombstoneSQL, msg.ID, string(metadata), p.tombstoneBody.bodyFor(content), tombstoneDigest(content)); err != nil {
		return err
	}
	var tombMetadata, tombContent []byte
	var tombDigest string
	if err = tx.QueryRow(`SELECT metadata, content, content_digest FROM queue_enqueue_tombstones WHERE id=$1 FOR UPDATE`, msg.ID).Scan(&tombMetadata, &tombContent, &tombDigest); err != nil {
		return err
	}
	var tomb Message
	if json.Unmarshal(tombMetadata, &tomb) != nil || !sameEnqueueMessage(tomb, msg) || !sameTombstoneContent(tombDigest, tombContent, content) {
		return fmt.Errorf("message ID %q conflicts with consumed enqueue identity", msg.ID)
	}
	res, err := tx.Exec(`DELETE FROM queue_messages WHERE id=$1`, msg.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("message not found: %s", msg.ID)
	}
	return tx.Commit()
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
	res, err := p.db.Exec(
		`UPDATE queue_messages
		 SET queue_type = $1, updated_at = $2, claimed_by = NULL, claim_until = NULL
		 WHERE id = $3 AND queue_type = $4`,
		string(toQueue), time.Now().UTC(), id, string(fromQueue),
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

// ClaimMessages atomically claims up to limit messages from a queue for one worker.
func (p *PostgresStorageBackend) ClaimMessages(queueType QueueType, limit int, workerID string, leaseUntil time.Time) ([]Message, error) {
	if limit <= 0 {
		return []Message{}, nil
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, fmt.Errorf("worker id is required")
	}

	rows, err := p.db.Query(
		`WITH claimed AS (
			SELECT id
			FROM queue_messages
			WHERE queue_type = $1
			  AND (claim_until IS NULL OR claim_until < NOW())
			ORDER BY created_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE queue_messages q
		SET claimed_by = $3, claim_until = $4, updated_at = NOW()
		FROM claimed
		WHERE q.id = claimed.id
		RETURNING q.id, q.metadata`,
		string(queueType), limit, workerID, leaseUntil.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to claim messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0, limit)
	for rows.Next() {
		var id string
		var metadata []byte
		if err := rows.Scan(&id, &metadata); err != nil {
			return nil, fmt.Errorf("failed scanning claimed row: %w", err)
		}

		var msg Message
		if err := json.Unmarshal(metadata, &msg); err != nil {
			return nil, fmt.Errorf("failed decoding claimed message metadata: %w", err)
		}
		msg.ID = id
		msg.QueueType = queueType
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating claimed messages: %w", err)
	}

	return messages, nil
}

// ReleaseMessageClaim clears an active claim on a message for the given worker.
func (p *PostgresStorageBackend) ReleaseMessageClaim(id, workerID string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("message id is required")
	}

	query := `UPDATE queue_messages SET claimed_by = NULL, claim_until = NULL, updated_at = NOW() WHERE id = $1`
	args := []any{id}
	if strings.TrimSpace(workerID) != "" {
		query += ` AND claimed_by = $2`
		args = append(args, workerID)
	}

	if _, err := p.db.Exec(query, args...); err != nil {
		return fmt.Errorf("failed to release message claim: %w", err)
	}
	return nil
}

// ListClaims returns active message claims for operational observability.
func (p *PostgresStorageBackend) ListClaims(now time.Time) ([]QueueClaimInfo, error) {
	rows, err := p.db.Query(
		`SELECT id, queue_type, claimed_by, claim_until
		 FROM queue_messages
		 WHERE claimed_by IS NOT NULL OR claim_until IS NOT NULL
		 ORDER BY claim_until ASC NULLS FIRST, updated_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list message claims: %w", err)
	}
	defer rows.Close()

	claims := make([]QueueClaimInfo, 0)
	for rows.Next() {
		var claim QueueClaimInfo
		var queueType string
		if err := rows.Scan(&claim.MessageID, &queueType, &claim.ClaimedBy, &claim.ClaimUntil); err != nil {
			return nil, fmt.Errorf("failed scanning message claim: %w", err)
		}
		claim.QueueType = QueueType(queueType)
		claim.Expired = !claim.ClaimUntil.IsZero() && !claim.ClaimUntil.After(now)
		claim.SecondsRemaining = int64(claim.ClaimUntil.Sub(now).Seconds())
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating message claims: %w", err)
	}
	return claims, nil
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

	// Tombstones are pruned on their own age, independently of whether any
	// message rows expired. They outnumber live messages several times over, so
	// tying them to message expiry would leave the leak running.
	tombCutoff := time.Now().Add(-time.Duration(tombstoneRetentionHours) * time.Hour).UTC()
	if _, err := p.db.Exec(`DELETE FROM queue_enqueue_tombstones WHERE consumed_at < $1`, tombCutoff); err != nil {
		return 0, fmt.Errorf("failed to cleanup enqueue tombstones: %w", err)
	}

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

func (p *PostgresStorageBackend) setTombstoneBody(policy tombstoneBodyPolicy) {
	p.tombstoneBody = policy
}
