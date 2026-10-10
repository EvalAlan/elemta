package queue

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bounded claiming for the SQLite backend.
//
// Without it, Processor.processQueue falls through to List on every tick, which
// reads and decodes every row in the queue before a single worker is
// dispatched. That cost is O(queue depth), so the server slows down exactly
// when it is furthest behind and adding workers barely helps.
//
// The claim is one UPDATE ... RETURNING over the oldest unleased rows, using
// the (queue_type, created_at) index. SQLite has a single writer, so that
// statement is atomic against every other connection on the same database
// file, including other processes: two workers cannot be handed the same row.

// ClaimMessages takes up to limit messages that no worker holds an unexpired
// lease on, leasing them to workerID until leaseUntil. Oldest first, to the
// precision of created_at's RFC3339Nano text, which can misorder two messages
// within the same second; that is close enough for draining a backlog.
func (s *SQLiteStorageBackend) ClaimMessages(queueType QueueType, limit int, workerID string, leaseUntil time.Time) ([]Message, error) {
	if limit <= 0 {
		return []Message{}, nil
	}
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("worker id is required")
	}

	rows, err := s.db.Query(
		`UPDATE queue_messages
		 SET claimed_by = ?, claim_until = ?
		 WHERE id IN (
			SELECT id FROM queue_messages
			WHERE queue_type = ?
			  AND (claim_until IS NULL OR claim_until < ?)
			ORDER BY created_at ASC
			LIMIT ?
		 )
		 RETURNING id, metadata`,
		workerID, leaseUntil.UnixNano(), string(queueType), time.Now().UnixNano(), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to claim messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0, limit)
	var undecodable []string
	for rows.Next() {
		var id, metadata string
		if err := rows.Scan(&id, &metadata); err != nil {
			return nil, fmt.Errorf("failed scanning claimed row: %w", err)
		}
		var msg Message
		if err := json.Unmarshal([]byte(metadata), &msg); err != nil {
			// List skips a row it cannot decode; so does this, but it has to
			// give the lease back rather than sit on the row until it expires.
			undecodable = append(undecodable, id)
			continue
		}
		msg.ID = id
		msg.QueueType = queueType
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating claimed messages: %w", err)
	}
	// The single connection is held by rows until it is closed, so releases
	// have to wait until after.
	_ = rows.Close()
	for _, id := range undecodable {
		_ = s.ReleaseMessageClaim(id, workerID)
	}

	return messages, nil
}

// ReleaseMessageClaim drops the lease so the message can be picked up again.
// An empty workerID releases regardless of holder, matching the other backends.
func (s *SQLiteStorageBackend) ReleaseMessageClaim(id, workerID string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("message id is required")
	}
	query := `UPDATE queue_messages SET claimed_by = NULL, claim_until = NULL WHERE id = ?`
	args := []any{id}
	if strings.TrimSpace(workerID) != "" {
		query += ` AND claimed_by = ?`
		args = append(args, workerID)
	}
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("failed to release message claim: %w", err)
	}
	return nil
}

// ListClaims returns active message claims for operational observability.
func (s *SQLiteStorageBackend) ListClaims(now time.Time) ([]QueueClaimInfo, error) {
	rows, err := s.db.Query(
		`SELECT id, queue_type, claimed_by, claim_until
		 FROM queue_messages
		 WHERE claimed_by IS NOT NULL OR claim_until IS NOT NULL
		 ORDER BY claim_until ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list message claims: %w", err)
	}
	defer rows.Close()

	claims := make([]QueueClaimInfo, 0)
	for rows.Next() {
		var (
			claim      QueueClaimInfo
			queueType  string
			claimedBy  sql.NullString
			claimUntil sql.NullInt64
		)
		if err := rows.Scan(&claim.MessageID, &queueType, &claimedBy, &claimUntil); err != nil {
			return nil, fmt.Errorf("failed scanning message claim: %w", err)
		}
		claim.QueueType = QueueType(queueType)
		claim.ClaimedBy = claimedBy.String
		if claimUntil.Valid {
			claim.ClaimUntil = time.Unix(0, claimUntil.Int64).UTC()
			claim.Expired = now.After(claim.ClaimUntil)
			if !claim.Expired {
				claim.SecondsRemaining = int64(claim.ClaimUntil.Sub(now).Seconds())
			}
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating message claims: %w", err)
	}
	return claims, nil
}
