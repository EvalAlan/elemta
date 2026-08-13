package queue

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// A tombstone must not keep the message body. Storing it leaked 1.9GB across
// 296,707 rows on a development queue in two days — 93% of the database — for
// a check a 32-byte digest answers.
func TestTombstonesDoNotStoreMessageBodies(t *testing.T) {
	backend := newTestSQLiteBackend(t)

	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	msg := Message{ID: "keeps-no-body", QueueType: Active, From: "a@example.com",
		To: []string{"b@example.com"}, CreatedAt: time.Now()}

	consume(t, backend, msg, body)

	var stored []byte
	var digest string
	err := backend.db.QueryRow(
		`SELECT content, content_digest FROM queue_enqueue_tombstones WHERE id = ?`,
		msg.ID).Scan(&stored, &digest)
	if err != nil {
		t.Fatalf("reading tombstone: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("tombstone kept %d bytes of the message body; it should keep none", len(stored))
	}
	if digest != tombstoneDigest(body) {
		t.Errorf("digest = %q, want the digest of the body", digest)
	}
}

// A conflicting re-enqueue — same ID, different bytes — must still be caught
// now that the comparison runs on a digest rather than the body.
func TestTombstoneStillCatchesAConflictingReuse(t *testing.T) {
	backend := newTestSQLiteBackend(t)
	msg := Message{ID: "reused", QueueType: Active, From: "a@example.com",
		To: []string{"b@example.com"}, CreatedAt: time.Now()}

	consume(t, backend, msg, []byte("original body"))

	created, err := backend.CreateMessageIfAbsent(msg, []byte("DIFFERENT body"))
	if err == nil {
		t.Fatalf("re-enqueuing id %q with different content was accepted (created=%v); "+
			"the digest check is not catching conflicts", msg.ID, created)
	}

	// And the honest repeat — same ID, same bytes — must still be recognised as
	// already consumed rather than reported as a conflict.
	created, err = backend.CreateMessageIfAbsent(msg, []byte("original body"))
	if err != nil {
		t.Fatalf("re-enqueuing the identical message was rejected: %v", err)
	}
	if created {
		t.Error("an already-consumed message was created again")
	}
}

// Cleanup must prune tombstones on their own age. Nothing deleted them before,
// in either backend, so the table grew without bound.
func TestCleanupPrunesOldTombstones(t *testing.T) {
	backend := newTestSQLiteBackend(t)

	for i := 0; i < 3; i++ {
		msg := Message{ID: fmt.Sprintf("old-%d", i), QueueType: Active,
			From: "a@example.com", To: []string{"b@example.com"}, CreatedAt: time.Now()}
		consume(t, backend, msg, []byte("body"))
	}
	// Age them past the retention bound.
	stale := time.Now().Add(-(tombstoneRetentionHours + 1) * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := backend.db.Exec(`UPDATE queue_enqueue_tombstones SET consumed_at = ?`, stale); err != nil {
		t.Fatalf("ageing tombstones: %v", err)
	}

	// A recent one, which must survive.
	fresh := Message{ID: "fresh", QueueType: Active, From: "a@example.com",
		To: []string{"b@example.com"}, CreatedAt: time.Now()}
	consume(t, backend, fresh, []byte("body"))

	if _, err := backend.Cleanup(24); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var remaining int
	if err := backend.db.QueryRow(`SELECT COUNT(*) FROM queue_enqueue_tombstones`).Scan(&remaining); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if remaining != 1 {
		t.Errorf("after cleanup %d tombstones remain, want 1 (the fresh one); "+
			"stale tombstones are not being pruned", remaining)
	}
}

// consume puts a message through its real lifecycle: enqueued, then consumed
// with a tombstone. DeleteMessageWithTombstone refuses a message that was never
// there, so the create is part of the setup rather than a detail.
func consume(t *testing.T, backend *SQLiteStorageBackend, msg Message, body []byte) {
	t.Helper()
	if _, err := backend.CreateMessageIfAbsent(msg, body); err != nil {
		t.Fatalf("enqueue %s: %v", msg.ID, err)
	}
	if err := backend.DeleteMessageWithTombstone(msg, body); err != nil {
		t.Fatalf("consume %s: %v", msg.ID, err)
	}
}

func newTestSQLiteBackend(t *testing.T) *SQLiteStorageBackend {
	t.Helper()
	path := filepath.Join(t.TempDir(), "queue.db")
	backend, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatalf("creating sqlite backend: %v", err)
	}
	return backend
}
