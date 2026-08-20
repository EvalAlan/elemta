package queue

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// By default a tombstone keeps the message body, because a binary rolled back
// to a build predating ContentHash reads only that field and an empty one makes
// it treat every retry as a conflict — it starts refusing mail.
//
// An earlier revision of this file asserted the opposite. Dropping the body
// halves the write on every delivery, which is worth having, but it is a
// decision about how far back a deployment can roll rather than a free win, so
// it is opt-in now and the safe side is the default.
func TestTombstoneKeepsTheBodyByDefault(t *testing.T) {
	backend := newTestSQLiteBackend(t)

	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	msg := Message{ID: "keeps-body", QueueType: Active, From: "a@example.com",
		To: []string{"b@example.com"}, CreatedAt: time.Now()}
	consume(t, backend, msg, body)

	var stored []byte
	var digest string
	if err := backend.db.QueryRow(
		`SELECT content, content_digest FROM queue_enqueue_tombstones WHERE id = ?`,
		msg.ID).Scan(&stored, &digest); err != nil {
		t.Fatalf("reading tombstone: %v", err)
	}
	if !bytes.Equal(stored, body) {
		t.Errorf("tombstone kept %d bytes of the body, want the whole %d — a "+
			"rolled-back binary reads this field and would refuse mail", len(stored), len(body))
	}
	if digest != tombstoneDigest(body) {
		t.Errorf("digest = %q, want the digest of the body", digest)
	}
}

// And with the body switched off, it is not written.
func TestTombstoneDropsTheBodyWhenConfigured(t *testing.T) {
	backend := newTestSQLiteBackend(t)
	backend.tombstoneBody.setRetain(false)

	body := []byte("a message body that should not be stored")
	msg := Message{ID: "drops-body", QueueType: Active, From: "a@example.com",
		To: []string{"b@example.com"}, CreatedAt: time.Now()}
	consume(t, backend, msg, body)

	var stored []byte
	var digest string
	if err := backend.db.QueryRow(
		`SELECT content, content_digest FROM queue_enqueue_tombstones WHERE id = ?`,
		msg.ID).Scan(&stored, &digest); err != nil {
		t.Fatalf("reading tombstone: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("tombstone kept %d bytes with the body switched off", len(stored))
	}
	// The digest still has to be there, or nothing can settle identity at all.
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

// The file backend accumulated 418,462 tombstones totalling 793MB on a
// development queue because nothing removed them — the same unbounded growth
// the sqlite and postgres backends had, on the backend that was missed.
func TestFileBackendPrunesOldTombstones(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	stale := testMessage("stale-tomb")
	if err := fs.RecordEnqueueTombstone(stale, []byte("body")); err != nil {
		t.Fatalf("record stale: %v", err)
	}
	stalePath := filepath.Join(dir, "tmp", ".consumed-"+stale.ID+".json")
	old := time.Now().Add(-(tombstoneRetentionHours + 1) * time.Hour)
	if err := os.Chtimes(stalePath, old, old); err != nil {
		t.Fatalf("ageing the tombstone: %v", err)
	}

	fresh := testMessage("fresh-tomb")
	if err := fs.RecordEnqueueTombstone(fresh, []byte("body")); err != nil {
		t.Fatalf("record fresh: %v", err)
	}

	if _, err := fs.Cleanup(24); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Error("a tombstone past the retention bound survived cleanup; they grow without limit")
	}
	if _, err := os.Stat(filepath.Join(dir, "tmp", ".consumed-"+fresh.ID+".json")); err != nil {
		t.Errorf("a fresh tombstone was pruned: %v", err)
	}
}
