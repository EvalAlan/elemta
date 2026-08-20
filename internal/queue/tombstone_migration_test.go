package queue

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Enqueue idempotency is decided against a tombstone written when a message was
// consumed. Adding a content hash to that record changes an on-disk format that
// existing deployments already have files in, so both directions have to work:
// a new binary reading an old tombstone, and an old binary reading a new one.
//
// Getting this wrong does not corrupt anything — it makes the server report
// "conflicts with consumed enqueue identity" and refuse mail it should have
// recognised as a duplicate.

func testMessage(id string) Message {
	now := time.Now().UTC().Truncate(time.Second)
	return Message{
		ID:         id,
		QueueType:  Active,
		From:       "sender@example.com",
		To:         []string{"user@example.com"},
		Domain:     "example.com",
		Subject:    "migration",
		Priority:   PriorityNormal,
		ReceivedAt: now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// writeLegacyTombstone writes a tombstone in the pre-hash format: the whole
// body embedded, no content_hash field.
func writeLegacyTombstone(t *testing.T, queueDir string, msg Message, content []byte) {
	t.Helper()

	legacy := struct {
		Message Message `json:"message"`
		Content []byte  `json:"content"`
	}{Message: msg, Content: content}

	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy tombstone: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(queueDir, "tmp"), 0o700); err != nil {
		t.Fatalf("create tmp dir: %v", err)
	}
	path := filepath.Join(queueDir, "tmp", ".consumed-"+msg.ID+".json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write legacy tombstone: %v", err)
	}
}

// TestLegacyTombstoneIsHonoured is the upgrade case: a tombstone already on
// disk, written without a hash, must still suppress a duplicate enqueue.
func TestLegacyTombstoneIsHonoured(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	msg := testMessage("legacy-same")
	content := []byte("Subject: hello\r\n\r\nbody text\r\n")
	writeLegacyTombstone(t, dir, msg, content)

	created, err := fs.CreateMessageIfAbsent(msg, content)
	if err != nil {
		t.Fatalf("re-enqueue of a consumed message should be suppressed, not fail: %v", err)
	}
	if created {
		t.Error("a consumed message should not be recreated")
	}
}

// TestLegacyTombstoneStillDetectsConflict makes sure the fallback did not
// become permissive: different content under the same ID is still a conflict.
func TestLegacyTombstoneStillDetectsConflict(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	msg := testMessage("legacy-conflict")
	writeLegacyTombstone(t, dir, msg, []byte("original body"))

	if _, err := fs.CreateMessageIfAbsent(msg, []byte("different body")); err == nil {
		t.Error("different content under a consumed ID should conflict")
	}
}

// TestLegacyTombstoneHonouredForStreamedContent covers the awkward combination:
// an old tombstone that can only be settled by comparing bodies, against a
// message being enqueued from a stream.
func TestLegacyTombstoneHonouredForStreamedContent(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	msg := testMessage("legacy-stream")
	content := []byte("Subject: streamed\r\n\r\nbody text\r\n")
	writeLegacyTombstone(t, dir, msg, content)

	created, err := fs.CreateMessageIfAbsentStream(msg, OpenerForBytes(content))
	if err != nil {
		t.Fatalf("streamed re-enqueue should be suppressed, not fail: %v", err)
	}
	if created {
		t.Error("a consumed message should not be recreated")
	}
}

// TestNewTombstoneRemainsReadableByOldBinaries is the rollback case.
//
// A tombstone written now must still carry the body, because a binary rolled
// back to a build that predates ContentHash reads only that field. If it were
// dropped, the old binary would see an empty body, decide every retry
// conflicts, and start refusing mail.
func TestNewTombstoneRemainsReadableByOldBinaries(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorageBackend(dir)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	msg := testMessage("rollback-safe")
	content := []byte("Subject: rollback\r\n\r\nbody text\r\n")
	if err := fs.RecordEnqueueTombstone(msg, content); err != nil {
		t.Fatalf("record tombstone: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "tmp", ".consumed-"+msg.ID+".json"))
	if err != nil {
		t.Fatalf("read tombstone: %v", err)
	}

	// Decode with the old shape, which knows nothing about content_hash.
	var legacy struct {
		Message Message `json:"message"`
		Content []byte  `json:"content"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("a tombstone written now must still decode as the old format: %v", err)
	}
	if string(legacy.Content) != string(content) {
		t.Errorf("the body must still be present for rolled-back binaries\n  want %q\n  got  %q",
			content, legacy.Content)
	}

	// And the new field is there for binaries that understand it.
	var current enqueueTombstone
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatalf("decode current format: %v", err)
	}
	if current.ContentHash != ContentHash(content) {
		t.Errorf("content_hash = %q, want %q", current.ContentHash, ContentHash(content))
	}
}

// TestTombstoneMatchesContentPrefersHash pins which field decides identity when
// both are present, and that a stale body alongside a correct hash does not
// cause a false conflict.
func TestTombstoneMatchesContentPrefersHash(t *testing.T) {
	content := []byte("the real body")
	hash := ContentHash(content)

	withBoth := enqueueTombstone{Content: []byte("stale body"), ContentHash: hash}
	if !withBoth.matchesContent(nil, hash) {
		t.Error("a matching hash should settle identity even if the stored body differs")
	}
	if withBoth.matchesContent(nil, ContentHash([]byte("other"))) {
		t.Error("a non-matching hash should not match")
	}

	legacyOnly := enqueueTombstone{Content: content}
	if !legacyOnly.matchesContent(content, hash) {
		t.Error("a hashless tombstone should compare bodies")
	}
	if legacyOnly.matchesContent([]byte("other"), hash) {
		t.Error("a hashless tombstone should reject a different body")
	}
}

func TestContentHashIsStableAndDistinct(t *testing.T) {
	a := []byte("Subject: one\r\n\r\nbody\r\n")
	b := []byte("Subject: two\r\n\r\nbody\r\n")

	if firstA, secondA := ContentHash(a), ContentHash(a); firstA != secondA {
		t.Errorf("hashing the same content twice must agree: %q vs %q", firstA, secondA)
	}
	if ContentHash(a) == ContentHash(b) {
		t.Error("different content must hash differently")
	}

	streamed, err := ContentHashFromReader(bytes.NewReader(a))
	if err != nil {
		t.Fatalf("hash from reader: %v", err)
	}
	if streamed != ContentHash(a) {
		t.Errorf("streamed hash %q disagrees with in-memory hash %q", streamed, ContentHash(a))
	}

	empty := ContentHash(nil)
	if empty == "" {
		t.Error("empty content should still produce a hash")
	}
}

// The rollback case for SQLite, which had no such test until it was needed.
//
// The file backend has been protected by TestNewTombstoneRemainsReadableByOldBinaries
// for a while. SQLite and Postgres were not, and when the body was dropped from
// them the same hazard was introduced silently: a binary rolled back to a build
// that predates content_digest selects only `content`, finds it empty, decides
// every retry conflicts, and starts refusing mail. Nothing failed, because
// nothing checked.
func TestSQLiteTombstoneRemainsReadableByOldBinaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	backend, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}

	msg := testMessage("sqlite-rollback-safe")
	content := []byte("Subject: rollback\r\n\r\nbody text\r\n")
	if _, err := backend.CreateMessageIfAbsent(msg, content); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := backend.DeleteMessageWithTombstone(msg, content); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Read it the way a binary that knows nothing about content_digest would.
	var legacyContent []byte
	if err := backend.db.QueryRow(
		`SELECT content FROM queue_enqueue_tombstones WHERE id = ?`, msg.ID).
		Scan(&legacyContent); err != nil {
		t.Fatalf("reading tombstone: %v", err)
	}
	if !bytes.Equal(legacyContent, content) {
		t.Errorf("a tombstone written now must still carry the body for a "+
			"rolled-back binary\n  want %d bytes\n  got  %d", len(content), len(legacyContent))
	}
}
