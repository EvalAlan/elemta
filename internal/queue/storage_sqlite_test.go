package queue

import (
	"database/sql"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestSQLiteStorageBackend_BasicLifecycle(t *testing.T) {
	dbPath := t.TempDir() + "/queue.db"

	backend, err := NewSQLiteStorageBackend(dbPath, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatalf("failed to create sqlite backend: %v", err)
	}

	msg := Message{
		ID:        "sqlite-test-1",
		QueueType: Active,
		From:      "sender@example.com",
		To:        []string{"dest@example.com"},
		Subject:   "SQLite Test",
		Size:      12,
		Priority:  PriorityNormal,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	content := []byte("hello sqlite")
	if err := backend.StoreContent(msg.ID, content); err != nil {
		t.Fatalf("failed to store content: %v", err)
	}

	if err := backend.Store(msg); err != nil {
		t.Fatalf("failed to store message: %v", err)
	}

	retrieved, err := backend.Retrieve(msg.ID)
	if err != nil {
		t.Fatalf("failed to retrieve message: %v", err)
	}

	if retrieved.ID != msg.ID {
		t.Fatalf("expected id %q, got %q", msg.ID, retrieved.ID)
	}
	if retrieved.QueueType != Active {
		t.Fatalf("expected queue %q, got %q", Active, retrieved.QueueType)
	}

	retrievedContent, err := backend.RetrieveContent(msg.ID)
	if err != nil {
		t.Fatalf("failed to retrieve content: %v", err)
	}
	if string(retrievedContent) != string(content) {
		t.Fatalf("expected content %q, got %q", string(content), string(retrievedContent))
	}

	if err := backend.Move(msg.ID, Active, Deferred); err != nil {
		t.Fatalf("failed to move message: %v", err)
	}

	moved, err := backend.Retrieve(msg.ID)
	if err != nil {
		t.Fatalf("failed to retrieve moved message: %v", err)
	}
	if moved.QueueType != Deferred {
		t.Fatalf("expected queue %q, got %q", Deferred, moved.QueueType)
	}

	if err := backend.Delete(msg.ID); err != nil {
		t.Fatalf("failed to delete message: %v", err)
	}
	if err := backend.DeleteContent(msg.ID); err != nil {
		t.Fatalf("failed to delete content: %v", err)
	}

	if _, err := backend.Retrieve(msg.ID); err == nil {
		t.Fatalf("expected retrieve after delete to fail")
	}
}

func sqliteEnqueueMessage(id string) Message {
	return Message{ID: id, QueueType: Active, From: "a@example.test", To: []string{"b@example.test"}, Domain: "example.test", Subject: "subject", Size: 4, Priority: PriorityHigh, ReceivedAt: time.Unix(10, 0).UTC(), CreatedAt: time.Unix(20, 0).UTC(), UpdatedAt: time.Unix(20, 0).UTC()}
}

func TestSQLiteAtomicEnqueueRepairsInterruptedPairs(t *testing.T) {
	b, err := NewSQLiteStorageBackend(t.TempDir()+"/queue.db", 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatal(err)
	}
	defer b.db.Close()
	metaOnly := sqliteEnqueueMessage("meta-only")
	if err := b.Store(metaOnly); err != nil {
		t.Fatal(err)
	}
	created, err := b.CreateMessageIfAbsent(metaOnly, []byte("body"))
	if err != nil || created {
		t.Fatalf("metadata repair: created=%v err=%v", created, err)
	}
	if got, err := b.RetrieveContent(metaOnly.ID); err != nil || string(got) != "body" {
		t.Fatalf("content=%q err=%v", got, err)
	}
	contentOnly := sqliteEnqueueMessage("content-only")
	if err := b.StoreContent(contentOnly.ID, []byte("body")); err != nil {
		t.Fatal(err)
	}
	created, err = b.CreateMessageIfAbsent(contentOnly, []byte("body"))
	if err != nil || !created {
		t.Fatalf("content repair: created=%v err=%v", created, err)
	}
	conflict := sqliteEnqueueMessage("conflict-orphan")
	if err := b.StoreContent(conflict.ID, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateMessageIfAbsent(conflict, []byte("body")); err == nil {
		t.Fatal("conflicting orphan content succeeded")
	}
}

func TestSQLiteAtomicEnqueueSeparateClientsDistinctIDs(t *testing.T) {
	path := t.TempDir() + "/queue.db"
	a, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatal(err)
	}
	defer a.db.Close()
	defer b.db.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, backend := range []*SQLiteStorageBackend{a, b} {
		wg.Add(1)
		go func(i int, backend *SQLiteStorageBackend) {
			defer wg.Done()
			_, err := backend.CreateMessageIfAbsent(sqliteEnqueueMessage([]string{"one", "two"}[i]), []byte("body"))
			errs <- err
		}(i, backend)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteTombstoneIgnoresMutableFieldsAndCannotBeRewritten(t *testing.T) {
	b, err := NewSQLiteStorageBackend(t.TempDir()+"/queue.db", 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatal(err)
	}
	defer b.db.Close()
	msg := sqliteEnqueueMessage("mutable")
	if _, err := b.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	msg.QueueType, msg.RetryCount, msg.UpdatedAt = Deferred, 3, time.Unix(99, 0)
	if err := b.Update(msg); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteMessageWithTombstone(msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	retry := sqliteEnqueueMessage("mutable")
	if created, err := b.CreateMessageIfAbsent(retry, []byte("body")); err != nil || created {
		t.Fatalf("retry: created=%v err=%v", created, err)
	}
	conflicting := retry
	conflicting.Subject = "changed"
	if _, err := b.CreateMessageIfAbsent(conflicting, []byte("body")); err == nil {
		t.Fatal("conflicting tombstone identity succeeded")
	}
}

func TestSQLiteTombstoneSchemaMigrationIsIdempotent(t *testing.T) {
	path := t.TempDir() + "/queue.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE queue_messages (id TEXT PRIMARY KEY, queue_type TEXT NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL); CREATE TABLE queue_contents (id TEXT PRIMARY KEY, content BLOB NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	for i := 0; i < 2; i++ {
		b, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
		if err != nil {
			t.Fatal(err)
		}
		var schema string
		if err := b.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='queue_enqueue_tombstones'`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		b.db.Close()
	}
}

func TestSQLiteConsumedLedgerCorruptionFailsClosed(t *testing.T) {
	b, err := NewSQLiteStorageBackend(t.TempDir()+"/queue.db", 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatal(err)
	}
	defer b.db.Close()
	msg := sqliteEnqueueMessage("corrupt")
	raw, _ := json.Marshal(msg)
	if _, err := b.db.Exec(`INSERT INTO queue_enqueue_tombstones(id,metadata,content,consumed_at) VALUES(?,?,?,?)`, msg.ID, string(raw), []byte("different"), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateMessageIfAbsent(msg, []byte("body")); err == nil {
		t.Fatal("corrupt/conflicting ledger did not fail closed")
	}
}
