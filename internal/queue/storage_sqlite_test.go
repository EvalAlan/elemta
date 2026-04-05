package queue

import (
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
