package queue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type indexedFSIndexFixture struct {
	Messages map[string]struct {
		QueueType QueueType `json:"queue_type"`
	} `json:"messages"`
}

func readIndexedFSIndex(t *testing.T, indexPath string) indexedFSIndexFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(indexPath, "messages.json"))
	if err != nil {
		t.Fatalf("read index file: %v", err)
	}
	var state indexedFSIndexFixture
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	return state
}

func TestIndexedFSIndexTracksLifecycle(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")

	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	msg := Message{
		ID:        "m1",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "s",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := backend.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	state := readIndexedFSIndex(t, idx)
	entry, ok := state.Messages[msg.ID]
	if !ok {
		t.Fatalf("expected message %s in index", msg.ID)
	}
	if entry.QueueType != Active {
		t.Fatalf("expected queue_type active, got %s", entry.QueueType)
	}

	if err := backend.Move(msg.ID, Active, Deferred); err != nil {
		t.Fatalf("move: %v", err)
	}
	state = readIndexedFSIndex(t, idx)
	entry = state.Messages[msg.ID]
	if entry.QueueType != Deferred {
		t.Fatalf("expected queue_type deferred after move, got %s", entry.QueueType)
	}

	if err := backend.Delete(msg.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	state = readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[msg.ID]; ok {
		t.Fatalf("expected message %s removed from index", msg.ID)
	}
}

func TestIndexedFSRecoveryRebuildsIndexOnStartup(t *testing.T) {
	root := t.TempDir()
	base := NewFileStorageBackend(root)
	if err := base.EnsureDirectories(); err != nil {
		t.Fatalf("ensure directories: %v", err)
	}

	msg := Message{
		ID:        "m2",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "seed",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := base.Store(msg); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	idx := filepath.Join(root, "index")
	if _, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx, RecoveryOnStartup: true}); err != nil {
		t.Fatalf("new indexedfs backend: %v", err)
	}

	state := readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[msg.ID]; !ok {
		t.Fatalf("expected recovered message %s in index", msg.ID)
	}
}

func TestIndexedFSCountIgnoresStrayMetadataFiles(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	msg := Message{
		ID:        "m3",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "count",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := backend.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	stray := filepath.Join(root, string(Active), "stray.json")
	if err := os.WriteFile(stray, []byte(`{"junk":true}`), 0600); err != nil {
		t.Fatalf("write stray file: %v", err)
	}

	count, err := backend.Count(Active)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected indexed count=1, got %d", count)
	}
}

func TestIndexedFSDeleteAllUsesIndexAndPrunesStaleEntries(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	now := time.Now()
	messages := []Message{
		{ID: "d1", QueueType: Active, From: "a@example.com", To: []string{"b@example.com"}, Subject: "d1", CreatedAt: now, UpdatedAt: now},
		{ID: "d2", QueueType: Active, From: "a@example.com", To: []string{"b@example.com"}, Subject: "d2", CreatedAt: now, UpdatedAt: now},
	}
	for _, msg := range messages {
		if err := backend.Store(msg); err != nil {
			t.Fatalf("store %s: %v", msg.ID, err)
		}
	}

	if err := os.Remove(filepath.Join(root, string(Active), "d2.json")); err != nil {
		t.Fatalf("remove underlying file for stale index test: %v", err)
	}

	if err := backend.DeleteAll(Active); err != nil {
		t.Fatalf("deleteall: %v", err)
	}

	count, err := backend.Count(Active)
	if err != nil {
		t.Fatalf("count after deleteall: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected active count=0 after deleteall, got %d", count)
	}

	state := readIndexedFSIndex(t, idx)
	if len(state.Messages) != 0 {
		t.Fatalf("expected empty index after deleteall, got %d entries", len(state.Messages))
	}
}

func TestIndexedFSCleanupUsesIndexAndPrunesStaleEntries(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	oldMsg := Message{ID: "c-old", QueueType: Failed, From: "a@example.com", To: []string{"b@example.com"}, Subject: "old", CreatedAt: time.Now().Add(-3 * time.Hour), UpdatedAt: time.Now()}
	newMsg := Message{ID: "c-new", QueueType: Failed, From: "a@example.com", To: []string{"b@example.com"}, Subject: "new", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	for _, msg := range []Message{oldMsg, newMsg} {
		if err := backend.Store(msg); err != nil {
			t.Fatalf("store %s: %v", msg.ID, err)
		}
	}

	if err := os.Remove(filepath.Join(root, string(Failed), "c-new.json")); err != nil {
		t.Fatalf("remove underlying file for stale index test: %v", err)
	}

	deleted, err := backend.Cleanup(1)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted old message, got %d", deleted)
	}

	count, err := backend.Count(Failed)
	if err != nil {
		t.Fatalf("count after cleanup: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected failed count=0 after cleanup, got %d", count)
	}
}
