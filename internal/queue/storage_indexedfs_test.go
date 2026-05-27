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
