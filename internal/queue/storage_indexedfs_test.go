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

func TestIndexedFSValidateIndexIntegrityDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	msg := Message{
		ID:        "v1",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "integrity",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := backend.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Corrupt the index file with garbage
	if err := os.WriteFile(filepath.Join(idx, "messages.json"), []byte(`{"messages":{`), 0600); err != nil {
		t.Fatalf("corrupt index: %v", err)
	}

	// ValidateIndexIntegrity should detect and auto-heal by rebuilding
	if err := backend.ValidateIndexIntegrity(); err != nil {
		t.Fatalf("validateIndexIntegrity should auto-heal, got: %v", err)
	}

	// The rebuilt index should still contain our message
	state := readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[msg.ID]; !ok {
		t.Fatalf("expected message %s recovered after corruption detection", msg.ID)
	}
}

func TestIndexedFSValidateIndexIntegrityDetectsMissingFiles(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	msg := Message{
		ID:        "v2",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "orphan",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := backend.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Delete the backing file but leave index entry (simulates crash mid-delete)
	if err := os.Remove(filepath.Join(root, string(Active), msg.ID+".json")); err != nil {
		t.Fatalf("remove backing file: %v", err)
	}

	// ValidateIndexIntegrity should prune the orphaned entry
	if err := backend.ValidateIndexIntegrity(); err != nil {
		t.Fatalf("validateIndexIntegrity: %v", err)
	}

	state := readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[msg.ID]; ok {
		t.Fatalf("expected orphaned message %s pruned from index", msg.ID)
	}
}

func TestIndexedFSMaintenanceCompactsAndPrunes(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	now := time.Now()
	// Store active message
	activeMsg := Message{
		ID:        "maint-active",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := backend.Store(activeMsg); err != nil {
		t.Fatalf("store active: %v", err)
	}

	// Store a failed message then delete its backing file (orphan)
	orphanMsg := Message{
		ID:        "maint-orphan",
		QueueType: Failed,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "orphan",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := backend.Store(orphanMsg); err != nil {
		t.Fatalf("store orphan: %v", err)
	}
	if err := os.Remove(filepath.Join(root, string(Failed), orphanMsg.ID+".json")); err != nil {
		t.Fatalf("remove orphan backing file: %v", err)
	}

	// Run maintenance — should prune the orphaned entry
	pruned, err := backend.Maintenance()
	if err != nil {
		t.Fatalf("maintenance: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned entry, got %d", pruned)
	}

	// Verify: active message still present, orphan removed
	state := readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[activeMsg.ID]; !ok {
		t.Fatalf("expected active message still in index after maintenance")
	}
	if _, ok := state.Messages[orphanMsg.ID]; ok {
		t.Fatalf("expected orphan message pruned from index after maintenance")
	}
}

func TestIndexedFSChecksumPresentAfterStore(t *testing.T) {
	root := t.TempDir()
	idx := filepath.Join(root, "index")
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{IndexPath: idx})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	msg := Message{
		ID:        "cs1",
		QueueType: Deferred,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "checksum",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := backend.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Read the index and verify checksum is non-zero (stored as float64 in JSON)
	data, err := os.ReadFile(filepath.Join(idx, "messages.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var raw struct {
		Checksum float64 `json:"checksum"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw.Checksum == 0 {
		t.Fatalf("expected non-zero checksum in stored index")
	}
}

func TestIndexedFSRecoveryContinuesOnPartialFailure(t *testing.T) {
	// Simulates a scenario where one queue directory is unreadable during rebuild.
	// The rebuild should still succeed with whatever queues it can list.
	root := t.TempDir()
	base := NewFileStorageBackend(root)
	if err := base.EnsureDirectories(); err != nil {
		t.Fatalf("ensure directories: %v", err)
	}

	// Store a message in the Active queue
	msg := Message{
		ID:        "recovery-partial",
		QueueType: Active,
		From:      "a@example.com",
		To:        []string{"b@example.com"},
		Subject:   "partial",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := base.Store(msg); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Remove one queue directory to simulate unreadable queue
	if err := os.RemoveAll(filepath.Join(root, string(Deferred))); err != nil {
		t.Fatalf("remove deferred dir: %v", err)
	}

	idx := filepath.Join(root, "index")

	// Recovery should not fail even though deferred queue dir is missing
	backend, err := NewIndexedFSStorageBackend(root, IndexedFSConfig{
		IndexPath:         idx,
		RecoveryOnStartup: true,
	})
	if err != nil {
		t.Fatalf("recovery should continue on partial failure, got: %v", err)
	}

	state := readIndexedFSIndex(t, idx)
	if _, ok := state.Messages[msg.ID]; !ok {
		t.Fatalf("expected message in rebuilt index despite partial queue failure")
	}

	_ = backend
}
