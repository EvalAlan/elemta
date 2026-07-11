package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStorageBackendRejectsInvalidPathComponents(t *testing.T) {
	invalidIDs := []string{"", "..", "../escape", "/absolute", `a/b`, `a\b`, "nul\x00byte", string(make([]byte, 256))}
	invalidQueues := []QueueType{"", "..", "../escape", "/absolute", `a/b`, `a\b`, QueueType("nul\x00byte")}

	for _, id := range invalidIDs {
		t.Run(fmt.Sprintf("id_%q", id), func(t *testing.T) {
			fs := NewFileStorageBackend(t.TempDir())
			msg := Message{ID: id, QueueType: Active}
			if err := fs.Store(msg); err == nil {
				t.Error("Store accepted invalid ID")
			}
			if err := fs.Update(msg); err == nil {
				t.Error("Update accepted invalid ID")
			}
			if _, err := fs.Retrieve(id); err == nil {
				t.Error("Retrieve accepted invalid ID")
			}
			if err := fs.Delete(id); err == nil {
				t.Error("Delete accepted invalid ID")
			}
			if err := fs.Move(id, Active, Failed); err == nil {
				t.Error("Move accepted invalid ID")
			}
		})
	}

	for _, queueType := range invalidQueues {
		t.Run(fmt.Sprintf("queue_%q", queueType), func(t *testing.T) {
			fs := NewFileStorageBackend(t.TempDir())
			msg := Message{ID: "safe-id", QueueType: queueType}
			if err := fs.Store(msg); err == nil {
				t.Error("Store accepted invalid queue type")
			}
			if err := fs.Update(msg); err == nil {
				t.Error("Update accepted invalid queue type")
			}
			if err := fs.Move("safe-id", queueType, Active); err == nil {
				t.Error("Move accepted invalid source queue")
			}
			if err := fs.Move("safe-id", Active, queueType); err == nil {
				t.Error("Move accepted invalid destination queue")
			}
			if _, err := fs.List(queueType); err == nil {
				t.Error("List accepted invalid queue type")
			}
			if _, err := fs.Count(queueType); err == nil {
				t.Error("Count accepted invalid queue type")
			}
			if err := fs.DeleteAll(queueType); err == nil {
				t.Error("DeleteAll accepted invalid queue type")
			}
		})
	}
}

func TestFileStorageBackendRejectsCorruptMetadataIdentity(t *testing.T) {
	root := t.TempDir()
	fs := NewFileStorageBackend(root)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Message{ID: "different-id", QueueType: Failed})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, string(Active), "expected-id.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Retrieve("expected-id"); err == nil {
		t.Fatal("Retrieve accepted mismatched metadata identity")
	}
	if err := fs.Move("expected-id", Active, Failed); err == nil {
		t.Fatal("Move accepted mismatched metadata identity")
	}
}

func FuzzFileStorageMessagePathContained(f *testing.F) {
	for _, seed := range []string{"safe-id", "../escape", "/tmp/x", `a\b`, "", "nul\x00byte"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		root := t.TempDir()
		fs := NewFileStorageBackend(root)
		err := fs.Store(Message{ID: id, QueueType: Active})
		if err != nil {
			return
		}
		path := filepath.Join(root, string(Active), id+".json")
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("successful Store resolved outside root: id=%q path=%q", id, path)
		}
	})
}

func TestFileStorageBackendSecurity(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "elemta_queue_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create storage backend
	backend := NewFileStorageBackend(tmpDir)

	// Test 1: Ensure directories are created with secure permissions (0700)
	t.Run("SecureDirectoryPermissions", func(t *testing.T) {
		if err := backend.EnsureDirectories(); err != nil {
			t.Fatalf("Failed to ensure directories: %v", err)
		}

		// Check main queue directory permissions
		info, err := os.Stat(tmpDir)
		if err != nil {
			t.Fatalf("Failed to stat main queue directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Main queue directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}

		// Check subdirectory permissions
		queueTypes := []QueueType{Active, Deferred, Hold, Failed}
		for _, qType := range queueTypes {
			qDir := filepath.Join(tmpDir, string(qType))
			info, err := os.Stat(qDir)
			if err != nil {
				t.Fatalf("Failed to stat queue directory %s: %v", qType, err)
			}
			if info.Mode().Perm() != 0700 {
				t.Errorf("Queue directory %s has incorrect permissions: got %o, want 0700", qType, info.Mode().Perm())
			}
		}

		// Check data directory permissions
		dataDir := filepath.Join(tmpDir, "data")
		info, err = os.Stat(dataDir)
		if err != nil {
			t.Fatalf("Failed to stat data directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Data directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}

		// Check tmp directory permissions
		tmpDirPath := filepath.Join(tmpDir, "tmp")
		info, err = os.Stat(tmpDirPath)
		if err != nil {
			t.Fatalf("Failed to stat tmp directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Tmp directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}
	})

	// Test 2: File operations use secure permissions (0600)
	t.Run("SecureFilePermissions", func(t *testing.T) {
		// Create a test message
		msg := Message{
			ID:        "test-message-1",
			QueueType: Active,
			From:      "test@example.com",
			To:        []string{"recipient@example.com"},
			Subject:   "Test Message",
			CreatedAt: time.Now(),
		}

		// Store message
		if err := backend.Store(msg); err != nil {
			t.Fatalf("Failed to store message: %v", err)
		}

		// Check file permissions
		filePath := filepath.Join(tmpDir, string(Active), "test-message-1.json")
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("Failed to stat message file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Message file has incorrect permissions: got %o, want 0600", info.Mode().Perm())
		}

		// Test content file permissions
		contentData := []byte("This is test message content")
		if err := backend.StoreContent("test-message-1", contentData); err != nil {
			t.Fatalf("Failed to store content: %v", err)
		}

		contentPath := filepath.Join(tmpDir, "data", "test-message-1")
		info, err = os.Stat(contentPath)
		if err != nil {
			t.Fatalf("Failed to stat content file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Content file has incorrect permissions: got %o, want 0600", info.Mode().Perm())
		}
	})

	// Test 3: Atomic file operations
	t.Run("AtomicFileOperations", func(t *testing.T) {
		// Create a test message
		msg := Message{
			ID:        "test-atomic-1",
			QueueType: Active,
			From:      "test@example.com",
			To:        []string{"recipient@example.com"},
			Subject:   "Atomic Test Message",
			CreatedAt: time.Now(),
		}

		// Store message (should use atomic write)
		if err := backend.Store(msg); err != nil {
			t.Fatalf("Failed to store message atomically: %v", err)
		}

		// Verify message was stored correctly
		retrieved, err := backend.Retrieve("test-atomic-1")
		if err != nil {
			t.Fatalf("Failed to retrieve message: %v", err)
		}
		if retrieved.ID != msg.ID {
			t.Errorf("Retrieved message ID mismatch: got %s, want %s", retrieved.ID, msg.ID)
		}
	})

	// Test 4: Symlink attack prevention
	t.Run("SymlinkAttackPrevention", func(t *testing.T) {
		// Create a symlink to a sensitive file
		sensitiveFile := filepath.Join(tmpDir, "sensitive.txt")
		if err := os.WriteFile(sensitiveFile, []byte("sensitive data"), 0600); err != nil {
			t.Fatalf("Failed to create sensitive file: %v", err)
		}

		// Create a symlink in the queue directory
		symlinkPath := filepath.Join(tmpDir, string(Active), "malicious.json")
		if err := os.Symlink(sensitiveFile, symlinkPath); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		// Try to store a message with the same name (should detect symlink attack)
		msg := Message{
			ID:        "malicious",
			QueueType: Active,
			From:      "attacker@example.com",
			To:        []string{"victim@example.com"},
			Subject:   "Malicious Message",
			CreatedAt: time.Now(),
		}

		err := backend.Store(msg)
		if err == nil {
			t.Error("Expected symlink attack to be detected, but operation succeeded")
		}
		if err != nil && !contains(err.Error(), "symlink") {
			t.Errorf("Expected symlink attack error, got: %v", err)
		}
	})

	t.Run("SymlinkedQueueDirectoryFailsClosed", func(t *testing.T) {
		root, outside := t.TempDir(), t.TempDir()
		data, _ := json.Marshal(Message{ID: "victim", QueueType: Active})
		outsideFile := filepath.Join(outside, "victim.json")
		if err := os.WriteFile(outsideFile, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, string(Active))); err != nil {
			t.Fatal(err)
		}
		fs := NewFileStorageBackend(root)
		operations := map[string]func() error{
			"Retrieve":  func() error { _, err := fs.Retrieve("victim"); return err },
			"Store":     func() error { return fs.Store(Message{ID: "new", QueueType: Active}) },
			"Update":    func() error { return fs.Update(Message{ID: "victim", QueueType: Active}) },
			"Delete":    func() error { return fs.Delete("victim") },
			"Move":      func() error { return fs.Move("victim", Active, Failed) },
			"List":      func() error { _, err := fs.List(Active); return err },
			"Count":     func() error { _, err := fs.Count(Active); return err },
			"DeleteAll": func() error { return fs.DeleteAll(Active) },
		}
		for name, operation := range operations {
			if err := operation(); err == nil {
				t.Errorf("%s followed symlink", name)
			}
		}
		got, err := os.ReadFile(outsideFile)
		if err != nil || string(got) != string(data) {
			t.Fatalf("external file touched: data=%q err=%v", got, err)
		}
		if _, err := os.Stat(filepath.Join(outside, "new.json")); !os.IsNotExist(err) {
			t.Fatalf("external file created: %v", err)
		}
	})

	t.Run("SymlinkedDataDirectoryFailsClosed", func(t *testing.T) {
		root, outside := t.TempDir(), t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "data")); err != nil {
			t.Fatal(err)
		}
		fs := NewFileStorageBackend(root)
		if err := fs.StoreContent("victim", []byte("bad")); err == nil {
			t.Error("StoreContent followed symlink")
		}
		if _, err := fs.RetrieveContent("victim"); err == nil {
			t.Error("RetrieveContent followed symlink")
		}
		if err := fs.DeleteContent("victim"); err == nil {
			t.Error("DeleteContent followed symlink")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("external directory touched: %v %v", entries, err)
		}
	})

	// Test 5: Race condition prevention with concurrent operations
	t.Run("RaceConditionPrevention", func(t *testing.T) {
		// Create multiple messages concurrently
		const numMessages = 10
		done := make(chan error, numMessages)

		for i := 0; i < numMessages; i++ {
			go func(id int) {
				msg := Message{
					ID:        fmt.Sprintf("concurrent-%d", id),
					QueueType: Active,
					From:      "test@example.com",
					To:        []string{"recipient@example.com"},
					Subject:   "Concurrent Test Message",
					CreatedAt: time.Now(),
				}
				done <- backend.Store(msg)
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < numMessages; i++ {
			if err := <-done; err != nil {
				t.Errorf("Concurrent store operation failed: %v", err)
			}
		}

		// Verify all messages were stored correctly
		for i := 0; i < numMessages; i++ {
			id := fmt.Sprintf("concurrent-%d", i)
			msg, err := backend.Retrieve(id)
			if err != nil {
				t.Errorf("Failed to retrieve concurrent message %s: %v", id, err)
			}
			if msg.ID != id {
				t.Errorf("Retrieved message ID mismatch: got %s, want %s", msg.ID, id)
			}
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			contains(s[1:], substr))))
}

func TestValidateMessageID(t *testing.T) {
	valid := []string{
		"1700000000000000000-2a2b3c4d",
		generateUniqueID(),
		"simple-id_123",
	}
	for _, id := range valid {
		if err := validateMessageID(id); err != nil {
			t.Errorf("validateMessageID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []string{
		"",
		"../../etc/passwd",
		"a/b",
		"a\\b",
		"foo..bar",
		"nul\x00byte",
	}
	for _, id := range invalid {
		if err := validateMessageID(id); err == nil {
			t.Errorf("validateMessageID(%q) = nil, want error", id)
		}
	}
}

func TestFileStorageBackendRejectsTraversalID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "elemta_queue_traversal_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	backend := NewFileStorageBackend(tmpDir)
	if _, err := backend.Retrieve("../../../etc/passwd"); err == nil {
		t.Fatal("expected Retrieve to reject a path-traversal ID")
	}
	if err := backend.Delete("../../secret"); err == nil {
		t.Fatal("expected Delete to reject a path-traversal ID")
	}
}

func TestFileStorageBackendCleanupDeletesExactQueueEntry(t *testing.T) {
	root := t.TempDir()
	fs := NewFileStorageBackend(root)
	old := Message{ID: "duplicate", QueueType: Active, CreatedAt: time.Now().Add(-3 * time.Hour)}
	fresh := Message{ID: "duplicate", QueueType: Failed, CreatedAt: time.Now()}
	if err := fs.Store(old); err != nil {
		t.Fatal(err)
	}
	if err := fs.Store(fresh); err != nil {
		t.Fatal(err)
	}
	deleted, err := fs.Cleanup(1)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted=%d, want 1", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, string(Active), "duplicate.json")); !os.IsNotExist(err) {
		t.Fatalf("old active entry still exists: %v", err)
	}
	got, err := fs.Retrieve("duplicate")
	if err != nil || got.QueueType != Failed {
		t.Fatalf("fresh duplicate was removed: %#v, %v", got, err)
	}
}

func TestFileStorageBackendCleanupPropagatesListError(t *testing.T) {
	root := t.TempDir()
	fs := NewFileStorageBackend(root)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, string(Active), "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Cleanup(1); err == nil {
		t.Fatal("Cleanup silently ignored corrupt queue entry")
	}
}

func TestFileStorageBackendEnsureDirectoriesRejectsSymlinkRootAndParent(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		parent, outside := t.TempDir(), t.TempDir()
		root := filepath.Join(parent, "queue")
		if err := os.Symlink(outside, root); err != nil {
			t.Fatal(err)
		}
		if err := NewFileStorageBackend(root).EnsureDirectories(); err == nil {
			t.Fatal("accepted symlink root")
		}
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Fatalf("created children through root symlink: %v", entries)
		}
	})
	t.Run("parent", func(t *testing.T) {
		base, outside := t.TempDir(), t.TempDir()
		parent := filepath.Join(base, "parent")
		if err := os.Symlink(outside, parent); err != nil {
			t.Fatal(err)
		}
		if err := NewFileStorageBackend(filepath.Join(parent, "queue")).EnsureDirectories(); err == nil {
			t.Fatal("accepted symlink parent")
		}
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Fatalf("created children through parent symlink: %v", entries)
		}
	})
}

func TestFileStorageBackendConcurrentQueueSwapDoesNotEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	fs := NewFileStorageBackend(root)
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, string(Active))
	parked := filepath.Join(root, "active.parked")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if os.Rename(active, parked) != nil {
				continue
			}
			_ = os.Symlink(outside, active)
			_ = os.Remove(active)
			_ = os.Rename(parked, active)
		}
	}()
	for i := 0; i < 500; i++ {
		_ = fs.Store(Message{ID: fmt.Sprintf("swap-%d", i), QueueType: Active, CreatedAt: time.Now()})
	}
	<-done
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("descriptor-relative operations escaped queue root: %v", entries)
	}
}

func TestGenerateUniqueIDNoCollisions(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := generateUniqueID()
		if _, dup := seen[id]; dup {
			t.Fatalf("generateUniqueID produced a duplicate: %q", id)
		}
		seen[id] = struct{}{}
	}
}
