package queue

import (
	"path/filepath"
	"testing"
)

// The option has to reach the backend on every path the factory can return
// through. A setting that parses and changes nothing is a failure mode this
// queue has hit more than once, and the indexedfs branch did exactly that
// until this test covered it.
func TestWithTombstoneBodyReachesEveryBackend(t *testing.T) {
	for _, backend := range []string{"file", "sqlite", "indexedfs"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			m, err := NewManagerFromBackend(dir, backend,
				SQLiteConfig{Path: filepath.Join(dir, "q.db")},
				PostgresConfig{}, IndexedFSConfig{}, 24,
				WithTombstoneBody(false))
			if err != nil {
				t.Fatalf("building %s manager: %v", backend, err)
			}

			var got bool
			switch b := m.storageBackend.(type) {
			case *FileStorageBackend:
				got = b.tombstoneBody.drop.Load()
			case *SQLiteStorageBackend:
				got = b.tombstoneBody.drop.Load()
			case *IndexedFSStorageBackend:
				// Embeds the file backend and writes tombstones through it.
				got = b.FileStorageBackend.tombstoneBody.drop.Load()
			default:
				t.Fatalf("unhandled backend type %T; add it here or the setting "+
					"can be silently ignored on that path", b)
			}
			if !got {
				t.Errorf("%s ignored WithTombstoneBody(false)", backend)
			}
		})
	}
}

// And the default is the safe one, whatever the caller forgets to pass.
func TestTombstoneBodyIsKeptWhenUnset(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManagerFromBackend(dir, "file", SQLiteConfig{}, PostgresConfig{},
		IndexedFSConfig{}, 24)
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}
	if m.storageBackend.(*FileStorageBackend).tombstoneBody.drop.Load() {
		t.Error("a manager built without the option drops the body; the default " +
			"must be the side that cannot refuse mail after a rollback")
	}
}

// The setting has to reach a manager that is already running, because that is
// how a config reload delivers it. Before this, saving in the web UI changed
// the file, reported success, and did nothing until someone restarted.
func TestSetTombstoneBodyAppliesToARunningManager(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManagerFromBackend(dir, "file", SQLiteConfig{}, PostgresConfig{},
		IndexedFSConfig{}, 24)
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}
	backend := m.storageBackend.(*FileStorageBackend)

	if backend.tombstoneBody.drop.Load() {
		t.Fatal("a fresh manager should keep the body")
	}
	m.SetTombstoneBody(false)
	if !backend.tombstoneBody.drop.Load() {
		t.Error("SetTombstoneBody(false) did not reach the running backend")
	}
	m.SetTombstoneBody(true)
	if backend.tombstoneBody.drop.Load() {
		t.Error("SetTombstoneBody(true) did not restore the body")
	}
}
