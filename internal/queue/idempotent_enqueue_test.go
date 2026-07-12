package queue

import (
	"sync"
	"testing"
	"time"
)

func TestEnqueueMessageWithIDConcurrentManagers(t *testing.T) {
	tests := []struct {
		name string
		open func(t *testing.T) (StorageBackend, StorageBackend)
	}{
		{"file", func(t *testing.T) (StorageBackend, StorageBackend) {
			d := t.TempDir()
			return NewFileStorageBackend(d), NewFileStorageBackend(d)
		}},
		{"sqlite", func(t *testing.T) (StorageBackend, StorageBackend) {
			path := t.TempDir() + "/queue.db"
			a, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
			if err != nil {
				t.Fatal(err)
			}
			b, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.db.Close(); b.db.Close() })
			return a, b
		}},
		{"indexedfs", func(t *testing.T) (StorageBackend, StorageBackend) {
			d := t.TempDir()
			a, err := NewIndexedFSStorageBackend(d, IndexedFSConfig{RecoveryOnStartup: true})
			if err != nil {
				t.Fatal(err)
			}
			b, err := NewIndexedFSStorageBackend(d, IndexedFSConfig{RecoveryOnStartup: true})
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := tt.open(t)
			ma, mb := NewManagerWithStorage(a, 0), NewManagerWithStorage(b, 0)
			defer ma.Stop()
			defer mb.Stop()
			at := time.Unix(123, 0).UTC()
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for _, m := range []*Manager{ma, mb} {
				wg.Add(1)
				go func(m *Manager) {
					defer wg.Done()
					_, err := m.EnqueueMessageWithID("stable", "a@test", []string{"b@test"}, "s", []byte("body"), PriorityHigh, at)
					errs <- err
				}(m)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ma.EnqueueMessageWithID("stable", "a@test", []string{"b@test"}, "s", []byte("different"), PriorityHigh, at); err == nil {
				t.Fatal("conflicting content succeeded")
			}
		})
	}
}

func TestFileAtomicEnqueueRepairsInterruptedPairs(t *testing.T) {
	fs := NewFileStorageBackend(t.TempDir())
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	msg := Message{ID: "repair", QueueType: Active, From: "a", To: []string{"b"}, Size: 4, Priority: PriorityHigh, ReceivedAt: time.Unix(1, 0)}
	if err := fs.Store(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	got, err := fs.RetrieveContent(msg.ID)
	if err != nil || string(got) != "body" {
		t.Fatalf("content=%q err=%v", got, err)
	}
	if err := fs.Delete(msg.ID); err != nil {
		t.Fatal(err)
	}
	if err := fs.StoreContent(msg.ID, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err == nil {
		t.Fatal("conflicting orphan content succeeded")
	}
}

func TestSQLiteConsumedDeterministicIDPersists(t *testing.T) {
	path := t.TempDir() + "/queue.db"
	open := func() *SQLiteStorageBackend {
		b, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := open()
	m := NewManagerWithStorage(b, 0)
	at := time.Unix(123, 0).UTC()
	if _, err := m.EnqueueMessageWithID("consumed", "a@test", []string{"b@test"}, "s", []byte("body"), PriorityHigh, at); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteMessage("consumed"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnqueueMessageWithID("consumed", "a@test", []string{"b@test"}, "s", []byte("body"), PriorityHigh, at); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Retrieve("consumed"); err == nil {
		t.Fatal("consumed message was recreated")
	}
	if _, err := m.EnqueueMessageWithID("consumed", "a@test", []string{"b@test"}, "s", []byte("different"), PriorityHigh, at); err == nil {
		t.Fatal("conflicting consumed identity succeeded")
	}
	m.Stop()
	if err := b.db.Close(); err != nil {
		t.Fatal(err)
	}
	b = open()
	defer b.db.Close()
	m = NewManagerWithStorage(b, 0)
	defer m.Stop()
	if _, err := m.EnqueueMessageWithID("consumed", "a@test", []string{"b@test"}, "s", []byte("body"), PriorityHigh, at); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Retrieve("consumed"); err == nil {
		t.Fatal("restart recreated consumed message")
	}
}
