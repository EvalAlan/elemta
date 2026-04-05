package queue

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newSQLiteManagerForTest(t *testing.T) *Manager {
	t.Helper()

	queueDir := t.TempDir()
	manager, err := NewManagerFromBackend(
		queueDir,
		"sqlite",
		SQLiteConfig{
			Path:          filepath.Join(queueDir, "queue.db"),
			BusyTimeoutMS: 2000,
			JournalMode:   "WAL",
			Synchronous:   "NORMAL",
		},
		24,
	)
	if err != nil {
		t.Fatalf("failed to create sqlite queue manager: %v", err)
	}
	t.Cleanup(manager.Stop)
	return manager
}

func TestQueueSQLiteGuardrails_EnqueueAndStorageStats(t *testing.T) {
	m := newSQLiteManagerForTest(t)

	_, err := m.EnqueueMessage(
		"sender@example.com",
		[]string{"recipient@example.com"},
		"sqlite guardrail",
		[]byte("hello sqlite backend"),
		PriorityNormal,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}

	if err := m.UpdateStats(); err != nil {
		t.Fatalf("update stats failed: %v", err)
	}

	stats := m.GetStats()
	if stats.ActiveCount != 1 {
		t.Fatalf("expected active_count=1, got %d", stats.ActiveCount)
	}

	storage, err := m.GetStorageInfo()
	if err != nil {
		t.Fatalf("GetStorageInfo failed: %v", err)
	}

	if storage.Backend != "sqlite" {
		t.Fatalf("expected backend sqlite, got %q", storage.Backend)
	}
	if storage.SQLitePath == "" {
		t.Fatalf("expected sqlite_path to be set")
	}
	if storage.MessageRows < 1 {
		t.Fatalf("expected at least 1 message row, got %d", storage.MessageRows)
	}
	if storage.ContentRows < 1 {
		t.Fatalf("expected at least 1 content row, got %d", storage.ContentRows)
	}
}

func TestQueueSQLiteGuardrails_ConcurrentEnqueueDoesNotBusyLock(t *testing.T) {
	m := newSQLiteManagerForTest(t)

	const workers = 20
	const perWorker = 4

	errCh := make(chan error, workers*perWorker)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				subject := fmt.Sprintf("sqlite-concurrency-%d-%d", workerID, j)
				_, err := m.EnqueueMessage(
					"sender@example.com",
					[]string{"recipient@example.com"},
					subject,
					[]byte("payload"),
					PriorityNormal,
					time.Now(),
				)
				if err != nil {
					errCh <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent enqueue failed: %v", err)
	}

	if err := m.UpdateStats(); err != nil {
		t.Fatalf("update stats failed: %v", err)
	}

	expected := workers * perWorker
	if got := m.GetStats().ActiveCount; got != expected {
		t.Fatalf("expected active_count=%d, got %d", expected, got)
	}
}
