package queue

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Deleting different messages must run in parallel.
//
// DeleteMessage held the manager's single write lock across three file
// operations — read the metadata, read the whole body, write a tombstone and
// unlink. Every completed delivery in the server queued behind it. On a
// 52,000-message queue with 20 workers configured, only 0.9 were ever busy and
// the queue drained at 11 a second with every container under 7% CPU.
func TestConcurrentDeletesOfDifferentMessages(t *testing.T) {
	manager := NewManager(t.TempDir(), 24)

	const count = 200
	ids := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id, err := manager.EnqueueMessage("a@example.com", []string{"b@example.com"},
			"subject", []byte("body"), PriorityNormal, time.Now())
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	var wg sync.WaitGroup
	errs := make(chan error, count)
	began := time.Now()
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := manager.DeleteMessage(id); err != nil {
				errs <- fmt.Errorf("delete %s: %w", id, err)
			}
		}(id)
	}
	wg.Wait()
	close(errs)
	elapsed := time.Since(began)

	for err := range errs {
		t.Error(err)
	}

	remaining, err := manager.ListMessages(Active)
	if err != nil {
		t.Fatalf("listing after the deletes: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d messages survived %d concurrent deletes", len(remaining), count)
	}
	t.Logf("%d concurrent deletes in %v", count, elapsed)
}

// The same message deleted from several goroutines must be consumed once, and
// the extra attempts must fail rather than double-count or double-tombstone.
func TestConcurrentDeletesOfTheSameMessage(t *testing.T) {
	manager := NewManager(t.TempDir(), 24)

	id, err := manager.EnqueueMessage("a@example.com", []string{"b@example.com"},
		"subject", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	const attempts = 12
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- manager.DeleteMessage(id)
		}()
	}
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Errorf("%d of %d concurrent deletes of the same message succeeded, want exactly 1", succeeded, attempts)
	}

	if _, err := manager.GetMessage(id); err == nil {
		t.Error("the message is still retrievable after being deleted")
	}
}
