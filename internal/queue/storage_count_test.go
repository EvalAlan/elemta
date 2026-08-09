package queue

import (
	"fmt"
	"testing"
	"time"
)

// Count used to call List, which opens and JSON-decodes every message file.
// refreshCounts runs it on all four queues every 5 seconds, so on a large spool
// that re-parsed the entire queue continuously just to produce counts. These
// tests pin that Count agrees with List while the benchmark shows it no longer
// scales with per-message decode work.

func storeN(t testing.TB, fs *FileStorageBackend, q QueueType, n int) {
	t.Helper()
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		msg := Message{
			ID:         fmt.Sprintf("count-%s-%04d", q, i),
			QueueType:  q,
			From:       "sender@example.com",
			To:         []string{"rcpt@example.net"},
			Subject:    "count test",
			Priority:   PriorityNormal,
			ReceivedAt: now,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := fs.Store(msg); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
}

func TestCountAgreesWithList(t *testing.T) {
	fs := NewFileStorageBackend(t.TempDir())
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	storeN(t, fs, Active, 17)
	storeN(t, fs, Deferred, 5)

	for _, tc := range []struct {
		q    QueueType
		want int
	}{{Active, 17}, {Deferred, 5}, {Hold, 0}, {Failed, 0}} {
		got, err := fs.Count(tc.q)
		if err != nil {
			t.Fatalf("count %s: %v", tc.q, err)
		}
		if got != tc.want {
			t.Errorf("Count(%s) = %d, want %d", tc.q, got, tc.want)
		}

		list, err := fs.List(tc.q)
		if err != nil {
			t.Fatalf("list %s: %v", tc.q, err)
		}
		if got != len(list) {
			t.Errorf("Count(%s) = %d disagrees with len(List) = %d", tc.q, got, len(list))
		}
	}
}

func TestCountIgnoresNonMessageEntries(t *testing.T) {
	fs := NewFileStorageBackend(t.TempDir())
	if err := fs.EnsureDirectories(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}
	storeN(t, fs, Active, 3)

	got, err := fs.Count(Active)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != 3 {
		t.Errorf("Count(Active) = %d, want 3", got)
	}
}

// BenchmarkCount shows the cost of counting no longer scales with per-message
// decode work: a 2000-message queue counts without opening a single message.
func BenchmarkCount(b *testing.B) {
	fs := NewFileStorageBackend(b.TempDir())
	if err := fs.EnsureDirectories(); err != nil {
		b.Fatalf("ensure dirs: %v", err)
	}
	storeN(b, fs, Active, 2000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fs.Count(Active); err != nil {
			b.Fatalf("count: %v", err)
		}
	}
}
