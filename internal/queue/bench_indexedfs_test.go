package queue

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func newBenchIndexedFSManager(b *testing.B) (*Manager, string) {
	b.Helper()
	root := b.TempDir()
	queueDir := filepath.Join(root, "queue")
	idx := filepath.Join(root, "index")

	m, err := NewManagerFromBackend(
		queueDir,
		"indexedfs",
		SQLiteConfig{},
		PostgresConfig{},
		IndexedFSConfig{IndexPath: idx},
		24,
	)
	if err != nil {
		b.Fatalf("failed to create indexedfs queue manager: %v", err)
	}
	b.Cleanup(func() { m.Stop() })
	return m, queueDir
}

func BenchmarkIndexedFSEnqueue_16KB(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(16 * 1024)
	receivedAt := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.EnqueueMessage(
			"sender@example.com",
			[]string{"rcpt@example.net"},
			"enqueue-bench",
			payload,
			PriorityNormal,
			receivedAt,
		)
		if err != nil {
			b.Fatalf("enqueue failed: %v", err)
		}
	}
}

func benchmarkIndexedFSListActiveAtDepth(b *testing.B, depth int) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(2 * 1024)
	enqueueNMessages(b, m, depth, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msgs, err := m.ListMessages(Active)
		if err != nil {
			b.Fatalf("list active failed: %v", err)
		}
		if len(msgs) != depth {
			b.Fatalf("expected %d messages, got %d", depth, len(msgs))
		}
	}
}

func BenchmarkIndexedFSListActive_1K(b *testing.B)  { benchmarkIndexedFSListActiveAtDepth(b, 1000) }
func BenchmarkIndexedFSListActive_10K(b *testing.B) { benchmarkIndexedFSListActiveAtDepth(b, 10000) }

func BenchmarkIndexedFSMaintenanceAtDepth(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(2 * 1024)
	const depth = 5000

	// Seed messages and delete half their backing files to create orphans
	ids := enqueueNMessages(b, m, depth, payload)
	for i := 0; i < depth; i += 2 {
		// Best-effort file deletion — we just want orphans for maintenance to find
		_ = m.storageBackend.Delete(ids[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Re-seed orphans each iteration since maintenance prunes them
		for j := 0; j < depth; j += 2 {
			_, _ = m.EnqueueMessage(
				"sender@example.com",
				[]string{"rcpt@example.net"},
				"reseed",
				payload,
				PriorityNormal,
				time.Now(),
			)
		}
		if _, err := m.storageBackend.(*IndexedFSStorageBackend).Maintenance(); err != nil {
			b.Fatalf("maintenance failed: %v", err)
		}
	}
}

func BenchmarkIndexedFSCount_10K(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(2 * 1024)
	enqueueNMessages(b, m, 10000, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats := m.GetStats()
		if stats.ActiveCount != 10000 {
			b.Fatalf("expected 10000, got %d", stats.ActiveCount)
		}
	}
}

func BenchmarkIndexedFSMoveActiveToDeferred(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(2 * 1024)
	ids := enqueueNMessages(b, m, b.N, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.MoveMessage(ids[i], Deferred, "benchmark defer"); err != nil {
			b.Fatalf("move failed: %v", err)
		}
	}
}

func BenchmarkIndexedFSRetrieveByID(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(2 * 1024)
	const depth = 5000
	ids := enqueueNMessages(b, m, depth, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := ids[i%depth]
		msg, err := m.GetMessage(id)
		if err != nil {
			b.Fatalf("retrieve failed: %v", err)
		}
		if msg.ID != id {
			b.Fatalf("expected id %s, got %s", id, msg.ID)
		}
	}
}

// BenchmarkIndexedFSStoreAndStoreContent benchmarks the dual-write pattern
// (metadata + content) that indexedfs inherits from file backend.
func BenchmarkIndexedFSStoreAndStoreContent(b *testing.B) {
	m, _ := newBenchIndexedFSManager(b)
	payload := benchmarkPayload(8 * 1024)
	receivedAt := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("store-content-%d", i)
		msg := Message{
			ID:        id,
			QueueType: Active,
			From:      "sender@example.com",
			To:        []string{"rcpt@example.net"},
			Subject:   "store-content-bench",
			Size:      int64(len(payload)),
			Priority:  PriorityNormal,
			ReceivedAt:  receivedAt,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := m.storageBackend.Store(msg); err != nil {
			b.Fatalf("store failed: %v", err)
		}
		if err := m.storageBackend.StoreContent(id, payload); err != nil {
			b.Fatalf("store content failed: %v", err)
		}
	}
}
