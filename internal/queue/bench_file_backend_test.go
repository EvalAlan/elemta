package queue

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func benchmarkPayload(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte('a' + (i % 26))
	}
	return buf
}

func enqueueNMessages(b *testing.B, m *Manager, n int, payload []byte) []string {
	b.Helper()
	ids := make([]string, 0, n)
	receivedAt := time.Now()
	for i := 0; i < n; i++ {
		id, err := m.EnqueueMessage(
			"sender@example.com",
			[]string{fmt.Sprintf("user%05d@example.net", i)},
			"benchmark",
			payload,
			PriorityNormal,
			receivedAt,
		)
		if err != nil {
			b.Fatalf("enqueue seed message %d failed: %v", i, err)
		}
		ids = append(ids, id)
	}
	return ids
}

func newBenchFileManager(b *testing.B) (*Manager, string) {
	b.Helper()
	root := b.TempDir()
	queueDir := filepath.Join(root, "queue")
	m := NewManager(queueDir, 24)
	b.Cleanup(func() { m.Stop() })
	return m, queueDir
}

func BenchmarkFileBackendEnqueue_16KB(b *testing.B) {
	m, _ := newBenchFileManager(b)
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

func benchmarkFileBackendListActiveAtDepth(b *testing.B, depth int) {
	m, _ := newBenchFileManager(b)
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

func BenchmarkFileBackendListActive_1K(b *testing.B) { benchmarkFileBackendListActiveAtDepth(b, 1000) }
func BenchmarkFileBackendListActive_10K(b *testing.B) {
	benchmarkFileBackendListActiveAtDepth(b, 10000)
}
func BenchmarkFileBackendListActive_50K(b *testing.B) {
	benchmarkFileBackendListActiveAtDepth(b, 50000)
}

func BenchmarkFileBackendMoveActiveToDeferred(b *testing.B) {
	m, _ := newBenchFileManager(b)
	payload := benchmarkPayload(2 * 1024)
	ids := enqueueNMessages(b, m, b.N, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.MoveMessage(ids[i], Deferred, "benchmark defer"); err != nil {
			b.Fatalf("move failed: %v", err)
		}
	}
}

func BenchmarkFileBackendRetrieveByID(b *testing.B) {
	m, _ := newBenchFileManager(b)
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
