package queue

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// The per-tick cost of finding work on a deep SQLite queue: List reads and
// decodes every row, ClaimMessages reads only the batch it takes.
func seedSQLiteBench(b *testing.B, n int) *SQLiteStorageBackend {
	b.Helper()
	s, err := NewSQLiteStorageBackend(filepath.Join(b.TempDir(), "queue.db"), 5000, "WAL", "NORMAL")
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.Cleanup(func() { _ = s.db.Close() })
	base := time.Now().Add(-time.Hour)
	for i := 0; i < n; i++ {
		msg := Message{
			ID:        fmt.Sprintf("178659%010d-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", i),
			QueueType: Active,
			From:      "sender@example.com",
			To:        []string{fmt.Sprintf("user%05d@example.net", i)},
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
		}
		if err := s.Store(msg); err != nil {
			b.Fatalf("seed %d: %v", i, err)
		}
	}
	return s
}

func BenchmarkSQLiteFindWork_List20k(b *testing.B) {
	s := seedSQLiteBench(b, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.List(Active); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteFindWork_Claim20Of20k(b *testing.B) {
	s := seedSQLiteBench(b, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := s.ClaimMessages(Active, 20, "bench", time.Now().Add(time.Minute))
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		for _, m := range got {
			_ = s.ReleaseMessageClaim(m.ID, "bench")
		}
		b.StartTimer()
	}
}
