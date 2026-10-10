package queue

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// The SQLite backend must satisfy the claiming interface, or
// Processor.processQueue silently falls back to listing and decoding the
// entire queue on every tick.
var _ ClaimingStorageBackend = (*SQLiteStorageBackend)(nil)
var _ claimInfoProvider = (*SQLiteStorageBackend)(nil)

func newSQLiteClaimBackend(t *testing.T, messages int) *SQLiteStorageBackend {
	t.Helper()
	s, err := NewSQLiteStorageBackend(filepath.Join(t.TempDir(), "queue.db"), 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatalf("open sqlite backend: %v", err)
	}
	t.Cleanup(func() { _ = s.db.Close() })
	base := time.Now().Add(-time.Hour)
	for i := 0; i < messages; i++ {
		msg := Message{
			ID:        fmt.Sprintf("178659%010d-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", i),
			QueueType: Active,
			From:      "a@example.com",
			To:        []string{"b@example.com"},
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}
		if _, err := s.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
			t.Fatalf("seeding message %d: %v", i, err)
		}
	}
	return s
}

func TestSQLiteClaimIsBoundedByLimit(t *testing.T) {
	s := newSQLiteClaimBackend(t, 50)

	got, err := s.ClaimMessages(Active, 5, "worker-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("claimed %d messages from a queue of 50, want 5", len(got))
	}
	for _, m := range got {
		if m.ID == "" || m.QueueType != Active || m.From != "a@example.com" {
			t.Errorf("claimed message not decoded: %+v", m)
		}
	}
}

func TestSQLiteClaimTakesOldestFirst(t *testing.T) {
	s := newSQLiteClaimBackend(t, 10)

	got, err := s.ClaimMessages(Active, 3, "worker-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	want := map[string]bool{}
	for i := 0; i < 3; i++ {
		want[fmt.Sprintf("178659%010d-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", i)] = true
	}
	for _, m := range got {
		if !want[m.ID] {
			t.Errorf("claimed %s, which is not among the three oldest", m.ID)
		}
	}
}

func TestSQLiteTwoWorkersDoNotClaimTheSameMessage(t *testing.T) {
	s := newSQLiteClaimBackend(t, 20)
	lease := time.Now().Add(time.Minute)

	first, err := s.ClaimMessages(Active, 5, "worker-1", lease)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	second, err := s.ClaimMessages(Active, 5, "worker-2", lease)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	seen := map[string]bool{}
	for _, m := range first {
		seen[m.ID] = true
	}
	for _, m := range second {
		if seen[m.ID] {
			t.Fatalf("message %s was handed to both workers; it would be delivered twice", m.ID)
		}
	}
	if len(second) != 5 {
		t.Errorf("second worker claimed %d, want 5", len(second))
	}
}

func TestSQLiteReleasedMessageCanBeClaimedAgain(t *testing.T) {
	s := newSQLiteClaimBackend(t, 3)
	lease := time.Now().Add(time.Minute)

	first, err := s.ClaimMessages(Active, 3, "worker-1", lease)
	if err != nil || len(first) != 3 {
		t.Fatalf("first claim: %v (got %d)", err, len(first))
	}
	if again, _ := s.ClaimMessages(Active, 3, "worker-2", lease); len(again) != 0 {
		t.Fatalf("claimed %d already-leased messages, want 0", len(again))
	}
	// Another worker's release must not free a lease it does not hold.
	if err := s.ReleaseMessageClaim(first[0].ID, "worker-2"); err != nil {
		t.Fatalf("foreign release: %v", err)
	}
	if again, _ := s.ClaimMessages(Active, 3, "worker-2", lease); len(again) != 0 {
		t.Fatalf("a release by a non-holder freed %d messages, want 0", len(again))
	}
	for _, m := range first {
		if err := s.ReleaseMessageClaim(m.ID, "worker-1"); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	again, err := s.ClaimMessages(Active, 3, "worker-2", lease)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 3 {
		t.Errorf("after release, claimed %d, want 3", len(again))
	}
}

// A worker that dies mid-delivery never releases. The lease deadline is what
// stops that message being stuck.
func TestSQLiteAnExpiredLeaseIsClaimable(t *testing.T) {
	s := newSQLiteClaimBackend(t, 2)

	if got, err := s.ClaimMessages(Active, 2, "dead-worker", time.Now().Add(-time.Second)); err != nil || len(got) != 2 {
		t.Fatalf("claim with an already-expired lease: %v (got %d)", err, len(got))
	}
	got, err := s.ClaimMessages(Active, 2, "live-worker", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("claimed %d after the lease expired, want 2", len(got))
	}

	claims, err := s.ListClaims(time.Now())
	if err != nil {
		t.Fatalf("list claims: %v", err)
	}
	if len(claims) != 2 || claims[0].ClaimedBy != "live-worker" || claims[0].Expired {
		t.Errorf("ListClaims = %+v, want two live claims by live-worker", claims)
	}
}

// Moving a message to another queue ends the delivery attempt that held it.
func TestSQLiteMoveClearsClaim(t *testing.T) {
	s := newSQLiteClaimBackend(t, 1)
	got, err := s.ClaimMessages(Active, 1, "worker-1", time.Now().Add(time.Minute))
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v (got %d)", err, len(got))
	}
	if err := s.Move(got[0].ID, Active, Deferred); err != nil {
		t.Fatalf("move: %v", err)
	}
	if err := s.Move(got[0].ID, Deferred, Active); err != nil {
		t.Fatalf("move back: %v", err)
	}
	again, err := s.ClaimMessages(Active, 1, "worker-2", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 1 {
		t.Errorf("claimed %d after the message was requeued, want 1", len(again))
	}
}

// A queue database created before claiming existed must gain the columns on
// open, or every claim fails and the processor cannot deliver anything.
func TestSQLiteClaimColumnsAreAddedToAnExistingQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE queue_messages (
		id TEXT PRIMARY KEY, queue_type TEXT NOT NULL, metadata TEXT NOT NULL,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.Exec(`INSERT INTO queue_messages VALUES (?, 'active', '{"from":"a@example.com"}', ?, ?)`,
		"1786590000000000-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", now, now); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	_ = raw.Close()

	s, err := NewSQLiteStorageBackend(path, 5000, "WAL", "NORMAL")
	if err != nil {
		t.Fatalf("open existing queue: %v", err)
	}
	defer func() { _ = s.db.Close() }()
	got, err := s.ClaimMessages(Active, 10, "worker-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("claim on migrated queue: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("claimed %d from a migrated queue of 1, want 1", len(got))
	}
}

// Re-storing a message's metadata must not free a claim a worker still holds.
func TestSQLiteStoreKeepsClaim(t *testing.T) {
	s := newSQLiteClaimBackend(t, 1)
	got, err := s.ClaimMessages(Active, 1, "worker-1", time.Now().Add(time.Minute))
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v (got %d)", err, len(got))
	}
	if err := s.Store(got[0]); err != nil {
		t.Fatalf("store: %v", err)
	}
	if again, _ := s.ClaimMessages(Active, 1, "worker-2", time.Now().Add(time.Minute)); len(again) != 0 {
		t.Errorf("Store released a held claim; a second worker claimed the message")
	}
}
