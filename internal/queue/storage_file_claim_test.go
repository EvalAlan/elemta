package queue

import (
	"fmt"
	"testing"
	"time"
)

// The file backend must satisfy the claiming interface, or Processor
// .processQueue silently falls back to listing — and decoding — the entire
// queue on every tick.
var _ ClaimingStorageBackend = (*FileStorageBackend)(nil)

func newClaimBackend(t *testing.T, messages int) *FileStorageBackend {
	t.Helper()
	fs := NewFileStorageBackend(t.TempDir())
	for i := 0; i < messages; i++ {
		msg := Message{
			ID:        fmt.Sprintf("178659%010d-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", i),
			QueueType: Active,
			From:      "a@example.com",
			To:        []string{"b@example.com"},
			CreatedAt: time.Now(),
		}
		if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
			t.Fatalf("seeding message %d: %v", i, err)
		}
	}
	t.Cleanup(func() { forgetExpiredFileClaims(time.Now().Add(time.Hour)) })
	return fs
}

func TestClaimIsBoundedByLimit(t *testing.T) {
	fs := newClaimBackend(t, 50)

	got, err := fs.ClaimMessages(Active, 5, "worker-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("claimed %d messages from a queue of 50, want 5 — an unbounded "+
			"claim is the whole problem this replaces", len(got))
	}
}

func TestTwoWorkersDoNotClaimTheSameMessage(t *testing.T) {
	fs := newClaimBackend(t, 20)
	lease := time.Now().Add(time.Minute)

	first, err := fs.ClaimMessages(Active, 5, "worker-1", lease)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	second, err := fs.ClaimMessages(Active, 5, "worker-2", lease)
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
		t.Errorf("second worker claimed %d, want 5 — it should get the next batch, not nothing", len(second))
	}
}

func TestReleasedMessageCanBeClaimedAgain(t *testing.T) {
	fs := newClaimBackend(t, 3)
	lease := time.Now().Add(time.Minute)

	first, err := fs.ClaimMessages(Active, 3, "worker-1", lease)
	if err != nil || len(first) != 3 {
		t.Fatalf("first claim: %v (got %d)", err, len(first))
	}
	if again, _ := fs.ClaimMessages(Active, 3, "worker-2", lease); len(again) != 0 {
		t.Fatalf("claimed %d already-leased messages, want 0", len(again))
	}

	for _, m := range first {
		if err := fs.ReleaseMessageClaim(m.ID, "worker-1"); err != nil {
			t.Fatalf("release: %v", err)
		}
	}

	again, err := fs.ClaimMessages(Active, 3, "worker-2", lease)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 3 {
		t.Errorf("after release, claimed %d, want 3 — released work must be "+
			"picked up again or a crashed delivery strands the message", len(again))
	}
}

// A worker that dies mid-delivery never releases. The lease deadline is what
// stops that message being stuck until the process restarts.
func TestAnExpiredLeaseIsClaimable(t *testing.T) {
	fs := newClaimBackend(t, 2)

	if got, err := fs.ClaimMessages(Active, 2, "dead-worker", time.Now().Add(-time.Second)); err != nil || len(got) != 2 {
		t.Fatalf("claim with an already-expired lease: %v (got %d)", err, len(got))
	}
	got, err := fs.ClaimMessages(Active, 2, "live-worker", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("claimed %d after the lease expired, want 2", len(got))
	}
}

func TestExpiredClaimsAreForgotten(t *testing.T) {
	fs := newClaimBackend(t, 4)
	if _, err := fs.ClaimMessages(Active, 4, "worker-1", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if removed := forgetExpiredFileClaims(time.Now()); removed == 0 {
		t.Error("no expired claims were swept; the lease map grows for every " +
			"delivery that never releases")
	}
}
