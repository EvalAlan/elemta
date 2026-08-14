package queue

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Listing a queue while it is being delivered must not fail.
//
// List reads the directory and then opens each entry. A message delivered and
// removed in between is gone by the time the open happens, and treating that
// as an error threw away every other message in the result. On a busy queue it
// is not a rare race: with 26,000 messages queued and deliveries running, the
// web UI showed "Failed to load queue data" and the stats refresher logged
// "failed to list messages ... no such file or directory".
func TestListToleratesMessagesDeliveredMidScan(t *testing.T) {
	backend := NewFileStorageBackend(t.TempDir())

	const count = 400
	ids := make([]string, 0, count)
	for i := 0; i < count; i++ {
		msg := Message{
			ID:        fmt.Sprintf("178666%010d-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", i),
			QueueType: Active,
			From:      "a@example.com",
			To:        []string{"b@example.com"},
			CreatedAt: time.Now(),
		}
		if _, err := backend.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
			t.Fatalf("seeding %d: %v", i, err)
		}
		ids = append(ids, msg.ID)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Deliveries, consuming the queue from under the listing.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for _, id := range ids {
			_ = backend.Delete(id)
		}
	}()

	// Listings, which must all succeed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := backend.List(Active); err != nil {
				t.Errorf("listing a queue that is being delivered failed: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}
