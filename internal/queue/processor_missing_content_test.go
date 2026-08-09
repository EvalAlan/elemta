package queue

import (
	"testing"
	"time"
)

// The processor works from a snapshot of the queue, and walking a large queue
// takes a while. A message that was delivered and consumed between the snapshot
// and the moment the processor reaches it is simply gone — its metadata and its
// content both.
//
// That used to be reported as "Failed to read content: content not found" and
// sent through moveToFailed, which emits a DSN. So a message that had actually
// been delivered could bounce back to its sender saying delivery failed, and be
// counted as a failure. It showed up roughly once per 4,400 messages under load.
//
// A message still in the queue that has lost its content is a different thing
// and must still fail.

func missingContentProcessor(t *testing.T) (*Processor, *Manager) {
	t.Helper()
	manager := NewManager(t.TempDir(), 24)
	t.Cleanup(manager.Stop)

	processor := NewProcessor(manager, ProcessorConfig{
		Enabled:       true,
		Interval:      time.Hour, // never ticks on its own; the test drives it
		MaxConcurrent: 1,
		MaxRetries:    3,
		RetrySchedule: []int{1},
		CleanupAge:    time.Hour,
	}, NewMockDeliveryHandler(0))

	return processor, manager
}

// TestConsumedMessageDoesNotBounce is the regression test: a message that left
// the queue before the processor reached it must not be turned into a failure.
func TestConsumedMessageDoesNotBounce(t *testing.T) {
	processor, manager := missingContentProcessor(t)

	id, err := manager.EnqueueMessage("sender@example.com", []string{"rcpt@example.net"},
		"snapshot race", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	snapshot, err := manager.GetMessage(id)
	if err != nil {
		t.Fatalf("get message: %v", err)
	}

	// Simulate the race: the message is delivered and consumed after the
	// snapshot the processor is holding was taken.
	if err := manager.DeleteMessage(id); err != nil {
		t.Fatalf("delete message: %v", err)
	}

	failedBefore := processor.failedCount
	processor.wg.Add(1)
	processor.workerSem <- struct{}{}
	processor.processMessage(snapshot)

	if processor.failedCount != failedBefore {
		t.Errorf("a message consumed before delivery was counted as a failure (%d -> %d)",
			failedBefore, processor.failedCount)
	}

	stats := manager.GetStats()
	if stats.FailedCount != 0 {
		t.Errorf("a message consumed before delivery was moved to the failed queue (failed=%d)",
			stats.FailedCount)
	}
	if _, err := manager.GetMessage(id); err == nil {
		t.Error("the consumed message was resurrected into the queue")
	}
}

// TestQueuedMessageWithMissingContentStillFails pins the other half: this
// change must not swallow a genuine orphan, where the message is still queued
// but its content has gone.
func TestQueuedMessageWithMissingContentStillFails(t *testing.T) {
	processor, manager := missingContentProcessor(t)

	id, err := manager.EnqueueMessage("sender@example.com", []string{"rcpt@example.net"},
		"orphan", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	msg, err := manager.GetMessage(id)
	if err != nil {
		t.Fatalf("get message: %v", err)
	}

	// Metadata stays, content goes: a real inconsistency.
	if err := manager.storageBackend.DeleteContent(id); err != nil {
		t.Fatalf("delete content: %v", err)
	}

	failedBefore := processor.failedCount
	processor.wg.Add(1)
	processor.workerSem <- struct{}{}
	processor.processMessage(msg)

	if processor.failedCount == failedBefore {
		t.Error("a queued message with no content should still be failed, not skipped")
	}
}
