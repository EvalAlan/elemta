package queue

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The property this file exists for: a message going to both a local mailbox
// and an outside address, where the outside leg defers, must not deliver to the
// local mailbox again when the message is retried.
//
// Split routing and recipient reduction were each tested on their own — the
// router reports accurate per-recipient outcomes, and the processor drops
// delivered recipients before deferring. Neither test says the two work
// together, and the failure mode is the one a person actually notices: the same
// message arriving in their mailbox on every retry, once a minute, until the
// far end recovers.

// flakyRemote defers the first time and succeeds afterwards, so a retry can be
// observed rather than simulated.
type flakyRemote struct {
	attempts int
}

func (h *flakyRemote) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

func (h *flakyRemote) DeliverMessageWithMetadata(_ context.Context, msg Message, _ []byte) (*DeliveryResult, error) {
	h.attempts++
	if h.attempts == 1 {
		err := errors.New("451 4.7.1 please try again later")
		return &DeliveryResult{
			Error:             err,
			RecipientOutcomes: outcomesFor(msg.To, RecipientTemporaryFailure, err.Error(), "remote"),
		}, err
	}
	return &DeliveryResult{
		Success:           true,
		RecipientOutcomes: outcomesFor(msg.To, RecipientDelivered, "", "remote"),
	}, nil
}

func (h *flakyRemote) GetFailedQueueRetentionHours() int { return 24 }

func TestARemoteDeferralDoesNotRedeliverToTheLocalMailbox(t *testing.T) {
	manager := NewManager(t.TempDir(), 0)
	defer manager.Stop()

	local := &recordingHandler{name: "dovecot"}
	remote := &flakyRemote{}
	split := NewSplitDeliveryHandler(local, remote, []string{"example.com"}, nil)

	id, err := manager.EnqueueMessage("sender@example.com",
		[]string{"inside@example.com", "outside@other.example"},
		"subject", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := manager.GetMessage(id)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProcessor(manager, DefaultProcessorConfig(), split)
	p.SetMetricsRecorder(&metricCapture{})

	// First attempt: local succeeds, remote defers.
	runMessage(t, p, msg)

	if len(local.delivered) != 1 {
		t.Fatalf("local delivery happened %d times on the first attempt", len(local.delivered))
	}

	stored, err := manager.GetMessage(id)
	if err != nil {
		t.Fatalf("the message should still be queued for the deferred recipient: %v", err)
	}
	// The envelope must now name only the recipient that still needs delivering.
	if strings.Join(stored.To, ",") != "outside@other.example" {
		t.Fatalf("envelope after deferral = %v; the delivered local recipient is still on it and will be mailed again",
			stored.To)
	}

	// Second attempt, as the queue would make it.
	runMessage(t, p, stored)

	if len(local.delivered) != 1 {
		t.Errorf("the local mailbox was delivered to %d times across two attempts; the recipient receives a duplicate on every retry",
			len(local.delivered))
	}
	if remote.attempts != 2 {
		t.Errorf("the remote leg was attempted %d times, want 2", remote.attempts)
	}
}

// TestAPermanentRemoteFailureAlsoSparesTheLocalMailbox. A bounce takes a
// different path through the processor than a deferral, and it reduces the
// envelope differently, so it needs its own check.
func TestAPermanentRemoteFailureAlsoSparesTheLocalMailbox(t *testing.T) {
	manager := NewManager(t.TempDir(), 0)
	defer manager.Stop()

	local := &recordingHandler{name: "dovecot"}
	remote := &recordingHandler{
		name:   "smtp",
		err:    errors.New("550 5.1.1 no such user"),
		status: RecipientPermanentFailure,
	}
	split := NewSplitDeliveryHandler(local, remote, []string{"example.com"}, nil)

	id, err := manager.EnqueueMessage("sender@example.com",
		[]string{"inside@example.com", "nobody@other.example"},
		"subject", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := manager.GetMessage(id)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProcessor(manager, DefaultProcessorConfig(), split)
	p.SetMetricsRecorder(&metricCapture{})
	runMessage(t, p, msg)

	if len(local.delivered) != 1 {
		t.Errorf("local delivery happened %d times, want once", len(local.delivered))
	}
	// Nothing is retryable, so the message must not be left queued for another
	// pass that would deliver locally a second time.
	if stored, err := manager.GetMessage(id); err == nil {
		if strings.Contains(strings.Join(stored.To, ","), "inside@example.com") {
			t.Errorf("the delivered local recipient is still queued: %v", stored.To)
		}
	}
}
