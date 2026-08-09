package queue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueueObservabilitySnapshot(t *testing.T) {
	mgr := NewManager(t.TempDir(), 0)
	defer mgr.Stop()

	activeID, err := mgr.EnqueueMessage("sender@example.com", []string{"a@example.net"}, "active", []byte("active"), PriorityNormal, time.Now().Add(-10*time.Minute))
	require.NoError(t, err)
	deferredID, err := mgr.EnqueueMessage("sender@example.com", []string{"b@example.org"}, "deferred", []byte("deferred"), PriorityHigh, time.Now().Add(-20*time.Minute))
	require.NoError(t, err)
	require.NoError(t, mgr.MoveMessage(deferredID, Deferred, "temporary failure"))
	deferred, err := mgr.GetMessage(deferredID)
	require.NoError(t, err)
	deferred.NextRetry = time.Now().Add(-time.Minute)
	require.NoError(t, mgr.storageBackend.Update(deferred))

	// Make the active message old enough to be the obvious oldest item.
	active, err := mgr.GetMessage(activeID)
	require.NoError(t, err)
	active.CreatedAt = time.Now().Add(-2 * time.Hour)
	require.NoError(t, mgr.storageBackend.Update(active))

	snapshot, err := mgr.GetObservabilitySnapshot()
	require.NoError(t, err)

	assert.Equal(t, "file", snapshot.Backend)
	assert.False(t, snapshot.ClaimsSupported)
	assert.Equal(t, 2, snapshot.TotalMessages)
	assert.Equal(t, 1, snapshot.ByQueue[string(Active)].Count)
	assert.Equal(t, 1, snapshot.ByQueue[string(Deferred)].Count)
	assert.Equal(t, 1, snapshot.ByQueue[string(Deferred)].ReadyDeferred)
	require.NotNil(t, snapshot.OldestMessage)
	assert.Equal(t, activeID, snapshot.OldestMessage.ID)
	assert.NotEmpty(t, snapshot.ByDomain)
	assert.Equal(t, "example.net", snapshot.ByDomain[0].Domain)
}

func TestRequeueMessageResetsDeliveryState(t *testing.T) {
	mgr := NewManager(t.TempDir(), 0)
	defer mgr.Stop()

	id, err := mgr.EnqueueMessage("sender@example.com", []string{"rcpt@example.net"}, "test", []byte("body"), PriorityNormal, time.Now())
	require.NoError(t, err)
	require.NoError(t, mgr.MoveMessage(id, Deferred, "450 greylisted"))

	deferred, err := mgr.GetMessage(id)
	require.NoError(t, err)
	require.Equal(t, Deferred, deferred.QueueType)
	require.Equal(t, 1, deferred.RetryCount)
	require.NotEmpty(t, deferred.LastError)
	require.False(t, deferred.NextRetry.IsZero())

	require.NoError(t, mgr.RequeueMessage(id, "operator retry"))

	msg, err := mgr.GetMessage(id)
	require.NoError(t, err)
	assert.Equal(t, Active, msg.QueueType)
	assert.Equal(t, 0, msg.RetryCount)
	assert.Empty(t, msg.LastError)
	assert.Empty(t, msg.HoldReason)
	assert.True(t, msg.NextRetry.IsZero())
	assert.Equal(t, "requeued", msg.Annotations["admin_action"])
	assert.Equal(t, "operator retry", msg.Annotations["admin_reason"])

	stats := mgr.GetStats()
	assert.Equal(t, 1, stats.ActiveCount)
	assert.Equal(t, 0, stats.DeferredCount)
}

// TestRequeueQueueMovesEveryMessageWithoutDeleting is the regression test for
// the dashboard bug: "Retry Deferred" called flush, which deleted the queue.
// Bulk retry must move messages back to active and leave them intact.
func TestRequeueQueueMovesEveryMessageWithoutDeleting(t *testing.T) {
	mgr := NewManager(t.TempDir(), 0)
	defer mgr.Stop()

	var ids []string
	for i := 0; i < 5; i++ {
		id, err := mgr.EnqueueMessage("sender@example.com", []string{"rcpt@example.net"}, "test", []byte("body"), PriorityNormal, time.Now())
		require.NoError(t, err)
		require.NoError(t, mgr.MoveMessage(id, Deferred, "450 greylisted"))
		ids = append(ids, id)
	}

	requeued, err := mgr.RequeueQueue(Deferred, "bulk retry")
	require.NoError(t, err)
	assert.Equal(t, 5, requeued)

	// Every message must still exist, now in the active queue.
	for _, id := range ids {
		msg, err := mgr.GetMessage(id)
		require.NoError(t, err, "message %s must not have been deleted", id)
		assert.Equal(t, Active, msg.QueueType)
		assert.Equal(t, 0, msg.RetryCount)
	}

	stats := mgr.GetStats()
	assert.Equal(t, 5, stats.ActiveCount)
	assert.Equal(t, 0, stats.DeferredCount)
}

func TestHoldMessage(t *testing.T) {
	mgr := NewManager(t.TempDir(), 0)
	defer mgr.Stop()

	id, err := mgr.EnqueueMessage("sender@example.com", []string{"rcpt@example.net"}, "test", []byte("body"), PriorityNormal, time.Now())
	require.NoError(t, err)

	require.NoError(t, mgr.HoldMessage(id, "investigate recipient"))

	msg, err := mgr.GetMessage(id)
	require.NoError(t, err)
	assert.Equal(t, Hold, msg.QueueType)
	assert.Equal(t, "investigate recipient", msg.HoldReason)
}
