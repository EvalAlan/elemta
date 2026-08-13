package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueueObservabilityAndControlRoutes(t *testing.T) {
	server := newStartedQueueControlTestServer(t)

	activeID, err := server.queueMgr.EnqueueMessage("sender@example.com", []string{"active@example.net"}, "active message", []byte("active body"), queue.PriorityNormal, time.Now())
	require.NoError(t, err)

	deferredID, err := server.queueMgr.EnqueueMessage("sender@example.com", []string{"deferred@example.org"}, "deferred message", []byte("deferred body"), queue.PriorityHigh, time.Now())
	require.NoError(t, err)
	require.NoError(t, server.queueMgr.MoveMessage(deferredID, queue.Deferred, "temporary failure"))

	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := fmt.Sprintf("http://%s/api", server.listener.Addr().String())

	t.Run("GET /api/queue/observability", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/queue/observability")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var snapshot queue.QueueObservabilitySnapshot
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&snapshot))
		assert.Equal(t, "file", snapshot.Backend)
		assert.Equal(t, 2, snapshot.TotalMessages)
		assert.Equal(t, 1, snapshot.ByQueue[string(queue.Active)].Count)
		assert.Equal(t, 1, snapshot.ByQueue[string(queue.Deferred)].Count)
		assert.False(t, snapshot.ClaimsSupported)
		require.NotEmpty(t, snapshot.ByDomain)
	})

	t.Run("POST /api/queue/message/{id}/hold", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/queue/message/"+activeID+"/hold", "application/json", bytes.NewBufferString(`{"reason":"test hold"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		msg, err := server.queueMgr.GetMessage(activeID)
		require.NoError(t, err)
		assert.Equal(t, queue.Hold, msg.QueueType)
		assert.Equal(t, "test hold", msg.HoldReason)
	})

	t.Run("POST /api/queue/message/{id}/requeue", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/queue/message/"+deferredID+"/requeue", "application/json", bytes.NewBufferString(`{"reason":"test requeue"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		msg, err := server.queueMgr.GetMessage(deferredID)
		require.NoError(t, err)
		assert.Equal(t, queue.Active, msg.QueueType)
		assert.Equal(t, 0, msg.RetryCount)
		assert.Empty(t, msg.LastError)
		assert.Equal(t, "requeued", msg.Annotations["admin_action"])
		assert.Equal(t, "test requeue", msg.Annotations["admin_reason"])
	})

	// The file backend used to answer 400 here because it had no concept of a
	// claim: the processor listed the whole queue every tick instead. It claims
	// in bounded batches now, so releasing one is a supported operation and the
	// endpoint has to say so. Backends that still lack claiming — sqlite and
	// indexedfs — keep returning 400 through the same handler.
	t.Run("POST /api/queue/message/{id}/release-claim on a claiming backend", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/queue/message/"+deferredID+"/release-claim", "application/json", bytes.NewBufferString(`{"worker_id":"worker-1"}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func newStartedQueueControlTestServer(t *testing.T) *Server {
	t.Helper()

	server, err := NewServer(&Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:0",
		WebRoot:     t.TempDir(),
		AuthEnabled: false,
	}, (*MainConfig)(nil), t.TempDir(), 0, "")
	require.NoError(t, err)

	require.NoError(t, server.Start())
	t.Cleanup(func() {
		_ = server.Stop()
		server.queueMgr.Stop()
	})

	return server
}
