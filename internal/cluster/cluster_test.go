package cluster

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewCluster_ValidatesRequiredFields(t *testing.T) {
	t.Run("missing node ID errors before attempting to connect", func(t *testing.T) {
		_, err := NewCluster(ClusterConfig{
			ValkeyURL: "localhost:6379",
			Logger:    testLogger(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "node ID is required")
	})

	t.Run("missing valkey URL errors before attempting to connect", func(t *testing.T) {
		_, err := NewCluster(ClusterConfig{
			NodeID: "node-1",
			Logger: testLogger(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valkey URL is required")
	})
}

// newTestCluster builds a Cluster struct directly (bypassing NewCluster,
// which requires a live Valkey connection and starts background
// goroutines) so the pure, in-memory bookkeeping logic below can be
// exercised without any network access.
func newTestCluster(nodeID string) *Cluster {
	return &Cluster{
		nodeID: nodeID,
		logger: testLogger(),
		localNode: &Node{
			ID:     nodeID,
			Status: StatusHealthy,
		},
		nodes: make(map[string]*Node),
	}
}

func TestCluster_GetNodesAndGetNode(t *testing.T) {
	c := newTestCluster("local")
	c.nodes["node-a"] = &Node{ID: "node-a", Status: StatusHealthy}
	c.nodes["node-b"] = &Node{ID: "node-b", Status: StatusDegraded}

	nodes := c.GetNodes()
	assert.Len(t, nodes, 2)

	node, ok := c.GetNode("node-a")
	require.True(t, ok)
	assert.Equal(t, "node-a", node.ID)

	// Returned node must be a copy: mutating it should not affect cluster state.
	node.Status = StatusOffline
	stillThere, _ := c.GetNode("node-a")
	assert.Equal(t, StatusHealthy, stillThere.Status)

	_, ok = c.GetNode("missing")
	assert.False(t, ok)
}

func TestCluster_IsLeaderAndGetLeader(t *testing.T) {
	c := newTestCluster("local")

	assert.False(t, c.IsLeader())
	assert.Equal(t, "", c.GetLeader())

	c.leadership.Store(true)
	c.masterNode.Store("local")

	assert.True(t, c.IsLeader())
	assert.Equal(t, "local", c.GetLeader())
}

func TestCluster_UpdateMetrics(t *testing.T) {
	c := newTestCluster("local")
	c.UpdateMetrics(42, 7, 0.5)

	assert.Equal(t, int32(42), c.localNode.Connections)
	assert.Equal(t, int32(7), c.localNode.QueueDepth)
	assert.Equal(t, 0.5, c.localNode.Load)
}

func TestCluster_GetClusterStats(t *testing.T) {
	t.Run("aggregates across all known nodes", func(t *testing.T) {
		c := newTestCluster("local")
		c.nodes["a"] = &Node{ID: "a", Status: StatusHealthy, Connections: 10, QueueDepth: 2, Load: 0.2}
		c.nodes["b"] = &Node{ID: "b", Status: StatusDegraded, Connections: 5, QueueDepth: 1, Load: 0.4}
		c.nodes["c"] = &Node{ID: "c", Status: StatusUnhealthy, Connections: 0, QueueDepth: 0, Load: 0.0}
		c.nodes["d"] = &Node{ID: "d", Status: StatusOffline, Connections: 0, QueueDepth: 0, Load: 0.0}

		stats := c.GetClusterStats()
		assert.Equal(t, 4, stats["total_nodes"])
		assert.Equal(t, 1, stats["healthy_nodes"])
		assert.Equal(t, 1, stats["degraded_nodes"])
		assert.Equal(t, 2, stats["unhealthy_nodes"]) // unhealthy + offline both count
		assert.Equal(t, int32(15), stats["total_connections"])
		assert.Equal(t, int32(3), stats["total_queue_depth"])
		assert.InDelta(t, 0.15, stats["avg_load"], 0.0001)
		assert.Equal(t, "local", stats["local_node_id"])
	})

	t.Run("avoids divide by zero with no nodes", func(t *testing.T) {
		c := newTestCluster("local")
		stats := c.GetClusterStats()
		assert.Equal(t, 0, stats["total_nodes"])
		assert.Equal(t, 0.0, stats["avg_load"])
	})
}

func TestCluster_GetNodes_ReturnsIndependentCopies(t *testing.T) {
	c := newTestCluster("local")
	c.nodes["a"] = &Node{ID: "a", Connections: 1}

	nodes := c.GetNodes()
	require.Len(t, nodes, 1)
	nodes[0].Connections = 999

	// The stored node must not have been mutated through the returned slice.
	stored, ok := c.GetNode("a")
	require.True(t, ok)
	assert.Equal(t, int32(1), stored.Connections)
}

func TestNodeRoleAndStatusConstants(t *testing.T) {
	assert.Equal(t, NodeRole("master"), RoleMaster)
	assert.Equal(t, NodeRole("worker"), RoleWorker)
	assert.Equal(t, NodeRole("standby"), RoleStandby)

	assert.Equal(t, NodeStatus("healthy"), StatusHealthy)
	assert.Equal(t, NodeStatus("degraded"), StatusDegraded)
	assert.Equal(t, NodeStatus("unhealthy"), StatusUnhealthy)
	assert.Equal(t, NodeStatus("offline"), StatusOffline)
}

// Sanity-check that GetNodes/GetNode are safe to call concurrently with
// writers, matching how discoverNodes would touch the map from a
// background goroutine in production.
func TestCluster_ConcurrentReadsAndWrites(t *testing.T) {
	c := newTestCluster("local")
	var wg sync.WaitGroup
	var writes atomic.Int32

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			c.nodesMu.Lock()
			c.nodes["node"] = &Node{ID: "node", Connections: int32(i)}
			c.nodesMu.Unlock()
			writes.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = c.GetNodes()
			_, _ = c.GetNode("node")
			_ = c.GetClusterStats()
		}
	}()
	wg.Wait()

	assert.Equal(t, int32(100), writes.Load())
}
