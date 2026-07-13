package performance

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewMemoryOptimizer_AppliesDefaults(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger()})
	defer func() { _ = mo.Close() }()

	assert.Equal(t, uint64(2*1024*1024*1024), mo.maxMemory)
	assert.Equal(t, 0.85, mo.gcThreshold)
	assert.Equal(t, 30*time.Second, mo.checkInterval)
	assert.NotNil(t, mo.GetBufferPool())
	assert.NotNil(t, mo.GetMessagePool())
}

func TestNewMemoryOptimizer_RespectsExplicitConfig(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{
		MaxMemory:     1024,
		GCThreshold:   0.5,
		CheckInterval: time.Millisecond,
		Logger:        testLogger(),
	})
	defer func() { _ = mo.Close() }()

	assert.Equal(t, uint64(1024), mo.maxMemory)
	assert.Equal(t, 0.5, mo.gcThreshold)
	assert.Equal(t, time.Millisecond, mo.checkInterval)
}

func TestMemoryOptimizer_Close(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})

	require.NoError(t, mo.Close())

	// Closing an already-stopped optimizer should report an error rather
	// than panic or block.
	err := mo.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already stopped")
}

func TestMemoryOptimizer_GetStats(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})
	defer func() { _ = mo.Close() }()

	stats := mo.GetStats()
	assert.Contains(t, stats, "heap_alloc_mb")
	assert.Contains(t, stats, "gc_runs")
	assert.Contains(t, stats, "goroutines")
	assert.Contains(t, stats, "max_memory_mb")

	goroutines, ok := stats["goroutines"].(int)
	require.True(t, ok)
	assert.Greater(t, goroutines, 0)
}

func TestMemoryOptimizer_ForceGC(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})
	defer func() { _ = mo.Close() }()

	duration := mo.ForceGC()
	assert.GreaterOrEqual(t, duration, time.Duration(0))
}

func TestMemoryOptimizer_SetGCPercent(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})
	defer func() { _ = mo.Close() }()

	old := mo.SetGCPercent(100)
	// Restore whatever it was before to avoid impacting other tests in this
	// process.
	defer mo.SetGCPercent(old)

	assert.IsType(t, 0, old)
}

func TestMemoryOptimizer_SetAndGetMemoryLimit(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})
	defer func() { _ = mo.Close() }()

	old := mo.SetMemoryLimit(512 * 1024 * 1024)
	defer mo.SetMemoryLimit(old)

	limit := mo.GetMemoryLimit()
	assert.Equal(t, int64(512*1024*1024), limit)
}

func TestBufferPool_GetPut(t *testing.T) {
	bp := NewBufferPool()

	buf := bp.Get(100)
	require.NotNil(t, buf)
	assert.Len(t, *buf, 100)

	// Requesting a larger size than the pooled default should still work.
	buf2 := bp.Get(8192)
	assert.Len(t, *buf2, 8192)

	bp.Put(buf)
	bp.Put(buf2)

	// Put(nil) must not panic.
	bp.Put(nil)

	// Reuse should not error and returns a correctly sized slice again.
	buf3 := bp.Get(50)
	assert.Len(t, *buf3, 50)
}

func TestMessagePool_GetPut(t *testing.T) {
	mp := NewMessagePool()

	msg := mp.Get()
	require.NotNil(t, msg)
	msg.Headers["X-Test"] = "value"
	msg.Body = append(msg.Body, []byte("hello")...)
	msg.Size = 5

	mp.Put(msg)

	// After Put, the message should have been cleared before returning to
	// the pool.
	assert.Empty(t, msg.Headers)
	assert.Empty(t, msg.Body)
	assert.Equal(t, 0, msg.Size)

	// Put(nil) must not panic.
	mp.Put(nil)

	msg2 := mp.Get()
	assert.Empty(t, msg2.Headers)
	assert.Empty(t, msg2.Body)
}

func TestMemoryOptimizer_MemoryProfileAndHeapDump(t *testing.T) {
	mo := NewMemoryOptimizer(MemoryOptimizerConfig{Logger: testLogger(), CheckInterval: time.Hour})
	defer func() { _ = mo.Close() }()

	assert.NotEmpty(t, mo.MemoryProfile())
	assert.NoError(t, mo.HeapDump("unused.pprof"))
}
