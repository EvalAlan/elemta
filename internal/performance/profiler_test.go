package performance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProfiler_AppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir})
	defer func() { _ = p.Close() }()

	assert.Equal(t, dir, p.profileDir)
	assert.False(t, p.enabled)
}

func TestNewProfiler_CreatesProfileDirWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "profiles-subdir")

	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: target})
	defer func() { _ = p.Close() }()

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestProfiler_EnableDisableIsEnabled(t *testing.T) {
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: t.TempDir()})
	defer func() { _ = p.Close() }()

	assert.False(t, p.IsEnabled())
	p.EnableProfiling()
	assert.True(t, p.IsEnabled())
	p.DisableProfiling()
	assert.False(t, p.IsEnabled())
}

func TestProfiler_OperationsRequireEnabled(t *testing.T) {
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: t.TempDir()})
	defer func() { _ = p.Close() }()

	require.Error(t, p.StartCPUProfile())
	require.Error(t, p.GenerateHeapProfile())
	require.Error(t, p.GenerateGoroutineProfile())
	require.Error(t, p.GenerateBlockProfile())
	require.Error(t, p.GenerateMutexProfile())
	require.Error(t, p.StartTrace())
	require.Error(t, p.GenerateAllProfiles())
}

func TestProfiler_StartStopCPUProfile(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true})
	defer func() { _ = p.Close() }()

	require.NoError(t, p.StartCPUProfile())

	// Starting again while active should error.
	err := p.StartCPUProfile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already active")

	require.NoError(t, p.StopCPUProfile())

	// Stopping when not active should error.
	err = p.StopCPUProfile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "expected a cpu profile file to be written")
}

func TestProfiler_GenerateHeapProfile(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true})
	defer func() { _ = p.Close() }()

	require.NoError(t, p.GenerateHeapProfile())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)

	metrics := p.GetMetrics()
	assert.Equal(t, uint32(1), metrics["profiles_generated"])
	assert.NotEqual(t, "never", metrics["last_profile"])
}

func TestProfiler_GenerateGoroutineProfile(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true})
	defer func() { _ = p.Close() }()

	require.NoError(t, p.GenerateGoroutineProfile())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}

func TestProfiler_StartStopTrace(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true})
	defer func() { _ = p.Close() }()

	require.NoError(t, p.StartTrace())

	err := p.StartTrace()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already active")

	require.NoError(t, p.StopTrace())

	err = p.StopTrace()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

func TestProfiler_GetMetrics_ReflectsState(t *testing.T) {
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: t.TempDir(), Enabled: true})
	defer func() { _ = p.Close() }()

	metrics := p.GetMetrics()
	assert.Equal(t, true, metrics["enabled"])
	// A fresh profiler has generated no profiles yet, so last_profile
	// reports the "never" sentinel rather than a formatted timestamp.
	assert.Equal(t, "never", metrics["last_profile"])
	assert.Equal(t, false, metrics["cpu_profile_active"])
	assert.Equal(t, false, metrics["trace_active"])

	require.NoError(t, p.StartCPUProfile())
	metrics = p.GetMetrics()
	assert.Equal(t, true, metrics["cpu_profile_active"])
	require.NoError(t, p.StopCPUProfile())
}

func TestProfiler_GetRuntimeStats(t *testing.T) {
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: t.TempDir()})
	defer func() { _ = p.Close() }()

	stats := p.GetRuntimeStats()
	assert.Contains(t, stats, "goroutines")
	assert.Contains(t, stats, "cpus")
	assert.Contains(t, stats, "heap_alloc_mb")

	cpus, ok := stats["cpus"].(int)
	require.True(t, ok)
	assert.Greater(t, cpus, 0)
}

func TestProfiler_Close_WhenNotRunningIsNoop(t *testing.T) {
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: t.TempDir()})
	// AutoProfile disabled by default, so running is never set to true;
	// Close should be a clean no-op.
	require.NoError(t, p.Close())
}

func TestProfiler_Close_StopsActiveCPUProfileAndTrace(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true, AutoProfile: true, ProfileInt: 0})

	require.NoError(t, p.StartCPUProfile())
	require.NoError(t, p.StartTrace())

	require.NoError(t, p.Close())

	metrics := p.GetMetrics()
	assert.Equal(t, false, metrics["cpu_profile_active"])
	assert.Equal(t, false, metrics["trace_active"])
}

func TestProfiler_GenerateAllProfiles(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(ProfilerConfig{Logger: testLogger(), ProfileDir: dir, Enabled: true})
	defer func() { _ = p.Close() }()

	require.NoError(t, p.GenerateAllProfiles())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	// heap + goroutine + block + mutex profiles
	assert.GreaterOrEqual(t, len(entries), 4)
}
