package plugin

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLifecycleState_String(t *testing.T) {
	tests := []struct {
		state LifecycleState
		want  string
	}{
		{StateUninitialized, "uninitialized"},
		{StateInitializing, "initializing"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{StateStopped, "stopped"},
		{StateError, "error"},
		{LifecycleState(999), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.state.String())
	}
}

func TestPluginState_String(t *testing.T) {
	tests := []struct {
		state PluginState
		want  string
	}{
		{PluginStateUnloaded, "unloaded"},
		{PluginStateLoading, "loading"},
		{PluginStateLoaded, "loaded"},
		{PluginStateInitializing, "initializing"},
		{PluginStateRunning, "running"},
		{PluginStateError, "error"},
		{PluginStateUnloading, "unloading"},
		{PluginState(999), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.state.String())
	}
}

func TestDefaultEnhancedConfig(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	assert.Equal(t, "./plugins", cfg.PluginPath)
	assert.True(t, cfg.Enabled)
	assert.Empty(t, cfg.Plugins)
	assert.False(t, cfg.AutoReload)
	assert.NotZero(t, cfg.ReloadInterval)
	assert.NotZero(t, cfg.HealthCheckInterval)
}

func TestNewEnhancedManager(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.PluginPath = "/plugins"
	em := NewEnhancedManager(cfg)

	require.NotNil(t, em)
	assert.Equal(t, StateUninitialized, em.lifecycleState)
	assert.False(t, em.started)
	assert.NotNil(t, em.hookRegistry)
	assert.NotNil(t, em.Manager)
}

func TestEnhancedManager_Start_DisabledConfig(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Enabled = false
	em := NewEnhancedManager(cfg)

	err := em.Start()
	require.NoError(t, err)
	assert.Equal(t, StateStopped, em.lifecycleState)
	assert.False(t, em.started, "manager should not be marked started when disabled")
}

func TestEnhancedManager_Start_EnabledWithNoConfiguredPlugins(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Enabled = true
	cfg.Plugins = nil
	em := NewEnhancedManager(cfg)

	err := em.Start()
	require.NoError(t, err)
	assert.Equal(t, StateRunning, em.lifecycleState)
	assert.True(t, em.started)

	require.NoError(t, em.Stop())
	assert.Equal(t, StateStopped, em.lifecycleState)
	assert.False(t, em.started)
}

func TestEnhancedManager_Start_TwiceErrors(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	em := NewEnhancedManager(cfg)

	require.NoError(t, em.Start())
	defer func() { _ = em.Stop() }()

	err := em.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
}

func TestEnhancedManager_Stop_WhenNotStartedIsNoop(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	em := NewEnhancedManager(cfg)

	err := em.Stop()
	require.NoError(t, err)
}

func TestEnhancedManager_LoadAndInitializePlugin_MissingPluginFileRecordsError(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.PluginPath = t.TempDir()
	em := NewEnhancedManager(cfg)

	err := em.loadAndInitializePlugin("does-not-exist")
	require.Error(t, err)

	em.mu.RLock()
	enhanced, exists := em.plugins["does-not-exist"]
	em.mu.RUnlock()

	require.True(t, exists)
	assert.Equal(t, PluginStateError, enhanced.State)
	assert.Error(t, enhanced.LastError)
}

func TestEnhancedManager_RegisterPluginHooks_RegistersMatchingInterfaces(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	em := NewEnhancedManager(cfg)

	// fakeConnectionHook (from hooks_test.go) implements ConnectionHook but
	// not the other hook interfaces, so only the connection hook registry
	// should gain an entry.
	hookPlugin := &fakeHookPlugin{}
	em.registerPluginHooks(hookPlugin, "hook-plugin")

	assert.Len(t, em.hookRegistry.GetConnectionHooks(), 1)
	assert.Empty(t, em.hookRegistry.GetSecurityHooks())
	assert.Empty(t, em.hookRegistry.GetMetricsHooks())
}

// fakeHookPlugin implements both Plugin and ConnectionHook so it can be
// registered through registerPluginHooks' type-switch dispatch.
type fakeHookPlugin struct{}

func (f *fakeHookPlugin) GetInfo() PluginInfo               { return PluginInfo{Name: "hook-plugin"} }
func (f *fakeHookPlugin) Init(map[string]interface{}) error { return nil }
func (f *fakeHookPlugin) Close() error                      { return nil }
func (f *fakeHookPlugin) OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}
func (f *fakeHookPlugin) OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}

func TestEnhancedManager_GetStatus(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	em := NewEnhancedManager(cfg)

	status := em.GetStatus()
	assert.Equal(t, "uninitialized", status["lifecycle_state"])
	assert.Equal(t, 0, status["loaded_plugins"])
	assert.Equal(t, 0, status["enabled_plugins"])
}
