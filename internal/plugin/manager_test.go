package plugin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePlugin is a minimal Plugin implementation for manager tests.
type fakePlugin struct {
	name      string
	closeErr  error
	closed    bool
	stages    []ProcessingStage
	priority  PluginPriority
	execFn    func(ctx interface{}) (PluginResult, error)
	execCalls int
}

func (f *fakePlugin) GetInfo() PluginInfo {
	return PluginInfo{Name: f.name, Type: PluginTypeFilter}
}
func (f *fakePlugin) Init(config map[string]interface{}) error { return nil }
func (f *fakePlugin) Close() error {
	f.closed = true
	return f.closeErr
}
func (f *fakePlugin) GetStages() []ProcessingStage { return f.stages }
func (f *fakePlugin) GetPriority() PluginPriority  { return f.priority }
func (f *fakePlugin) Execute(ctx interface{}) (PluginResult, error) {
	f.execCalls++
	if f.execFn != nil {
		return f.execFn(ctx)
	}
	return PluginResult{Action: ActionContinue}, nil
}

func TestManager_NewManager(t *testing.T) {
	m := NewManager("/some/path")
	require.NotNil(t, m)
	assert.Equal(t, "/some/path", m.pluginPath)
	assert.Empty(t, m.ListPluginTypes())
	assert.False(t, m.IsSecureMode())
}

func TestManager_RegisterAndListTypePlugins(t *testing.T) {
	m := NewManager("/plugins")

	p1 := &fakePlugin{name: "p1"}
	p2 := &fakePlugin{name: "p2"}

	m.registerTypePlugin("p1", p1, PluginTypeFilter)
	m.registerTypePlugin("p2", p2, PluginTypeFilter)

	plugins := m.GetPluginsByType(PluginTypeFilter)
	assert.Len(t, plugins, 2)

	types := m.ListPluginTypes()
	assert.Contains(t, types, PluginTypeFilter)

	// Unregistered type returns empty slice, not nil-panic
	assert.Empty(t, m.GetPluginsByType("nonexistent"))
}

func TestManager_RegisterStagePlugin_SortsByPriority(t *testing.T) {
	m := NewManager("/plugins")

	low := &fakePlugin{name: "low", stages: []ProcessingStage{StageDataComplete}, priority: PriorityLow}
	high := &fakePlugin{name: "high", stages: []ProcessingStage{StageDataComplete}, priority: PriorityHigh}
	normal := &fakePlugin{name: "normal", stages: []ProcessingStage{StageDataComplete}, priority: PriorityNormal}

	// Register in an order that would be wrong if not sorted
	m.registerStagePlugin(low)
	m.registerStagePlugin(high)
	m.registerStagePlugin(normal)

	plugins := m.GetPluginsByStage(StageDataComplete)
	require.Len(t, plugins, 3)
	assert.Equal(t, PriorityHigh, plugins[0].GetPriority())
	assert.Equal(t, PriorityNormal, plugins[1].GetPriority())
	assert.Equal(t, PriorityLow, plugins[2].GetPriority())

	// Stage with nothing registered returns empty, not nil-panic
	assert.Empty(t, m.GetPluginsByStage(StageConnect))
}

func TestManager_GetPlugin_NotFoundErrors(t *testing.T) {
	m := NewManager("/plugins")

	_, err := m.GetAntivirusPlugin("missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPluginNotFound))

	_, err = m.GetAntispamPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)

	_, err = m.GetDKIMPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)

	_, err = m.GetSPFPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)

	_, err = m.GetDMARCPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)

	_, err = m.GetARCPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)

	_, err = m.GetRateLimitPlugin("missing")
	require.ErrorIs(t, err, ErrPluginNotFound)
}

func TestManager_LoadPlugin_MissingFile(t *testing.T) {
	m := NewManager(t.TempDir())
	err := m.LoadPlugin("doesnotexist")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPluginNotFound))
}

func TestManager_LoadPlugins_MissingDirectory(t *testing.T) {
	m := NewManager("/path/that/does/not/exist/anywhere")
	err := m.LoadPlugins()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plugin directory not found")
}

func TestManager_ListARCAndRateLimitPlugins_Sorted(t *testing.T) {
	m := NewManager("/plugins")

	m.arcPlugins["zebra"] = nil
	m.arcPlugins["alpha"] = nil
	m.arcPlugins["mid"] = nil

	names := m.ListARCPlugins()
	assert.Equal(t, []string{"alpha", "mid", "zebra"}, names)

	m.rateLimitPlugins["zzz"] = nil
	m.rateLimitPlugins["aaa"] = nil
	rlNames := m.ListRateLimitPlugins()
	assert.Equal(t, []string{"aaa", "zzz"}, rlNames)
}

func TestManager_ExecuteStage(t *testing.T) {
	t.Run("no plugins registered continues by default", func(t *testing.T) {
		m := NewManager("/plugins")
		result, err := m.ExecuteStage(StageMailFrom, nil)
		require.NoError(t, err)
		assert.Equal(t, ActionContinue, result.Action)
	})

	t.Run("plugin annotations are merged", func(t *testing.T) {
		m := NewManager("/plugins")
		p := &fakePlugin{
			name:     "annotator",
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityNormal,
			execFn: func(ctx interface{}) (PluginResult, error) {
				return PluginResult{
					Action:      ActionContinue,
					Annotations: map[string]string{"key": "value"},
				}, nil
			},
		}
		m.registerStagePlugin(p)

		result, err := m.ExecuteStage(StageMailFrom, nil)
		require.NoError(t, err)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "value", result.Annotations["key"])
		assert.Equal(t, 1, p.execCalls)
	})

	t.Run("non-continue action stops processing further plugins", func(t *testing.T) {
		m := NewManager("/plugins")
		first := &fakePlugin{
			name:     "rejector",
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityHigh,
			execFn: func(ctx interface{}) (PluginResult, error) {
				return PluginResult{Action: ActionReject, Message: "blocked"}, nil
			},
		}
		second := &fakePlugin{
			name:     "never-called",
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityLow,
		}
		m.registerStagePlugin(first)
		m.registerStagePlugin(second)

		result, err := m.ExecuteStage(StageMailFrom, nil)
		require.NoError(t, err)
		assert.Equal(t, ActionReject, result.Action)
		assert.Equal(t, "blocked", result.Message)
		assert.Equal(t, 1, first.execCalls)
		assert.Equal(t, 0, second.execCalls, "lower priority plugin should not run after reject")
	})

	t.Run("plugin execution error is propagated", func(t *testing.T) {
		m := NewManager("/plugins")
		p := &fakePlugin{
			name:     "erroring",
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityNormal,
			execFn: func(ctx interface{}) (PluginResult, error) {
				return PluginResult{}, errors.New("boom")
			},
		}
		m.registerStagePlugin(p)

		_, err := m.ExecuteStage(StageMailFrom, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "boom")
	})
}

func TestManager_Close(t *testing.T) {
	m := NewManager("/plugins")

	p1 := &fakePlugin{name: "p1"}
	p2 := &fakePlugin{name: "p2", closeErr: errors.New("close failed")}
	m.registerTypePlugin("p1", p1, PluginTypeFilter)
	m.registerTypePlugin("p2", p2, PluginTypeFilter)

	err := m.Close()
	require.Error(t, err) // last error from p2 should propagate
	assert.True(t, p1.closed)
	assert.True(t, p2.closed)

	// State should be reset
	assert.Empty(t, m.ListPluginTypes())
	assert.Empty(t, m.GetPluginsByType(PluginTypeFilter))
}

func TestManager_SecureManagerAccessors(t *testing.T) {
	m := NewManager("/plugins")
	assert.False(t, m.IsSecureMode())
	assert.Nil(t, m.GetSecureManager())

	status := m.GetSecurityStatus()
	assert.Equal(t, false, status["secure_mode"])
}

func TestManager_ExecuteSecurePlugin_FallsBackWithoutSecureManager(t *testing.T) {
	m := NewManager("/plugins")
	called := false
	result, err := m.ExecuteSecurePlugin("anything", func() (*PluginResult, error) {
		called = true
		return &PluginResult{Action: ActionContinue}, nil
	})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestManager_LoadSecurePlugin_FallsBackToRegularLoad(t *testing.T) {
	m := NewManager(t.TempDir())
	err := m.LoadSecurePlugin("doesnotexist")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPluginNotFound))
}
