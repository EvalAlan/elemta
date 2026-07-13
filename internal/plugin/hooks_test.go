package plugin

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHookContext(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2525}
	ctx := NewHookContext(context.Background(), "session-1", "msg-1", addr, addr, StageMailFrom)

	require.NotNil(t, ctx)
	assert.Equal(t, "session-1", ctx.SessionID)
	assert.Equal(t, "msg-1", ctx.MessageID)
	assert.Equal(t, StageMailFrom, ctx.Phase)
	assert.NotNil(t, ctx.Data)
	assert.False(t, ctx.Timestamp.IsZero())
}

func TestHookContext_SetAndGet(t *testing.T) {
	ctx := NewHookContext(context.Background(), "s", "m", nil, nil, StageConnect)

	_, exists := ctx.Get("missing")
	assert.False(t, exists)

	ctx.Set("key", "value")
	val, exists := ctx.Get("key")
	require.True(t, exists)
	assert.Equal(t, "value", val)

	ctx.Set("key", "overwritten")
	val, _ = ctx.Get("key")
	assert.Equal(t, "overwritten", val)
}

// fakeConnectionHook implements ConnectionHook for registry tests.
type fakeConnectionHook struct{}

func (f *fakeConnectionHook) OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}
func (f *fakeConnectionHook) OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}

type fakeSecurityHook struct{}

func (f *fakeSecurityHook) OnRateLimitCheck(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}
func (f *fakeSecurityHook) OnGreylistCheck(ctx *HookContext, sender, recipient string, remoteAddr net.Addr) (*PluginResult, error) {
	return nil, nil
}
func (f *fakeSecurityHook) OnReputationCheck(ctx *HookContext, remoteAddr net.Addr, domain string) (*PluginResult, error) {
	return nil, nil
}

type fakeMetricsHook struct{}

func (f *fakeMetricsHook) OnMetricsCollect(ctx *HookContext, event string, data map[string]interface{}) error {
	return nil
}

func TestHookRegistry_NewRegistryStartsEmpty(t *testing.T) {
	hr := NewHookRegistry()

	assert.Empty(t, hr.GetConnectionHooks())
	assert.Empty(t, hr.GetCommandHooks())
	assert.Empty(t, hr.GetTransactionHooks())
	assert.Empty(t, hr.GetProcessingHooks())
	assert.Empty(t, hr.GetQueueHooks())
	assert.Empty(t, hr.GetDeliveryHooks())
	assert.Empty(t, hr.GetSecurityHooks())
	assert.Empty(t, hr.GetContentFilterHooks())
	assert.Empty(t, hr.GetAuthenticationHooks())
	assert.Empty(t, hr.GetMetricsHooks())
	assert.Empty(t, hr.GetErrorHooks())
}

func TestHookRegistry_RegisterConnectionHook(t *testing.T) {
	hr := NewHookRegistry()
	h1 := &fakeConnectionHook{}
	h2 := &fakeConnectionHook{}

	hr.RegisterConnectionHook(h1)
	assert.Len(t, hr.GetConnectionHooks(), 1)

	hr.RegisterConnectionHook(h2)
	hooks := hr.GetConnectionHooks()
	require.Len(t, hooks, 2)
	assert.Same(t, h1, hooks[0])
	assert.Same(t, h2, hooks[1])
}

func TestHookRegistry_RegisterSecurityHook(t *testing.T) {
	hr := NewHookRegistry()
	hr.RegisterSecurityHook(&fakeSecurityHook{})
	assert.Len(t, hr.GetSecurityHooks(), 1)
	// Other registries remain unaffected
	assert.Empty(t, hr.GetConnectionHooks())
}

func TestHookRegistry_RegisterMetricsHook(t *testing.T) {
	hr := NewHookRegistry()
	hr.RegisterMetricsHook(&fakeMetricsHook{})
	assert.Len(t, hr.GetMetricsHooks(), 1)
}
