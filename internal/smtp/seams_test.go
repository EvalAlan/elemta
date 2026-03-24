package smtp

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/datasource"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuthDataSource struct {
	authenticateFn func(ctx context.Context, username, password string) (bool, error)
}

func (f *fakeAuthDataSource) Connect() error    { return nil }
func (f *fakeAuthDataSource) Close() error      { return nil }
func (f *fakeAuthDataSource) IsConnected() bool { return true }
func (f *fakeAuthDataSource) Name() string      { return "fake" }
func (f *fakeAuthDataSource) Type() string      { return "fake" }
func (f *fakeAuthDataSource) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return nil, nil
}
func (f *fakeAuthDataSource) GetUser(ctx context.Context, username string) (datasource.User, error) {
	return datasource.User{}, nil
}
func (f *fakeAuthDataSource) CreateUser(ctx context.Context, user datasource.User) error { return nil }
func (f *fakeAuthDataSource) UpdateUser(ctx context.Context, user datasource.User) error {
	return nil
}
func (f *fakeAuthDataSource) DeleteUser(ctx context.Context, username string) error { return nil }
func (f *fakeAuthDataSource) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]datasource.User, error) {
	return nil, nil
}
func (f *fakeAuthDataSource) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if f.authenticateFn != nil {
		return f.authenticateFn(ctx, username, password)
	}
	return true, nil
}
func (f *fakeAuthDataSource) GetPermissions(ctx context.Context, username string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthDataSource) HasPermission(ctx context.Context, username, permission string) (bool, error) {
	return false, nil
}

type stubMetricsRecorder struct{}

func (s *stubMetricsRecorder) IncrDelivered(ctx context.Context) error { return nil }
func (s *stubMetricsRecorder) IncrFailed(ctx context.Context) error    { return nil }
func (s *stubMetricsRecorder) IncrDeferred(ctx context.Context) error  { return nil }
func (s *stubMetricsRecorder) AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error {
	return nil
}

func TestNewAuthenticator_UsesInjectedDataSourceFactory(t *testing.T) {
	oldFactory := newAuthDataSource
	defer func() { newAuthDataSource = oldFactory }()

	called := false
	newAuthDataSource = func(cfg datasource.Config) (datasource.DataSource, error) {
		called = true
		assert.Equal(t, "ldap", cfg.Type)
		assert.Equal(t, "ldap.internal", cfg.Host)
		assert.Equal(t, 389, cfg.Port)
		assert.Equal(t, "dc=example,dc=com", cfg.Options["base_dn"])
		return &fakeAuthDataSource{}, nil
	}

	auth, err := NewAuthenticator(&AuthConfig{
		Enabled:        true,
		DataSourceName: "ldap",
		DataSourceHost: "ldap.internal",
		DataSourcePort: 389,
		DataSourceDB:   "dc=example,dc=com",
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.True(t, called)
}

func TestInitAuthenticator_UsesInjectedFactoryWithoutExternalBackend(t *testing.T) {
	oldFactory := newAuthDataSource
	defer func() { newAuthDataSource = oldFactory }()

	newAuthDataSource = func(cfg datasource.Config) (datasource.DataSource, error) {
		return &fakeAuthDataSource{}, nil
	}

	auth, err := initAuthenticator(&Config{
		Auth: &AuthConfig{
			Enabled:        true,
			DataSourceName: "ldap",
			DataSourceHost: "elemta-ldap",
			DataSourcePort: 389,
			DataSourceDB:   "dc=example,dc=com",
		},
	}, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.True(t, auth.IsEnabled())
}

func TestInitQueueSystem_UsesInjectedDeliveryAndMetricsFactories(t *testing.T) {
	oldDeliveryFactory := newDeliveryHandler
	oldMetricsFactory := newQueueMetricsStore
	defer func() {
		newDeliveryHandler = oldDeliveryFactory
		newQueueMetricsStore = oldMetricsFactory
	}()

	var gotHost string
	var gotPort int
	var gotMaxPerDomain int
	var gotRetention int
	var metricsAddr string

	newDeliveryHandler = func(host string, port int, maxPerDomain int, failedQueueRetentionHours int) queue.DeliveryHandler {
		gotHost = host
		gotPort = port
		gotMaxPerDomain = maxPerDomain
		gotRetention = failedQueueRetentionHours
		return queue.NewMockDeliveryHandler(failedQueueRetentionHours)
	}
	newQueueMetricsStore = func(addr string) (queue.MetricsRecorder, error) {
		metricsAddr = addr
		return &stubMetricsRecorder{}, nil
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 2
	cfg.MaxRetries = 3
	cfg.Delivery = &DeliveryConfig{Host: "mock-lmtp", Port: 2526}
	cfg.MaxConnectionsPerDomain = 7
	cfg.FailedQueueRetentionHours = 48

	manager, processor := initQueueSystem(cfg, slog.Default())
	require.NotNil(t, manager)
	require.NotNil(t, processor)
	assert.Equal(t, "mock-lmtp", gotHost)
	assert.Equal(t, 2526, gotPort)
	assert.Equal(t, 7, gotMaxPerDomain)
	assert.Equal(t, 48, gotRetention)
	assert.Equal(t, "elemta-valkey:6379", metricsAddr)
}

func TestInitQueueSystem_ToleratesMetricsFactoryFailure(t *testing.T) {
	oldDeliveryFactory := newDeliveryHandler
	oldMetricsFactory := newQueueMetricsStore
	defer func() {
		newDeliveryHandler = oldDeliveryFactory
		newQueueMetricsStore = oldMetricsFactory
	}()

	newDeliveryHandler = func(host string, port int, maxPerDomain int, failedQueueRetentionHours int) queue.DeliveryHandler {
		return queue.NewMockDeliveryHandler(failedQueueRetentionHours)
	}
	newQueueMetricsStore = func(addr string) (queue.MetricsRecorder, error) {
		return nil, errors.New("metrics unavailable")
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1

	manager, processor := initQueueSystem(cfg, slog.Default())
	require.NotNil(t, manager)
	require.NotNil(t, processor)

	// Start/stop to prove the processor still works without external metrics.
	require.NoError(t, processor.Start())
	time.Sleep(10 * time.Millisecond)
	processor.Stop()
}
