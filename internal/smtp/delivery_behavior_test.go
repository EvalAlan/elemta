package smtp

import (
	"context"
	"testing"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/require"
	"log/slog"
)

// TestDeliveryHandlerFactoryEnsuresMockUsed verifies that the injection seam
// allows substituting a mock delivery handler.
func TestDeliveryHandlerFactoryEnsuresMockUsed(t *testing.T) {
	// Override factory for this test
	oldFactory := newDeliveryHandler
	defer func() { newDeliveryHandler = oldFactory }()

	var called bool
	newDeliveryHandler = func(host string, port int, maxPerDomain int, failedQueueRetentionHours int) queue.DeliveryHandler {
		called = true
		return queue.NewMockDeliveryHandler(failedQueueRetentionHours)
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1
	cfg.MaxRetries = 0
	cfg.MaxConnectionsPerDomain = 10
	cfg.FailedQueueRetentionHours = 0

	_, _, err := initQueueSystem(cfg, slog.Default())
	require.NoError(t, err)
	require.True(t, called, "newDeliveryHandler factory was not called")
	// We cannot easily inspect processor.handler without exposing it.
	// However, the seam test already proves the wiring; this test simply
	// ensures the factory override is honored in the init path.
}

// TestMetricsStoreFactoryEnsuresStubUsed verifies that the metrics store factory injection works.
func TestMetricsStoreFactoryEnsuresStubUsed(t *testing.T) {
	oldFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldFactory }()

	var called bool
	newQueueMetricsStore = func(addr string) (queue.MetricsRecorder, error) {
		called = true
		return &deliveryMetricsStub{}, nil
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1

	_, _, err := initQueueSystem(cfg, slog.Default())
	require.NoError(t, err)
	require.True(t, called, "newQueueMetricsStore factory was not called")
	// We cannot easily inspect processor.metricsRecorder without exposing it.
	// However, the seam test already proves the wiring; this test simply
	// ensures the factory override is honored in the init path.
}

type deliveryMetricsStub struct{}

func (s *deliveryMetricsStub) IncrDelivered(ctx context.Context) error { return nil }
func (s *deliveryMetricsStub) IncrFailed(ctx context.Context) error    { return nil }
func (s *deliveryMetricsStub) IncrDeferred(ctx context.Context) error  { return nil }
func (s *deliveryMetricsStub) AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error {
	return nil
}
