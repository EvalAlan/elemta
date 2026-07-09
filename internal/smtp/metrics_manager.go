package smtp

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/busybox42/elemta/internal/queue"
)

// MetricsManager handles all metrics-related functionality
type MetricsManager struct {
	metrics       *Metrics
	metricsServer *http.Server
	config        *Config
	logger        *slog.Logger
	queueManager  queue.QueueManager
}

// SetQueueManager wires the queue manager so queue-size gauges are fed from its
// authoritative, incrementally-maintained stats rather than re-scanning disk.
func (m *MetricsManager) SetQueueManager(qm queue.QueueManager) {
	m.queueManager = qm
}

// NewMetricsManager creates a new metrics manager
func NewMetricsManager(config *Config, logger *slog.Logger, metrics *Metrics) *MetricsManager {
	return &MetricsManager{
		config:  config,
		logger:  logger,
		metrics: metrics,
	}
}

// Start initializes the metrics server if enabled
func (m *MetricsManager) Start() error {
	if m.config.Metrics != nil && m.config.Metrics.Enabled {
		m.logger.Info("Starting metrics server", "address", m.config.Metrics.ListenAddr)
		m.metricsServer = StartMetricsServer(m.config.Metrics.ListenAddr)
	}
	return nil
}

// UpdateQueueSizes updates queue size metrics. When a queue manager is wired it
// uses the authoritative in-memory stats; otherwise it falls back to a disk scan.
func (m *MetricsManager) UpdateQueueSizes() {
	if m.metrics == nil {
		return
	}
	if m.queueManager != nil {
		stats := m.queueManager.GetStats()
		m.metrics.SetQueueSizes(stats.ActiveCount, stats.DeferredCount, stats.HoldCount, stats.FailedCount)
		return
	}
	m.metrics.UpdateQueueSizes(m.config)
}

// Shutdown gracefully shuts down the metrics server
func (m *MetricsManager) Shutdown(ctx context.Context) error {
	if m.metricsServer != nil {
		if err := m.metricsServer.Shutdown(ctx); err != nil {
			m.logger.Error("Failed to shutdown metrics server", "error", err)
			return err
		}
	}
	return nil
}
