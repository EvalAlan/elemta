package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/busybox42/elemta/internal/dkim"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/require"
)

func writeDeliveryTestDKIMKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "dkim.key")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

// TestInitQueueSystemSMTPModeAttachesARCSealer proves the sealer reaches the
// delivery path. Configuration that parses but never reaches the code that uses
// it is a failure this repository has hit more than once.
func TestInitQueueSystemSMTPModeAttachesARCSealer(t *testing.T) {
	oldMetricsFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldMetricsFactory }()
	newQueueMetricsStore = func(string) (queue.MetricsRecorder, error) {
		return &deliveryMetricsStub{}, nil
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1
	cfg.Delivery = &DeliveryConfig{Mode: "smtp"}
	cfg.Plugins = &PluginConfig{ARC: &ARCPluginConfig{
		Enabled: true, Verify: true, Seal: true,
		Domain: "auth.test", Selector: "arc",
		PrivateKeyPath:         writeDeliveryTestDKIMKey(t),
		HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed",
	}}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	manager, _, err := initQueueSystem(cfg, logger)
	require.NoError(t, err)
	defer manager.Stop()

	output := logs.String()
	require.True(t, strings.Contains(output, "ARC outbound sealing enabled"), output)
	require.True(t, strings.Contains(output, "arc._domainkey.auth.test"), output)
}

func TestInitQueueSystemRejectsInvalidDKIMWhenProcessorDisabled(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = false
	cfg.DKIM = &dkim.Config{
		Enabled: true,
		Domains: []dkim.DomainConfig{{
			Domain:         "example.com",
			Selector:       "sel1",
			PrivateKeyPath: writeDeliveryTestDKIMKey(t),
			HeadersToSign:  []string{"Subject"},
		}},
	}

	manager, _, err := initQueueSystem(cfg, slog.Default())
	if manager != nil {
		defer manager.Stop()
	}
	require.ErrorContains(t, err, "headers_to_sign must include From")
}

func TestInitQueueSystem_SMTPModeAttachesDKIMSigner(t *testing.T) {
	oldMetricsFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldMetricsFactory }()
	newQueueMetricsStore = func(string) (queue.MetricsRecorder, error) {
		return &deliveryMetricsStub{}, nil
	}

	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1
	cfg.Delivery = &DeliveryConfig{Mode: "smtp"}
	cfg.DKIM = &dkim.Config{
		Enabled: true,
		Domains: []dkim.DomainConfig{{
			Domain:         "example.com",
			Selector:       "sel1",
			PrivateKeyPath: writeDeliveryTestDKIMKey(t),
		}},
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	manager, _, err := initQueueSystem(cfg, logger)
	require.NoError(t, err)
	defer manager.Stop()

	output := logs.String()
	require.True(t, strings.Contains(output, "Creating SMTP delivery handler"), output)
	require.True(t, strings.Contains(output, "DKIM outbound signing enabled"), output)
	require.False(t, strings.Contains(output, "active delivery handler is not the remote SMTP handler"), output)
}

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
