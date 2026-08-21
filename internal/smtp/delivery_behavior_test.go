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

	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/queue"
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
// TestSplitModeStillSignsAndSeals. DKIM signing and ARC sealing attach to the
// remote handler, which in split mode lives inside the router rather than being
// the delivery handler itself. A type assertion against the wrapper silently
// finds nothing, and outbound mail goes unsigned with the dashboard still
// reporting signing as enabled.
func TestSplitModeStillSignsAndSeals(t *testing.T) {
	oldMetricsFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldMetricsFactory }()
	newQueueMetricsStore = func(string) (queue.MetricsRecorder, error) {
		return &deliveryMetricsStub{}, nil
	}

	keyPath := writeDeliveryTestDKIMKey(t)
	cfg := createTestConfig(t)
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1
	cfg.Delivery = &DeliveryConfig{Mode: "split"}
	cfg.LocalDomains = []string{"example.com"}
	cfg.DKIM = &dkim.Config{
		Enabled: true,
		Domains: []dkim.DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	}
	cfg.Plugins = &PluginConfig{ARC: &ARCPluginConfig{
		Enabled: true, Verify: true, Seal: true,
		Domain: "auth.test", Selector: "arc", PrivateKeyPath: keyPath,
		HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed",
	}}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	manager, _, err := initQueueSystem(cfg, logger)
	require.NoError(t, err)
	defer manager.Stop()

	output := logs.String()
	require.True(t, strings.Contains(output, "Creating split delivery handler"), output)
	require.True(t, strings.Contains(output, "DKIM outbound signing enabled"), output)
	require.True(t, strings.Contains(output, "ARC outbound sealing enabled"), output)
	require.True(t, strings.Contains(output, "Per-destination traffic shaping enabled"), output)
	// The fallback message means the wrapper hid the remote handler.
	require.False(t, strings.Contains(output, "not the remote SMTP handler"), output)
}

// TestSplitModeNeedsLocalDomains: with none configured every recipient is
// remote, which is what mode "smtp" already does. Starting anyway would look
// like split routing while doing nothing of the sort.
func TestSplitModeNeedsLocalDomains(t *testing.T) {
	oldMetricsFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldMetricsFactory }()
	newQueueMetricsStore = func(string) (queue.MetricsRecorder, error) {
		return &deliveryMetricsStub{}, nil
	}

	cfg := createTestConfig(t)
	// The delivery handler is only chosen when the processor runs, so without
	// this the misconfiguration is never reached and the test passes vacuously.
	cfg.QueueProcessorEnabled = true
	cfg.QueueProcessInterval = 1
	cfg.QueueWorkers = 1
	cfg.Delivery = &DeliveryConfig{Mode: "split"}
	cfg.LocalDomains = nil

	var logs bytes.Buffer
	_, _, err := initQueueSystem(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "local_domains")
}

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
func (s *deliveryMetricsStub) IncrDomainOutcome(ctx context.Context, domain, outcome string) error {
	return nil
}
func (s *deliveryMetricsStub) AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error {
	return nil
}

// TestEveryValidDeliveryModeIsActuallyImplemented walks the advertised list and
// checks the runtime accepts each one.
//
// The validator and the runtime switch used to keep separate lists, and they
// disagreed in both directions: "local" passed validation and then failed at
// startup, while a mode the runtime understood was rejected before reaching it.
// The second kind is the nastier one — the container crashloops with a
// configuration the operator was told was valid.
func TestEveryValidDeliveryModeIsActuallyImplemented(t *testing.T) {
	oldMetricsFactory := newQueueMetricsStore
	defer func() { newQueueMetricsStore = oldMetricsFactory }()
	newQueueMetricsStore = func(string) (queue.MetricsRecorder, error) {
		return &deliveryMetricsStub{}, nil
	}

	if len(DeliveryModes) == 0 {
		t.Fatal("DeliveryModes is empty; this test would check nothing")
	}

	for _, mode := range DeliveryModes {
		t.Run(mode, func(t *testing.T) {
			cfg := createTestConfig(t)
			cfg.QueueProcessorEnabled = true
			cfg.QueueProcessInterval = 1
			cfg.QueueWorkers = 1
			cfg.Delivery = &DeliveryConfig{Mode: mode}
			// split is the one mode with a prerequisite; give it one so this
			// tests the mode rather than the prerequisite.
			cfg.LocalDomains = []string{"example.com"}

			var logs bytes.Buffer
			manager, _, err := initQueueSystem(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
			if err != nil {
				t.Fatalf("mode %q is advertised as valid but the runtime refuses it: %v", mode, err)
			}
			manager.Stop()
		})
	}
}
