package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnvironmentOverridesApplyWhereUsed pins that the scaling settings a
// container sets in its environment reach the MTA and the dashboard, and
// never the saved configuration, which would otherwise keep the queue's
// password.
func TestEnvironmentOverridesApplyWhereUsed(t *testing.T) {
	t.Setenv(EnvQueueBackend, "postgres")
	t.Setenv(EnvQueuePostgresDSN, "postgres://q:secret@db/queue")
	t.Setenv(EnvProxyProtocolFrom, "10.0.0.5, 10.0.1.0/24")
	t.Setenv(EnvAPISessionStore, "valkey")
	cfg := &Config{}
	cfg.Queue.Backend = "file"
	smtp, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	if smtp.QueueBackend != "postgres" || smtp.QueuePostgres.DSN != "postgres://q:secret@db/queue" ||
		strings.Join(smtp.ProxyProtocolFrom, "|") != "10.0.0.5|10.0.1.0/24" || cfg.EffectiveSessionStore() != "valkey" {
		t.Fatalf("overrides not applied: %+v %v", smtp.QueueBackend, smtp.ProxyProtocolFrom)
	}
	if cfg.Queue.Backend != "file" || cfg.Queue.Postgres.DSN != "" {
		t.Fatal("the configuration itself was changed")
	}
	path := filepath.Join(t.TempDir(), "elemta.toml")
	if err := cfg.SaveConfig(path); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "secret") || strings.Contains(string(saved), "postgres") {
		t.Errorf("the saved configuration holds the environment's settings:\n%s", saved)
	}
}
