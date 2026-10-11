package smtp

import (
	"path/filepath"
	"testing"

	"github.com/EvalAlan/elemta/internal/queue"
)

func TestPoolsFingerprintTracksPoolChangesOnly(t *testing.T) {
	cfg := func() *Config {
		return &Config{QueueDir: "/var/spool/q", Delivery: &DeliveryConfig{
			Pools: []queue.PoolConfig{{Name: "bulk", IPs: []queue.PoolIPConfig{{Address: "192.0.2.1"}}}},
		}}
	}
	base := poolsFingerprint(poolsSettings(cfg()))
	if base == "" {
		t.Fatal("configured pools have an empty fingerprint")
	}

	unrelated := cfg()
	unrelated.Delivery.DANE = true
	if got := poolsFingerprint(poolsSettings(unrelated)); got != base {
		t.Error("an unrelated delivery setting changed the pools fingerprint")
	}

	edited := cfg()
	edited.Delivery.Pools[0].IPs[0].Helo = "mta1.example.com"
	if got := poolsFingerprint(poolsSettings(edited)); got == base {
		t.Error("editing a pool address left the fingerprint unchanged")
	}

	if got := poolsFingerprint(poolsSettings(&Config{})); got != "" {
		t.Errorf("no pools fingerprint = %q, want empty", got)
	}
	if got := poolsSettings(cfg()).StateFile; got != filepath.Join("/var/spool/q", "pool-state.json") {
		t.Errorf("default state file = %q", got)
	}
}

func TestValkeyAddressMatchesSenderTelemetry(t *testing.T) {
	t.Setenv("VALKEY_ADDR", "")
	if got := valkeyAddress(); got != "elemta-valkey:6379" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("VALKEY_ADDR", "10.0.0.5:6379")
	if got := valkeyAddress(); got != "10.0.0.5:6379" {
		t.Errorf("from env = %q", got)
	}
	if got := sharedStatePrefix(nil); got != queue.DefaultSharedStatePrefix {
		t.Errorf("default prefix = %q", got)
	}
	if got := sharedStatePrefix(&DeliveryConfig{SharedStatePrefix: "eu:"}); got != "eu:" {
		t.Errorf("configured prefix = %q", got)
	}
}
