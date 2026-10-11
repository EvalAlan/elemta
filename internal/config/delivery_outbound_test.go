package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/EvalAlan/elemta/internal/queue"
	"github.com/EvalAlan/elemta/internal/smtp"
	pelletier "github.com/pelletier/go-toml/v2"
)

const poolsTOML = `
[delivery]
mode = "smtp"
default_pool = "transactional"
pool_state_file = "/var/spool/elemta/pool-state.json"

[[delivery.pools]]
name = "transactional"
senders = ["example.com"]

[[delivery.pools.ips]]
address = "203.0.113.10"
helo = "mta1.example.com"

[[delivery.pools]]
name = "bulk"
senders = ["news.example.com", ".promo.example.com"]
warmup_schedule = [200, 500, 1000]

[[delivery.pools.ips]]
address = "203.0.113.20"
helo = "bulk1.example.com"
warmup_start = "2026-10-01"

[[delivery.pools.ips]]
address = "2001:db8::20"
helo = "bulk1.example.com"
`

// TestDeliveryPoolsDecodeInBothDecoders: the server reads config through
// pelletier here and BurntSushi in internal/smtp, and an array of tables
// nested in an array of tables is exactly where decoders disagree. A key
// that silently lands nowhere would leave mail unpooled with no error.
func TestDeliveryPoolsDecodeInBothDecoders(t *testing.T) {
	check := func(t *testing.T, d *smtp.DeliveryConfig) {
		t.Helper()
		if d == nil || len(d.Pools) != 2 {
			t.Fatalf("pools did not decode: %+v", d)
		}
		if d.DefaultPool != "transactional" || d.PoolStateFile != "/var/spool/elemta/pool-state.json" {
			t.Errorf("default_pool/pool_state_file = %q/%q", d.DefaultPool, d.PoolStateFile)
		}
		bulk := d.Pools[1]
		if bulk.Name != "bulk" || len(bulk.Senders) != 2 || len(bulk.WarmupSchedule) != 3 || len(bulk.IPs) != 2 {
			t.Fatalf("bulk pool = %+v", bulk)
		}
		if ip := bulk.IPs[0]; ip.Address != "203.0.113.20" || ip.Helo != "bulk1.example.com" || ip.WarmupStart != "2026-10-01" {
			t.Errorf("bulk ip = %+v", ip)
		}
		if ip := d.Pools[0].IPs[0]; ip.Address != "203.0.113.10" || ip.Helo != "mta1.example.com" {
			t.Errorf("transactional ip = %+v", ip)
		}
	}

	t.Run("pelletier", func(t *testing.T) {
		var cfg Config
		if err := pelletier.Unmarshal([]byte(poolsTOML), &cfg); err != nil {
			t.Fatal(err)
		}
		check(t, cfg.Delivery)
	})
	t.Run("burntsushi", func(t *testing.T) {
		var cfg smtp.Config
		if _, err := toml.Decode(poolsTOML, &cfg); err != nil {
			t.Fatal(err)
		}
		check(t, cfg.Delivery)
	})
}

func TestValidateDeliveryRejectsBadPools(t *testing.T) {
	var cfg Config
	if err := pelletier.Unmarshal([]byte(poolsTOML), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Delivery.DefaultPool = "missing"

	result := &ValidationResult{Valid: true}
	cfg.validateDelivery(result, NewSecurityValidator())
	found := false
	for _, e := range result.Errors {
		if e.Field == "delivery.pools" && strings.Contains(e.Message, "missing") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unknown default_pool passed validation: %+v", result.Errors)
	}
}

const providersTOML = `
[delivery]
mode = "smtp"
provider_profiles = true

[[delivery.providers]]
name = "gmail"
max_connections = 5
throttled_messages_per_minute = 30
throttle_signals = ["custom signal"]
throttle_backoff = 600

[[delivery.providers]]
name = "yahoo"
disabled = true

[[delivery.providers]]
name = "corp"
mx_suffixes = ["mx.corp.example"]
max_messages_per_minute = 100
`

func TestDeliveryProvidersDecodeInBothDecoders(t *testing.T) {
	check := func(t *testing.T, d *smtp.DeliveryConfig) {
		t.Helper()
		if d == nil || len(d.Providers) != 3 || !d.ProviderProfilesEnabled() {
			t.Fatalf("providers did not decode: %+v", d)
		}
		g := d.Providers[0]
		if g.Name != "gmail" || g.MaxConnections != 5 || g.ThrottledMessagesPerMinute != 30 ||
			len(g.ThrottleSignals) != 1 || g.ThrottleBackoff != 600 {
			t.Errorf("gmail = %+v", g)
		}
		if !d.Providers[1].Disabled {
			t.Error("yahoo disabled did not decode")
		}
		if c := d.Providers[2]; len(c.MXSuffixes) != 1 || c.MaxMessagesPerMinute != 100 {
			t.Errorf("corp = %+v", c)
		}
	}
	t.Run("pelletier", func(t *testing.T) {
		var cfg Config
		if err := pelletier.Unmarshal([]byte(providersTOML), &cfg); err != nil {
			t.Fatal(err)
		}
		check(t, cfg.Delivery)
	})
	t.Run("burntsushi", func(t *testing.T) {
		var cfg smtp.Config
		if _, err := toml.Decode(providersTOML, &cfg); err != nil {
			t.Fatal(err)
		}
		check(t, cfg.Delivery)
	})

	off := false
	if (&smtp.DeliveryConfig{ProviderProfiles: &off}).ProviderProfilesEnabled() {
		t.Error("provider_profiles = false did not turn profiles off")
	}
	if !(*smtp.DeliveryConfig)(nil).ProviderProfilesEnabled() {
		t.Error("profiles should be on when [delivery] is absent")
	}
}

func TestValidateDeliveryRejectsBadProviders(t *testing.T) {
	cfg := Config{Delivery: &smtp.DeliveryConfig{Providers: []queue.ProviderConfig{{Name: "corp"}}}}
	result := &ValidationResult{Valid: true}
	cfg.validateDelivery(result, NewSecurityValidator())
	for _, e := range result.Errors {
		if e.Field == "delivery.providers" {
			return
		}
	}
	t.Errorf("a custom provider without mx_suffixes passed validation: %+v", result.Errors)
}
