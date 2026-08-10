package config

import (
	"reflect"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/dkim"
	"github.com/busybox42/elemta/internal/smtp"
)

// fieldsIntentionallyUnmapped lists smtp.Config fields that ToSMTPConfig
// deliberately leaves to ApplyDefaults or to another subsystem. Adding a field
// here is a conscious decision; forgetting a field is not.
var fieldsIntentionallyUnmapped = map[string]string{
	"Cache":                   "not exposed via TOML (json tags only)",
	"Rules":                   "not exposed via TOML (json tags only)",
	"KeepDeliveredMessages":   "consumed by the queue, not the SMTP server",
	"KeepMessageData":         "consumed by the queue, not the SMTP server",
	"QueuePriorityEnabled":    "not currently consumed",
	"MessageRetentionHours":   "not currently consumed",
	"ConnectTimeout":          "not currently consumed",
	"SMTPTimeout":             "not currently consumed",
	"MaxConnectionsPerDomain": "not currently consumed",
	"API":                     "API server is configured separately",
}

// TestToSMTPConfig_AllFieldsMapped is the guard rail for the bug class this
// conversion function was written to eliminate: a field added to smtp.Config
// that nobody remembers to populate, silently taking its zero value.
//
// It sets every mappable field of the source config to a non-zero value and
// asserts that the corresponding smtp.Config field is non-zero afterwards.
func TestToSMTPConfig_AllFieldsMapped(t *testing.T) {
	cfg := fullyPopulatedConfig()

	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}

	v := reflect.ValueOf(*out)
	typ := v.Type()

	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if reason, ok := fieldsIntentionallyUnmapped[name]; ok {
			t.Logf("skipping %s: %s", name, reason)
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("smtp.Config.%s is zero after ToSMTPConfig — field is not mapped. "+
				"Add it to ToSMTPConfig, or to fieldsIntentionallyUnmapped with a reason.", name)
		}
	}
}

// TestToSMTPConfig_StrictLineEndingsDefaultsToTrue pins the security-relevant
// default: an operator who says nothing gets RFC 5321 enforcement.
func TestToSMTPConfig_StrictLineEndingsDefaultsToTrue(t *testing.T) {
	cfg := &Config{}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}
	if !out.StrictLineEndingsEnabled() {
		t.Error("strict_line_endings must default to true when unset")
	}
}

// TestToSMTPConfig_StrictLineEndingsExplicitFalseIsHonoured makes sure the
// tri-state actually works — an explicit opt-out must survive ApplyDefaults.
func TestToSMTPConfig_StrictLineEndingsExplicitFalseIsHonoured(t *testing.T) {
	cfg := &Config{StrictLineEndings: smtp.BoolPtr(false)}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}
	if out.StrictLineEndingsEnabled() {
		t.Error("explicit strict_line_endings=false must be preserved")
	}
}

// TestToSMTPConfig_LegacyServerSectionFallback covers configs that only use the
// older [server] block rather than the flat top-level keys.
func TestToSMTPConfig_LegacyServerSectionFallback(t *testing.T) {
	cfg := &Config{}
	cfg.Server.Hostname = "legacy.example.com"
	cfg.Server.Listen = ":2626"
	cfg.Server.MaxSize = 1234
	cfg.Server.LocalDomains = []string{"legacy.example.com"}

	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}

	if out.Hostname != "legacy.example.com" {
		t.Errorf("hostname: got %q, want legacy.example.com", out.Hostname)
	}
	if out.ListenAddr != ":2626" {
		t.Errorf("listen addr: got %q, want :2626", out.ListenAddr)
	}
	if out.MaxSize != 1234 {
		t.Errorf("max size: got %d, want 1234", out.MaxSize)
	}
	if len(out.LocalDomains) != 1 || out.LocalDomains[0] != "legacy.example.com" {
		t.Errorf("local domains: got %v", out.LocalDomains)
	}
}

// TestToSMTPConfig_FlatKeysWinOverLegacy pins the precedence rule.
func TestToSMTPConfig_FlatKeysWinOverLegacy(t *testing.T) {
	cfg := &Config{Hostname: "flat.example.com", ListenAddr: ":2525", MaxSize: 999}
	cfg.Server.Hostname = "legacy.example.com"
	cfg.Server.Listen = ":2626"
	cfg.Server.MaxSize = 111

	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}
	if out.Hostname != "flat.example.com" || out.ListenAddr != ":2525" || out.MaxSize != 999 {
		t.Errorf("flat keys should win: got hostname=%q listen=%q max_size=%d",
			out.Hostname, out.ListenAddr, out.MaxSize)
	}
}

// TestSetListenAddr_UpdatesBothForms guards the --port flag regression: the
// override used to be written to Server.Listen while the mapping read
// ListenAddr, so the flag silently did nothing.
func TestSetListenAddr_UpdatesBothForms(t *testing.T) {
	cfg := &Config{ListenAddr: ":25"}
	cfg.Server.Listen = ":25"

	cfg.SetListenAddr(":2525")

	if got := cfg.EffectiveListenAddr(); got != ":2525" {
		t.Errorf("effective listen addr: got %q, want :2525", got)
	}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig returned error: %v", err)
	}
	if out.ListenAddr != ":2525" {
		t.Errorf("port override did not reach smtp.Config: got %q", out.ListenAddr)
	}
}

func TestToSMTPConfig_InvalidSessionTimeout(t *testing.T) {
	cfg := &Config{SessionTimeout: "not-a-duration"}
	if _, err := cfg.ToSMTPConfig(); err == nil {
		t.Error("expected an error for an unparseable session_timeout")
	}
}

// fullyPopulatedConfig builds a Config with every mappable field set to a
// non-zero value.
func fullyPopulatedConfig() *Config {
	cfg := &Config{
		Hostname:                  "mail.example.com",
		ListenAddr:                ":2525",
		QueueDir:                  "/var/spool/elemta",
		MaxSize:                   50 * 1024 * 1024,
		MaxWorkers:                8,
		MaxRetries:                7,
		MaxQueueTime:              3600,
		RetrySchedule:             []int{60, 300},
		SessionTimeout:            "5m",
		LocalDomains:              []string{"example.com"},
		AllowedRelays:             []string{"10.0.0.0/8"},
		FailedQueueRetentionHours: 48,
		StrictLineEndings:         smtp.BoolPtr(true),
		SpoolThresholdBytes:       int64Ptr(1 << 20),
		TrustedNetworks:           []string{"10.0.0.0/8"},
		TLS:                       &smtp.TLSConfig{Enabled: true},
		Auth:                      &smtp.AuthConfig{Enabled: true},
		Delivery:                  &smtp.DeliveryConfig{Mode: "smtp"},
		Metrics:                   &smtp.MetricsConfig{Enabled: true},
		Memory:                    smtp.DefaultMemoryConfig(),
		Resources:                 &smtp.ResourceConfig{MaxConnections: 100},
		AccessControl:             &smtp.AccessControlConfig{Enabled: true},
		RBL:                       &smtp.RBLConfig{Enabled: true, Zones: []string{"zen.example.org"}},
		Antivirus:                 &smtp.AntivirusConfig{Enabled: true},
		Antispam:                  &smtp.AntispamConfig{Enabled: true},
		DKIM:                      &dkim.Config{Enabled: true},
	}

	cfg.Server.DevMode = true
	cfg.Queue.Backend = "sqlite"
	cfg.Queue.Dir = "/var/spool/elemta"
	cfg.Queue.SQLite.Path = "/var/spool/elemta/queue.db"
	cfg.Queue.SQLite.BusyTimeoutMS = 5000
	cfg.Queue.SQLite.JournalMode = "WAL"
	cfg.Queue.SQLite.Synchronous = "NORMAL"
	cfg.Queue.Postgres.DSN = "postgres://localhost/elemta"
	cfg.Queue.Postgres.MaxOpenConns = 10
	cfg.Queue.Postgres.MaxIdleConns = 5
	cfg.Queue.Postgres.ConnMaxLifetimeSeconds = 300
	cfg.Queue.IndexedFS.IndexPath = "/var/spool/elemta/index"
	cfg.Queue.IndexedFS.ContentDir = "/var/spool/elemta/content"
	cfg.Queue.IndexedFS.SyncMode = "full"
	cfg.Queue.IndexedFS.RecoveryOnStartup = true
	cfg.QueueProcessor.Enabled = true
	cfg.QueueProcessor.Interval = 10
	cfg.QueueProcessor.Workers = 4
	cfg.Plugins.Directory = "/usr/lib/elemta/plugins"
	cfg.Plugins.Enabled = []string{"spf"}

	cfg.Timeouts = TimeoutConfig{
		SessionTimeout:    5 * time.Minute,
		CommandTimeout:    30 * time.Second,
		DataTimeout:       10 * time.Minute,
		ShutdownTimeout:   30 * time.Second,
		ConnectionTimeout: time.Minute,
		AuthTimeout:       30 * time.Second,
	}

	return cfg
}

func int64Ptr(v int64) *int64 { return &v }
