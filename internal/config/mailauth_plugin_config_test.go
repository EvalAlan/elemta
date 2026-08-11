package config

import (
	"strings"
	"testing"

	"github.com/busybox42/elemta/internal/dkim"
	"github.com/busybox42/elemta/internal/smtp"
	toml "github.com/pelletier/go-toml/v2"
)

func TestMailAuthPluginTablesReachSMTPConfig(t *testing.T) {
	doc := []byte(`
[plugins.spf]
enabled = true
timeout = 4

[plugins.dkim]
enabled = true
verify = true
sign = true
header_canonicalization = "relaxed"
body_canonicalization = "simple"
domains = [{ domain = "example.com", selector = "mail", private_key_path = "/run/mail.key" }]

[plugins.dmarc]
enabled = true
enforce = false
timeout = 6

`)
	var cfg Config
	if err := toml.Unmarshal(doc, &cfg); err != nil {
		t.Fatal(err)
	}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	if out.Plugins == nil || out.Plugins.SPF == nil || out.Plugins.DKIM == nil || out.Plugins.DMARC == nil {
		t.Fatalf("mail-auth plugins were not mapped: %+v", out.Plugins)
	}
	if !out.Plugins.SPF.Enabled || out.Plugins.SPF.Timeout != 4 {
		t.Errorf("SPF = %+v", out.Plugins.SPF)
	}
	if out.DKIM == nil || !out.DKIM.Enabled || len(out.DKIM.Domains) != 1 {
		t.Errorf("outbound DKIM = %+v", out.DKIM)
	}
}

func TestMailAuthLegacyAndPluginConflictIsRejected(t *testing.T) {
	cfg := &Config{
		InboundAuth: &smtp.InboundAuthConfig{Enabled: true},
	}
	cfg.Plugins.SPF = &smtp.SPFPluginConfig{Enabled: true}
	if _, err := cfg.ToSMTPConfig(); err == nil || !strings.Contains(err.Error(), "both legacy") {
		t.Fatalf("expected legacy inbound conflict, got %v", err)
	}

	cfg = &Config{DKIM: &dkim.Config{Enabled: true}}
	cfg.Plugins.DKIM = &smtp.DKIMPluginConfig{Enabled: true, Sign: true}
	if _, err := cfg.ToSMTPConfig(); err == nil || !strings.Contains(err.Error(), "both legacy") {
		t.Fatalf("expected legacy DKIM conflict, got %v", err)
	}
}

func TestMailAuthPluginValidationRejectsImpossibleRuntime(t *testing.T) {
	cfg := &Config{}
	cfg.Plugins.DKIM = &smtp.DKIMPluginConfig{
		Enabled: true, Sign: true, HeaderCanonicalization: "invented",
	}
	cfg.Plugins.DMARC = &smtp.DMARCPluginConfig{Enabled: true, Timeout: 301}
	result := &ValidationResult{Valid: true}
	cfg.validateMailAuthPlugins(result)
	if result.Valid {
		t.Fatal("invalid mail-auth plugin configuration passed validation")
	}
	joined := make([]string, 0, len(result.Errors))
	for _, validationErr := range result.Errors {
		joined = append(joined, validationErr.Field)
	}
	fields := strings.Join(joined, " ")
	for _, want := range []string{
		"plugins.dkim.header_canonicalization",
		"plugins.dkim.domains",
		"plugins.dmarc.timeout",
		"plugins.dmarc",
	} {
		if !strings.Contains(fields, want) {
			t.Errorf("missing validation for %s: %s", want, fields)
		}
	}
}
