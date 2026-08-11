package commands

import (
	"testing"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/dkim"
	"github.com/busybox42/elemta/internal/smtp"
)

func TestConvertToAPIMainConfig_PropagatesAuthLegacyHashPolicy(t *testing.T) {
	allowDeprecated := false
	cfg := config.DefaultConfig()
	cfg.Auth = &smtp.AuthConfig{AllowDeprecatedSHA1: &allowDeprecated}

	mc := convertToAPIMainConfig(cfg)
	if mc == nil {
		t.Fatal("expected MainConfig")
	}
	if mc.AuthAllowDeprecatedSHA1 == nil {
		t.Fatal("expected AuthAllowDeprecatedSHA1 to be propagated")
	}
	if *mc.AuthAllowDeprecatedSHA1 {
		t.Fatal("expected propagated AuthAllowDeprecatedSHA1=false")
	}
}

func TestConvertToAPIMainConfig_PreparesMixedLegacyMailAuthForMigration(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.InboundAuth = &smtp.InboundAuthConfig{Enabled: true, EnforceDMARC: true, Timeout: 9}
	cfg.Plugins.SPF = &smtp.SPFPluginConfig{Enabled: false, Timeout: 3}
	cfg.DKIM = &dkim.Config{Enabled: true, Domains: []dkim.DomainConfig{{
		Domain: "legacy.example.com", Selector: "mail", PrivateKeyPath: "/run/legacy.key",
	}}}

	mc := convertToAPIMainConfig(cfg)
	if !mc.LegacyInboundAuth || !mc.LegacyDKIM {
		t.Fatalf("legacy migration flags = inbound:%t dkim:%t", mc.LegacyInboundAuth, mc.LegacyDKIM)
	}
	if mc.SPF == nil || mc.SPF.Enabled || mc.SPF.Timeout != 3 {
		t.Errorf("explicit SPF plugin did not win: %+v", mc.SPF)
	}
	if mc.DMARC == nil || !mc.DMARC.Enabled || !mc.DMARC.Enforce || mc.DMARC.Timeout != 9 {
		t.Errorf("missing DMARC plugin did not inherit legacy aggregate: %+v", mc.DMARC)
	}
	if mc.DKIM == nil || !mc.DKIM.Enabled || !mc.DKIM.Verify || !mc.DKIM.Sign || len(mc.DKIM.Domains) != 1 {
		t.Errorf("legacy verification/signing did not merge: %+v", mc.DKIM)
	}
}
