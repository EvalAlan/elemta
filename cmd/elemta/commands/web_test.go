package commands

import (
	"testing"

	"github.com/busybox42/elemta/internal/config"
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
