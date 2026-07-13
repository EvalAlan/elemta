package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSecurityConfig(t *testing.T) {
	cfg := DefaultSecurityConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "moderate", cfg.Mode)
	assert.False(t, cfg.DevelopmentMode)
	assert.True(t, cfg.SignatureVerification.Enabled)
	// Signatures are not required by default: requiring them with no trusted
	// certificates configured would fail ValidateSecurityConfig, making the
	// default config invalid out of the box.
	assert.False(t, cfg.SignatureVerification.Required)
	assert.True(t, cfg.Sandboxing.Enabled)
	assert.Equal(t, int64(100), cfg.Sandboxing.MaxMemoryMB)

	// The default config must pass its own validation.
	assert.NoError(t, ValidateSecurityConfig(&cfg))
}

func TestDevelopmentSecurityConfig_RelaxesDefaults(t *testing.T) {
	dev := DevelopmentSecurityConfig()
	def := DefaultSecurityConfig()

	assert.True(t, dev.DevelopmentMode)
	assert.Equal(t, "permissive", dev.Mode)
	assert.False(t, dev.SignatureVerification.Required)
	assert.Greater(t, dev.Sandboxing.MaxMemoryMB, def.Sandboxing.MaxMemoryMB)
	assert.Greater(t, dev.Sandboxing.MaxCPUPercent, def.Sandboxing.MaxCPUPercent)
	assert.True(t, dev.Sandboxing.AllowFileSystem)
	assert.False(t, dev.Capabilities.RequireExplicitGrant)
}

func TestStrictSecurityConfig_TightensDefaults(t *testing.T) {
	strict := StrictSecurityConfig()
	def := DefaultSecurityConfig()

	assert.Equal(t, "strict", strict.Mode)
	assert.False(t, strict.DevelopmentMode)
	assert.Less(t, strict.Sandboxing.MaxMemoryMB, def.Sandboxing.MaxMemoryMB)
	assert.Less(t, strict.Sandboxing.MaxCPUPercent, def.Sandboxing.MaxCPUPercent)
	assert.False(t, strict.Sandboxing.AllowNetworkAccess)
	assert.True(t, strict.Sandboxing.EnableProcessIsolation)
	assert.Equal(t, 1, strict.AuditLogging.AlertThreshold)
	assert.Equal(t, 1, strict.HotReload.MaxReloadAttempts)
}

func TestGetSecurityConfigForMode(t *testing.T) {
	tests := []struct {
		mode         string
		wantMode     string
		wantDevMode  bool
		wantStrictSb bool
	}{
		{"strict", "strict", false, true},
		{"development", "permissive", true, false},
		{"dev", "permissive", true, false},
		{"moderate", "moderate", false, false},
		{"production", "moderate", false, false},
		{"unknown-garbage", "moderate", false, false},
		{"", "moderate", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := GetSecurityConfigForMode(tt.mode)
			assert.Equal(t, tt.wantMode, cfg.Mode)
			assert.Equal(t, tt.wantDevMode, cfg.DevelopmentMode)
		})
	}
}

func TestValidateSecurityConfig(t *testing.T) {
	t.Run("valid default config passes", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		require.NoError(t, ValidateSecurityConfig(&cfg))
	})

	t.Run("signature required without trusted certs errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Enabled = true
		cfg.SignatureVerification.Required = true
		cfg.SignatureVerification.TrustedCertificates = nil
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no trusted certificates")
	})

	t.Run("missing trusted certificate file errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Enabled = true
		cfg.SignatureVerification.Required = true
		cfg.SignatureVerification.TrustedCertificates = []string{"/nonexistent/cert.pem"}
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trusted certificate file not found")
	})

	t.Run("missing trusted key file errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Enabled = true
		cfg.SignatureVerification.Required = true
		cert := filepath.Join(t.TempDir(), "cert.pem")
		require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))
		cfg.SignatureVerification.TrustedCertificates = []string{cert}
		cfg.SignatureVerification.TrustedKeys = []string{"/nonexistent/key.pem"}
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trusted key file not found")
	})

	t.Run("invalid sandboxing memory errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Required = false
		cfg.Sandboxing.Enabled = true
		cfg.Sandboxing.MaxMemoryMB = 0
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max_memory_mb must be positive")
	})

	t.Run("invalid sandboxing cpu percent errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Required = false
		cfg.Sandboxing.Enabled = true
		cfg.Sandboxing.MaxCPUPercent = 150
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max_cpu_percent must be between 0 and 100")
	})

	t.Run("invalid sandboxing goroutines errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Required = false
		cfg.Sandboxing.Enabled = true
		cfg.Sandboxing.MaxGoroutines = 0
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max_goroutines must be positive")
	})

	t.Run("audit logging without log path errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Required = false
		cfg.AuditLogging.Enabled = true
		cfg.AuditLogging.LogPath = ""
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit log path is required")
	})

	t.Run("audit logging with invalid retention errors", func(t *testing.T) {
		cfg := DefaultSecurityConfig()
		cfg.SignatureVerification.Required = false
		cfg.AuditLogging.Enabled = true
		cfg.AuditLogging.RetentionDays = 0
		err := ValidateSecurityConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "retention_days must be positive")
	})
}

func TestLoadSecurityConfig(t *testing.T) {
	t.Run("missing file returns defaults", func(t *testing.T) {
		cfg, err := LoadSecurityConfig(filepath.Join(t.TempDir(), "nope.toml"))
		require.NoError(t, err)
		assert.Equal(t, "moderate", cfg.Mode)
	})

	t.Run("path traversal is rejected when the target file exists", func(t *testing.T) {
		// The check is a naive strings.Contains(path, ".."), so filepath.Join
		// must be avoided since it cleans ".." away before the check sees it.
		parent := t.TempDir()
		sub := filepath.Join(parent, "sub")
		require.NoError(t, os.MkdirAll(sub, 0o750))
		target := filepath.Join(parent, "evil.toml")
		require.NoError(t, os.WriteFile(target, []byte("mode = \"strict\""), 0o600))

		traversalPath := sub + "/../evil.toml"
		_, err := LoadSecurityConfig(traversalPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})

	t.Run("path traversal is rejected even when the target file does not exist", func(t *testing.T) {
		// The traversal check runs before the existence check, so a traversal
		// path never silently falls back to the default config.
		traversalPath := filepath.Join(t.TempDir(), "sub") + "/../nope.toml"
		_, err := LoadSecurityConfig(traversalPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})

	t.Run("round-trips through save and load", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "security.toml")

		original := DefaultSecurityConfig()
		original.Mode = "strict"
		original.Sandboxing.MaxMemoryMB = 42

		require.NoError(t, SaveSecurityConfig(&original, path))

		loaded, err := LoadSecurityConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "strict", loaded.Mode)
		assert.Equal(t, int64(42), loaded.Sandboxing.MaxMemoryMB)
	})

	t.Run("malformed TOML produces parse error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.toml")
		require.NoError(t, os.WriteFile(path, []byte("not = [valid toml"), 0o600))

		_, err := LoadSecurityConfig(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse TOML")
	})
}

func TestSecurityConfigManager(t *testing.T) {
	t.Run("new manager against missing file succeeds with defaults", func(t *testing.T) {
		// LoadSecurityConfig falls back to DefaultSecurityConfig() when the
		// config file doesn't exist, and the default config passes its own
		// validation, so a manager can be constructed against a fresh path.
		path := filepath.Join(t.TempDir(), "sec.toml")
		scm, err := NewSecurityConfigManager(path)
		require.NoError(t, err)
		assert.Equal(t, "moderate", scm.GetConfig().Mode)
	})

	t.Run("manager works when the on-disk config passes validation", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sec.toml")

		seed := DefaultSecurityConfig()
		require.NoError(t, SaveSecurityConfig(&seed, path))

		scm, err := NewSecurityConfigManager(path)
		require.NoError(t, err)
		assert.Equal(t, "moderate", scm.GetConfig().Mode)
	})

	t.Run("update config validates and persists", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sec.toml")

		seed := DefaultSecurityConfig()
		require.NoError(t, SaveSecurityConfig(&seed, path))

		scm, err := NewSecurityConfigManager(path)
		require.NoError(t, err)

		newCfg := DefaultSecurityConfig()
		newCfg.Mode = "strict"
		require.NoError(t, scm.UpdateConfig(&newCfg))
		assert.Equal(t, "strict", scm.GetConfig().Mode)

		// Reload from disk should reflect the persisted change
		require.NoError(t, scm.ReloadConfig())
		assert.Equal(t, "strict", scm.GetConfig().Mode)
	})

	t.Run("update config rejects invalid configuration", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sec.toml")

		seed := DefaultSecurityConfig()
		require.NoError(t, SaveSecurityConfig(&seed, path))

		scm, err := NewSecurityConfigManager(path)
		require.NoError(t, err)

		badCfg := DefaultSecurityConfig()
		badCfg.Sandboxing.Enabled = true
		badCfg.Sandboxing.MaxMemoryMB = -1
		err = scm.UpdateConfig(&badCfg)
		require.Error(t, err)
		// Original config should remain untouched
		assert.Equal(t, "moderate", scm.GetConfig().Mode)
	})
}
