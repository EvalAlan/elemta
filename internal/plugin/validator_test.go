package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginValidator_ValidateFileBasics(t *testing.T) {
	v := NewPluginValidator()

	t.Run("missing file produces error", func(t *testing.T) {
		result := &ValidationResult{Errors: []string{}, Warnings: []string{}}
		err := v.validateFileBasics(filepath.Join(t.TempDir(), "missing.so"), result)
		require.NoError(t, err)
		require.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0], "Plugin file not found")
	})

	t.Run("wrong extension produces error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "plugin.txt")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

		result := &ValidationResult{Errors: []string{}, Warnings: []string{}}
		err := v.validateFileBasics(path, result)
		require.NoError(t, err)
		assert.Contains(t, result.Errors, "Plugin file must have .so extension")
	})

	t.Run("oversized file produces error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "plugin.so")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

		v2 := NewPluginValidator()
		v2.maxFileSize = 2 // force the small file to exceed the limit
		result := &ValidationResult{Errors: []string{}, Warnings: []string{}}
		err := v2.validateFileBasics(path, result)
		require.NoError(t, err)
		found := false
		for _, e := range result.Errors {
			if strings.Contains(e, "too large") {
				found = true
			}
		}
		assert.True(t, found, "expected a 'too large' error, got: %v", result.Errors)
	})

	t.Run("valid .so file computes hash and no errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "plugin.so")
		require.NoError(t, os.WriteFile(path, []byte("plugin-binary-data"), 0o600))

		result := &ValidationResult{Errors: []string{}, Warnings: []string{}}
		err := v.validateFileBasics(path, result)
		require.NoError(t, err)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.FileHash)
		assert.Equal(t, int64(len("plugin-binary-data")), result.FileSize)
	})
}

func TestPluginValidator_CalculateFileHash(t *testing.T) {
	v := NewPluginValidator()

	t.Run("path traversal is rejected", func(t *testing.T) {
		_, err := v.calculateFileHash("../etc/passwd.so")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})

	t.Run("hash is deterministic for same content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "a.so")
		require.NoError(t, os.WriteFile(path, []byte("hello world"), 0o600))

		h1, err := v.calculateFileHash(path)
		require.NoError(t, err)
		h2, err := v.calculateFileHash(path)
		require.NoError(t, err)
		assert.Equal(t, h1, h2)
		assert.Len(t, h1, 64) // sha256 hex length
	})

	t.Run("different content yields different hash", func(t *testing.T) {
		dir := t.TempDir()
		path1 := filepath.Join(dir, "a.so")
		path2 := filepath.Join(dir, "b.so")
		require.NoError(t, os.WriteFile(path1, []byte("content-a"), 0o600))
		require.NoError(t, os.WriteFile(path2, []byte("content-b"), 0o600))

		h1, err := v.calculateFileHash(path1)
		require.NoError(t, err)
		h2, err := v.calculateFileHash(path2)
		require.NoError(t, err)
		assert.NotEqual(t, h1, h2)
	})

	t.Run("nonexistent file errors", func(t *testing.T) {
		_, err := v.calculateFileHash(filepath.Join(t.TempDir(), "nope.so"))
		require.Error(t, err)
	})
}

func TestPluginValidator_ValidateSecurity(t *testing.T) {
	t.Run("hash mismatch with enforcement produces error", func(t *testing.T) {
		v := NewPluginValidator()
		v.enforceSignatures = true
		v.trustedHashes["myplugin"] = "expectedhash123"

		dir := t.TempDir()
		path := filepath.Join(dir, "myplugin.so")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

		result := &ValidationResult{FileHash: "actualhash456", Errors: []string{}, Warnings: []string{}}
		err := v.validateSecurity(path, result)
		require.NoError(t, err)
		require.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0], "hash mismatch")
	})

	t.Run("hash mismatch without enforcement produces warning only", func(t *testing.T) {
		v := NewPluginValidator()
		v.enforceSignatures = false
		v.trustedHashes["myplugin"] = "expectedhash123"

		dir := t.TempDir()
		path := filepath.Join(dir, "myplugin.so")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

		result := &ValidationResult{FileHash: "actualhash456", Errors: []string{}, Warnings: []string{}}
		err := v.validateSecurity(path, result)
		require.NoError(t, err)
		assert.Empty(t, result.Errors)
		assert.NotEmpty(t, result.Warnings)
	})

	t.Run("unknown plugin name skips hash check", func(t *testing.T) {
		v := NewPluginValidator()
		dir := t.TempDir()
		path := filepath.Join(dir, "unknownplugin.so")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

		result := &ValidationResult{FileHash: "anything", Errors: []string{}, Warnings: []string{}}
		err := v.validateSecurity(path, result)
		require.NoError(t, err)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Warnings)
	})
}

func TestPluginValidator_SetDevelopmentMode(t *testing.T) {
	v := NewPluginValidator()

	v.SetDevelopmentMode(true)
	assert.True(t, v.developmentMode)
	assert.False(t, v.enforceSignatures)

	v.SetDevelopmentMode(false)
	assert.False(t, v.developmentMode)
	assert.True(t, v.enforceSignatures)
}

func TestPluginValidator_UpdateTrustedHash(t *testing.T) {
	v := NewPluginValidator()
	v.UpdateTrustedHash("newplugin", "abcdef1234567890abcdef1234567890")
	assert.Equal(t, "abcdef1234567890abcdef1234567890", v.trustedHashes["newplugin"])
}

func TestPluginValidator_GetValidationSummary(t *testing.T) {
	v := NewPluginValidator()
	summary := v.GetValidationSummary()

	assert.Equal(t, v.maxFileSize, summary["max_file_size"])
	assert.Equal(t, v.enforceSignatures, summary["enforce_signatures"])
	assert.Equal(t, v.developmentMode, summary["development_mode"])
	assert.Equal(t, len(v.trustedHashes), summary["trusted_plugins"])
	assert.Equal(t, len(v.allowedSymbols), summary["allowed_symbols"])
	assert.Equal(t, len(v.forbiddenSymbols), summary["forbidden_symbols"])
}

func TestPluginValidator_ValidateDependencies(t *testing.T) {
	v := NewPluginValidator()
	result := &ValidationResult{Errors: []string{}, Warnings: []string{}}
	err := v.validateDependencies("anything.so", result)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Warnings)
}
