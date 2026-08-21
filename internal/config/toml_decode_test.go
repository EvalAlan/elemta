package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/smtp"

	toml "github.com/pelletier/go-toml/v2"
)

// decodeConfigFile mirrors the TOML decode step inside LoadConfig, without the
// path and filesystem validation around it. That decode is what matters here:
// it is the step that runs against operator-supplied config in production.
func decodeConfigFile(t *testing.T, path string) error {
	t.Helper()

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	cfg := &Config{TLS: &smtp.TLSConfig{}}
	return toml.Unmarshal(data, cfg)
}

// TestShippedConfigsDecode decodes every TOML file under config/ with the same
// library the server uses.
//
// This exists because a change to config/elemta.toml once put every container
// into a restart loop. The value was validated against BurntSushi/toml, which
// internal/smtp uses, while the server actually loads config through
// pelletier/go-toml here — and the two disagree about time.Duration. The unit
// tests and the full suite stayed green the whole time, because nothing in the
// suite ever decoded the shipped files.
func TestShippedConfigsDecode(t *testing.T) {
	root := filepath.Join("..", "..", "config")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("config directory not available: %v", err)
	}

	var found int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".toml" {
			continue
		}
		found++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			if err := decodeConfigFile(t, filepath.Join(root, name)); err != nil {
				t.Errorf("shipped config %s does not decode: %v", name, err)
			}
		})
	}
	if found == 0 {
		t.Fatal("no shipped .toml configs were found to check")
	}
}

// TestMemoryMonitoringIntervalIsSeconds pins the representation both TOML
// decoders agree on, and that it resolves to the interval the operator meant
// rather than to nanoseconds.
func TestMemoryMonitoringIntervalIsSeconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "elemta.toml")
	contents := "[memory]\nmonitoring_interval = 5\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	cfg := &Config{TLS: &smtp.TLSConfig{}}
	if err := toml.Unmarshal(data, cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatalf("ToSMTPConfig: %v", err)
	}
	out.Memory.ApplyDefaults()

	if out.Memory.MonitoringInterval != 5*time.Second {
		t.Errorf("monitoring_interval = 5 should resolve to 5s, got %v",
			out.Memory.MonitoringInterval)
	}
}

// TestMemoryConfigDecodesWithBurntSushi covers the other decoder. smtp.LoadConfig
// reads the same keys with BurntSushi/toml, so the representation has to be
// valid for both or the two config paths diverge again.
func TestMemoryConfigDecodesWithBurntSushi(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smtp.toml")
	contents := "hostname = \"mail.example.com\"\n" +
		"queue_dir = " + strconvQuote(filepath.Join(dir, "queue")) + "\n\n" +
		"[memory]\nmonitoring_interval = 5\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := smtp.LoadConfig(path)
	if err != nil {
		t.Fatalf("smtp.LoadConfig: %v", err)
	}
	if cfg.Memory == nil {
		t.Fatal("memory config was not decoded")
	}
	cfg.Memory.ApplyDefaults()
	if cfg.Memory.MonitoringInterval != 5*time.Second {
		t.Errorf("monitoring_interval = 5 should resolve to 5s, got %v",
			cfg.Memory.MonitoringInterval)
	}
}

func strconvQuote(s string) string { return "\"" + s + "\"" }
