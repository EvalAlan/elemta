package config

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// TestAPIAuthDefaultsOn guards the admin API default. A config that sets up
// [api] without mentioning auth_enabled used to get an unauthenticated API.
func TestAPIAuthDefaultsOn(t *testing.T) {
	if !DefaultConfig().API.AuthEnabled {
		t.Fatal("DefaultConfig().API.AuthEnabled = false, want true")
	}

	cfg := DefaultConfig()
	data := []byte("[api]\nenabled = true\nlisten_addr = \"0.0.0.0:8025\"\n")
	if err := toml.Unmarshal(data, cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !cfg.API.AuthEnabled {
		t.Error("config without auth_enabled decoded with auth off, want on")
	}

	cfg = DefaultConfig()
	if err := toml.Unmarshal([]byte("[api]\nauth_enabled = false\n"), cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.API.AuthEnabled {
		t.Error("explicit auth_enabled = false was not honoured")
	}
}
