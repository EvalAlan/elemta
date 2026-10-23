package config

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestAPITrustedProxies(t *testing.T) {
	var cfg Config
	data := []byte("[api.rate_limit]\ntrusted_proxies = [\"10.42.0.0/16\", \"192.0.2.10\"]\n")
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.API.RateLimit.TrustedProxies; len(got) != 2 || got[0] != "10.42.0.0/16" || got[1] != "192.0.2.10" {
		t.Fatalf("decoded %v", got)
	}

	result := &ValidationResult{Valid: true}
	cfg.validateAPI(result)
	if !result.Valid {
		t.Errorf("valid entries refused: %v", result.Errors)
	}

	// Silently skipped, a typo would leave the proxy untrusted and every
	// client sharing its address, so it must fail loudly.
	cfg.API.RateLimit.TrustedProxies = []string{"10.42.0.0/33"}
	result = &ValidationResult{Valid: true}
	cfg.validateAPI(result)
	if result.Valid {
		t.Error("an invalid CIDR was accepted")
	}
}
