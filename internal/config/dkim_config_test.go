package config

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// TestDKIMConfigParsing verifies the [dkim] TOML section unmarshals into the
// Config struct, including per-domain selectors, key paths and header overrides.
func TestDKIMConfigParsing(t *testing.T) {
	const cfgTOML = `
hostname = "mail.example.com"

[dkim]
enabled = true
header_canonicalization = "relaxed"
body_canonicalization = "relaxed"

  [[dkim.domains]]
  domain = "example.com"
  selector = "mail"
  private_key_path = "/etc/elemta/dkim/example.com.key"

  [[dkim.domains]]
  domain = "example.net"
  selector = "s2026"
  private_key_path = "/etc/elemta/dkim/example.net.key"
  headers_to_sign = ["From", "Subject", "Date"]
`

	var cfg Config
	if err := toml.Unmarshal([]byte(cfgTOML), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.DKIM == nil {
		t.Fatal("DKIM section not parsed")
	}
	if !cfg.DKIM.Enabled {
		t.Fatal("expected DKIM enabled")
	}
	if cfg.DKIM.HeaderCanonicalization != "relaxed" || cfg.DKIM.BodyCanonicalization != "relaxed" {
		t.Fatalf("canonicalization = %q/%q", cfg.DKIM.HeaderCanonicalization, cfg.DKIM.BodyCanonicalization)
	}
	if len(cfg.DKIM.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(cfg.DKIM.Domains))
	}

	d0 := cfg.DKIM.Domains[0]
	if d0.Domain != "example.com" || d0.Selector != "mail" || d0.PrivateKeyPath != "/etc/elemta/dkim/example.com.key" {
		t.Fatalf("domain[0] parsed incorrectly: %+v", d0)
	}
	if len(d0.HeadersToSign) != 0 {
		t.Fatalf("domain[0] should have no header override, got %v", d0.HeadersToSign)
	}

	d1 := cfg.DKIM.Domains[1]
	if d1.Domain != "example.net" || d1.Selector != "s2026" {
		t.Fatalf("domain[1] parsed incorrectly: %+v", d1)
	}
	if want := []string{"From", "Subject", "Date"}; len(d1.HeadersToSign) != len(want) {
		t.Fatalf("domain[1] header override = %v, want %v", d1.HeadersToSign, want)
	}
}

// TestDKIMConfigAbsentIsNil confirms that omitting the section leaves DKIM nil
// (signing disabled) rather than producing a partially populated struct.
func TestDKIMConfigAbsentIsNil(t *testing.T) {
	var cfg Config
	if err := toml.Unmarshal([]byte(`hostname = "mail.example.com"`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DKIM != nil {
		t.Fatalf("expected nil DKIM when section absent, got %+v", cfg.DKIM)
	}
}
