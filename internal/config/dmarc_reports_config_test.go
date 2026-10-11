package config

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestDMARCReportsTableReachesSMTPConfig(t *testing.T) {
	doc := []byte(`
[dmarc_reports]
enabled = true
organization_name = "Example Inc"
contact_email = "postmaster@example.com"
report_from = "dmarc-reports@example.com"
state_dir = "/var/lib/elemta"
`)
	var cfg Config
	if err := toml.Unmarshal(doc, &cfg); err != nil {
		t.Fatal(err)
	}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	d := out.DMARCReports
	if d == nil || !d.Enabled || d.OrganizationName != "Example Inc" || d.ContactEmail != "postmaster@example.com" ||
		d.ReportFrom != "dmarc-reports@example.com" || d.StateDir != "/var/lib/elemta" {
		t.Errorf("dmarc_reports = %+v", d)
	}
}

func TestDMARCReportsOffWhenUnconfigured(t *testing.T) {
	var cfg Config
	if err := toml.Unmarshal([]byte("hostname = \"mx.example.com\"\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	out, err := cfg.ToSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	if out.DMARCReports != nil && out.DMARCReports.Enabled {
		t.Error("DMARC reports enabled by a config that does not mention them")
	}
}
