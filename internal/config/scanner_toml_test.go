package config

import (
	"testing"

	burnt "github.com/BurntSushi/toml"
	pell "github.com/pelletier/go-toml/v2"

	"github.com/busybox42/elemta/internal/smtp"
)

// The scanner sections are decoded by two different TOML libraries depending on
// the entry point: internal/smtp uses BurntSushi, internal/config uses
// pelletier. Neither maps an underscored key onto a Go field by name — a key
// like `scan_limit` only reaches ScanLimit through an explicit toml tag.
//
// The nested scanner structs originally carried json tags only, while their
// parents carried both. The result was that `enabled`, `address`, `timeout` and
// `threshold` worked (single words match the field name case-insensitively) but
// `scan_limit` and `api_key` were accepted and silently discarded. An operator
// capping scan size, or pointing at a password-protected Rspamd, got the
// default instead with nothing logged.
//
// This runs the same document through both decoders so the two cannot drift.

const scannerTOML = `
[antivirus]
enabled = true
reject_on_failure = true

[antivirus.clamav]
enabled = true
address = "clamav.internal:3310"
timeout = 45
scan_limit = 26214400

[antispam]
enabled = true
reject_on_spam = true

[antispam.rspamd]
enabled = true
address = "http://rspamd.internal:11333"
timeout = 20
threshold = 7.5
scan_limit = 1048576
api_key = "s3cret"

[antispam.spamassassin]
enabled = true
address = "spamd.internal:783"
timeout = 15
threshold = 5.0
scan_limit = 2097152
`

type scannerSections struct {
	Antivirus *smtp.AntivirusConfig `toml:"antivirus"`
	Antispam  *smtp.AntispamConfig  `toml:"antispam"`
}

func checkScannerSections(t *testing.T, decoder string, s scannerSections) {
	t.Helper()

	if s.Antivirus == nil || s.Antivirus.ClamAV == nil {
		t.Fatalf("%s: antivirus section did not decode", decoder)
	}
	if s.Antispam == nil || s.Antispam.Rspamd == nil || s.Antispam.SpamAssassin == nil {
		t.Fatalf("%s: antispam section did not decode", decoder)
	}

	if !s.Antivirus.RejectOnFailure {
		t.Errorf("%s: reject_on_failure did not decode", decoder)
	}
	if !s.Antispam.RejectOnSpam {
		t.Errorf("%s: reject_on_spam did not decode", decoder)
	}

	clam := s.Antivirus.ClamAV
	if !clam.Enabled {
		t.Errorf("%s: clamav enabled did not decode", decoder)
	}
	if clam.Address != "clamav.internal:3310" {
		t.Errorf("%s: clamav address = %q, want clamav.internal:3310", decoder, clam.Address)
	}
	if clam.Timeout != 45 {
		t.Errorf("%s: clamav timeout = %d, want 45", decoder, clam.Timeout)
	}
	if clam.ScanLimit != 26214400 {
		t.Errorf("%s: clamav scan_limit = %d, want 26214400 (an unmapped key is silently ignored)",
			decoder, clam.ScanLimit)
	}

	rspamd := s.Antispam.Rspamd
	if rspamd.Address != "http://rspamd.internal:11333" {
		t.Errorf("%s: rspamd address = %q", decoder, rspamd.Address)
	}
	if rspamd.Timeout != 20 {
		t.Errorf("%s: rspamd timeout = %d, want 20", decoder, rspamd.Timeout)
	}
	if rspamd.Threshold != 7.5 {
		t.Errorf("%s: rspamd threshold = %v, want 7.5", decoder, rspamd.Threshold)
	}
	if rspamd.ScanLimit != 1048576 {
		t.Errorf("%s: rspamd scan_limit = %d, want 1048576", decoder, rspamd.ScanLimit)
	}
	if rspamd.APIKey != "s3cret" {
		t.Errorf("%s: rspamd api_key = %q, want s3cret (a dropped key means auth is silently absent)",
			decoder, rspamd.APIKey)
	}

	sa := s.Antispam.SpamAssassin
	if sa.Address != "spamd.internal:783" {
		t.Errorf("%s: spamassassin address = %q", decoder, sa.Address)
	}
	if sa.ScanLimit != 2097152 {
		t.Errorf("%s: spamassassin scan_limit = %d, want 2097152", decoder, sa.ScanLimit)
	}
	if sa.Threshold != 5.0 {
		t.Errorf("%s: spamassassin threshold = %v, want 5.0", decoder, sa.Threshold)
	}
}

func TestScannerConfigDecodesWithBurntSushi(t *testing.T) {
	var s scannerSections
	if _, err := burnt.Decode(scannerTOML, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	checkScannerSections(t, "burntsushi", s)
}

func TestScannerConfigDecodesWithPelletier(t *testing.T) {
	var s scannerSections
	if err := pell.Unmarshal([]byte(scannerTOML), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	checkScannerSections(t, "pelletier", s)
}
