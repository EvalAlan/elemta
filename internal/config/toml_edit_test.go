package config

import (
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// These tests exist because the previous approach to writing configuration
// back — rebuild from DefaultConfig(), re-serialise with SaveConfig — dropped
// every section SaveConfig does not emit. Toggling the rate limiter in the web
// UI removed [antivirus] and [antispam] entirely and reset queue.backend from
// sqlite to file, which points the server at a different queue and orphans the
// mail already in it.
//
// The invariant here is narrow and absolute: changing one key must not change
// any other byte of the document.

const sampleTOML = `# Elemta configuration
hostname = "mail.example.com"
listen_addr = ":2525"
local_domains = ["example.com"]

[queue]
backend = "sqlite"   # deliberately not the default
dir = "/var/spool/elemta"

[antivirus]
enabled = true
reject_on_failure = false

[antivirus.clamav]
enabled = true
address = "clamav.internal:3310"

[rate_limiter]
enabled = true
max_messages_per_minute = 300
`

func TestSetTOMLValueChangesOnlyTheTargetKey(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "rate_limiter", "enabled", false)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "[rate_limiter]\nenabled = false") {
		t.Errorf("target key was not updated:\n%s", got)
	}
	// Everything the old writer destroyed must still be here.
	for _, must := range []string{
		`backend = "sqlite"`,
		"[antivirus]",
		"[antivirus.clamav]",
		`address = "clamav.internal:3310"`,
		"# Elemta configuration",
		"# deliberately not the default",
		`local_domains = ["example.com"]`,
		"max_messages_per_minute = 300",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("writing one key destroyed %q:\n%s", must, got)
		}
	}
}

func TestSetTOMLValueUpdatesNestedSections(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "antivirus.clamav", "enabled", false)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "[antivirus.clamav]\nenabled = false") {
		t.Errorf("nested key not updated:\n%s", got)
	}
	// The parent section's own "enabled" must be untouched.
	if !strings.Contains(got, "[antivirus]\nenabled = true") {
		t.Errorf("parent section was modified by a nested write:\n%s", got)
	}
}

func TestSetTOMLValueAddsMissingKeyToExistingSection(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "antivirus", "scan_limit", 26214400)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "scan_limit = 26214400") {
		t.Errorf("missing key was not added:\n%s", got)
	}
	// It must land inside [antivirus], not after [antivirus.clamav].
	av := strings.Index(got, "[antivirus]")
	clam := strings.Index(got, "[antivirus.clamav]")
	scan := strings.Index(got, "scan_limit")
	if !(av < scan && scan < clam) {
		t.Errorf("key landed outside its section (antivirus=%d scan=%d clamav=%d):\n%s", av, scan, clam, got)
	}
}

func TestSetTOMLValueCreatesMissingSection(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "antispam", "reject_on_spam", true)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "[antispam]") || !strings.Contains(got, "reject_on_spam = true") {
		t.Errorf("missing section was not created:\n%s", got)
	}
	if !strings.Contains(got, "[antivirus]") {
		t.Errorf("creating a section destroyed another:\n%s", got)
	}
}

func TestSetTOMLValueUpdatesTopLevelKeys(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "", "hostname", "relay.example.net")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, `hostname = "relay.example.net"`) {
		t.Errorf("top-level key not updated:\n%s", got)
	}
	if strings.Contains(got, `hostname = "mail.example.com"`) {
		t.Errorf("old value left behind:\n%s", got)
	}
	// A top-level write must not leak into a section.
	if !strings.Contains(got, `backend = "sqlite"`) {
		t.Errorf("top-level write disturbed [queue]:\n%s", got)
	}
}

func TestSetTOMLValuePreservesTrailingComments(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "queue", "backend", "postgres")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, `backend = "postgres"   # deliberately not the default`) &&
		!strings.Contains(got, `backend = "postgres" # deliberately not the default`) {
		t.Errorf("trailing comment lost:\n%s", got)
	}
}

func TestSetTOMLValueRejectsUnsupportedTypes(t *testing.T) {
	if _, err := SetTOMLValue([]byte(sampleTOML), "queue", "backend", map[string]string{"a": "b"}); err == nil {
		t.Error("an unsupported value type must be an error, not a guess that corrupts the file")
	}
}

func TestSetTOMLValueRoundTripsThroughTheParser(t *testing.T) {
	out, err := SetTOMLValue([]byte(sampleTOML), "antivirus", "enabled", false)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	// The result must still be valid TOML with the expected values.
	var probe struct {
		Hostname string `toml:"hostname"`
		Queue    struct {
			Backend string `toml:"backend"`
		} `toml:"queue"`
		Antivirus struct {
			Enabled bool `toml:"enabled"`
		} `toml:"antivirus"`
	}
	if err := decodeTOMLForTest(out, &probe); err != nil {
		t.Fatalf("result is not valid TOML: %v\n%s", err, out)
	}
	if probe.Antivirus.Enabled {
		t.Error("antivirus.enabled was not set to false")
	}
	if probe.Queue.Backend != "sqlite" {
		t.Errorf("queue.backend = %q, want sqlite (unrelated value changed)", probe.Queue.Backend)
	}
	if probe.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q, want mail.example.com", probe.Hostname)
	}
}

// decodeTOMLForTest decodes with the same library the server uses, so the test
// checks the document against the real parser rather than a lookalike.
func decodeTOMLForTest(doc []byte, v interface{}) error {
	return toml.Unmarshal(doc, v)
}
