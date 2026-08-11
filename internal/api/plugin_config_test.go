package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	toml "github.com/pelletier/go-toml/v2"
)

// These tests exist because the settings forms in the web UI were, until now,
// decoration: they rendered the current values, accepted changes, and had
// nowhere to send them. The endpoint read `enabled` and dropped everything
// else. So the cases below are mostly about the two ways that failure can come
// back — a value that is accepted and not stored, and a value that is stored
// and cannot be loaded again.

func testServerWithConfig(t *testing.T, doc string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "elemta.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return &Server{
		configPath: path,
		mainConfig: &MainConfig{
			Hostname:      "mail.example.com",
			Antivirus:     &ScannerStatus{Enabled: true, Address: "clam:3310", Timeout: 30, ScanLimit: 1024},
			Antispam:      &ScannerStatus{Enabled: true, Address: "http://rspamd:11333", Timeout: 30, Threshold: 6},
			AccessControl: &AccessControlStatus{},
			RBL:           &RBLStatus{Timeout: 5, CacheTTL: 3600, CacheSize: 10000},
			MassMailer:    &MassMailerStatus{DefaultRatePerMinute: 600},
			SPF:           &SPFStatus{Enabled: true, Timeout: 10},
			DKIM:          &DKIMStatus{Enabled: true, Verify: true, HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed"},
			DMARC:         &DMARCStatus{Enabled: true, Timeout: 10},
		},
	}, path
}

const pluginTestTOML = `hostname = "mail.example.com"
listen_addr = ":2525"

[antivirus]
enabled = true
reject_on_failure = false

[antivirus.clamav]
enabled = true
address = "clam:3310"
timeout = 30
scan_limit = 1024

[antispam]
enabled = true
reject_on_spam = false

[antispam.rspamd]
enabled = true
address = "http://rspamd:11333"
timeout = 30
threshold = 6.0
`

func updatePlugin(t *testing.T, s *Server, name string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/config/plugins/"+name, strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"plugin": name})
	rec := httptest.NewRecorder()
	s.handleUpdatePlugin(rec, req)
	return rec
}

// TestPluginSettingsReachTheConfigFile is the whole point: a value typed into
// the form must be readable from the file afterwards.
func TestPluginSettingsReachTheConfigFile(t *testing.T) {
	s, path := testServerWithConfig(t, pluginTestTOML)

	rec := updatePlugin(t, s, "rspamd", `{"config":{"address":"http://scanner.internal:11333","timeout":45,"threshold":4.5,"reject_on_spam":true}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update rejected: %d %s", rec.Code, rec.Body.String())
	}

	var probe struct {
		Antispam struct {
			Enabled      bool `toml:"enabled"`
			RejectOnSpam bool `toml:"reject_on_spam"`
			Rspamd       struct {
				Address   string  `toml:"address"`
				Timeout   int     `toml:"timeout"`
				Threshold float64 `toml:"threshold"`
			} `toml:"rspamd"`
		} `toml:"antispam"`
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := toml.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("config no longer parses: %v\n%s", err, raw)
	}

	if probe.Antispam.Rspamd.Address != "http://scanner.internal:11333" {
		t.Errorf("address = %q, want the value that was submitted", probe.Antispam.Rspamd.Address)
	}
	if probe.Antispam.Rspamd.Timeout != 45 {
		t.Errorf("timeout = %d, want 45", probe.Antispam.Rspamd.Timeout)
	}
	if probe.Antispam.Rspamd.Threshold != 4.5 {
		t.Errorf("threshold = %v, want 4.5", probe.Antispam.Rspamd.Threshold)
	}
	// reject_on_spam belongs to the stage, not the scanner. Written into
	// [antispam.rspamd] it would load without complaint and do nothing.
	if !probe.Antispam.RejectOnSpam {
		t.Error("reject_on_spam did not reach [antispam]")
	}
	// A settings-only update must not change enablement.
	if !probe.Antispam.Enabled {
		t.Error("a settings-only update turned the scanner off")
	}
}

// TestPluginSettingsRejectedValuesDoNotStick: a refused payload must leave both
// the file and the live config as they were. Applying field by field would
// half-write it.
func TestPluginSettingsRejectedValuesDoNotStick(t *testing.T) {
	s, path := testServerWithConfig(t, pluginTestTOML)
	before, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// The timeout is fine; the address is not. Neither may be applied.
	rec := updatePlugin(t, s, "clamav", `{"config":{"timeout":90,"address":"http://clam:3310"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a URL where host:port belongs should be refused, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "host:port") {
		t.Errorf("the error should say what to type instead, got %q", rec.Body.String())
	}
	if s.mainConfig.Antivirus.Timeout != 30 {
		t.Errorf("the valid half of a refused update was applied: timeout = %d", s.mainConfig.Antivirus.Timeout)
	}

	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a refused update rewrote the config file")
	}
}

func TestPluginSettingsValidation(t *testing.T) {
	cases := []struct {
		plugin string
		body   string
		why    string
	}{
		{"clamav", `{"config":{"timeout":0}}`, "a zero timeout is no timeout at all"},
		{"clamav", `{"config":{"timeout":0.5}}`, "a fractional timeout would truncate to zero"},
		{"clamav", `{"config":{"address":""}}`, "an empty address"},
		{"clamav", `{"config":{"address":"clam"}}`, "an address with no port"},
		{"clamav", `{"config":{"timeout":"30"}}`, "a number sent as text"},
		{"rspamd", `{"config":{"address":"rspamd:11333"}}`, "host:port where a URL belongs"},
		{"rspamd", `{"config":{"address":"http://rspamd:11333/"}}`, "a trailing slash, which would produce //checkv2"},
		{"rspamd", `{"config":{"address":"http://rspamd:11333/checkv2"}}`, "the endpoint path, which is appended already"},
		{"rspamd", `{"config":{"threshold":-1}}`, "a negative threshold"},
		{"access_control", `{"config":{"deny_ips":["10.0.0.0/33"]}}`, "an impossible prefix length"},
		{"access_control", `{"config":{"deny_ips":["not-an-address"]}}`, "a rule the server cannot parse at startup"},
		{"access_control", `{"config":{"deny_domains":["spammer@example.com"]}}`, "an address where a domain belongs"},
		{"access_control", `{"config":{"deny_domains":["com"]}}`, "a bare label that would never match"},
		{"access_control", `{"config":{"deny_ips":"10.0.0.0/8"}}`, "a list sent as a single string"},
		{"rbl", `{"config":{"zones":["http://zen.example.org"]}}`, "a URL where a zone belongs"},
		{"rbl", `{"config":{"zones":["notadomain"]}}`, "a bare label that can never match"},
		{"rbl", `{"config":{"cache_size":0}}`, "an unbounded cache keyed by peer address"},
		{"rbl", `{"config":{"timeout":600}}`, "a timeout long enough to stall every session"},
		{"rbl", `{"config":{"skip_ips":["nope"]}}`, "a skip rule the server cannot parse"},
		{"mass_mailer", `{"config":{"default_rate_per_minute":0}}`, "an unbounded default rate"},
		{"spf", `{"config":{"timeout":0}}`, "an unbounded SPF lookup"},
		{"dkim", `{"config":{"header_canonicalization":"invented"}}`, "an unknown DKIM canonicalization"},
		{"dkim", `{"config":{"sign":true,"domains":[]}}`, "DKIM signing with no key"},
		{"rate_limiter", `{"config":{"max_messages_per_minute":10}}`, "a plugin edited through its own panel"},
		{"nonesuch", `{"config":{"anything":1}}`, "a plugin that does not exist"},
	}

	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			s, _ := testServerWithConfig(t, pluginTestTOML)
			rec := updatePlugin(t, s, tc.plugin, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s should be refused, got %d %s", tc.why, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMailAuthPluginSettingsPersistAsTypedTables(t *testing.T) {
	s, path := testServerWithConfig(t, pluginTestTOML)
	rec := updatePlugin(t, s, "dkim", `{"enabled":true,"config":{"verify":true,"sign":true,"domains":[{"domain":"pass.auth.test","selector":"mail","private_key_path":"/run/keys/mail.key","headers_to_sign":["From","Subject"]}]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("DKIM update rejected: %d %s", rec.Code, rec.Body.String())
	}
	var probe struct {
		Plugins struct {
			DKIM struct {
				Enabled bool `toml:"enabled"`
				Sign    bool `toml:"sign"`
				Domains []struct {
					Domain         string `toml:"domain"`
					Selector       string `toml:"selector"`
					PrivateKeyPath string `toml:"private_key_path"`
				} `toml:"domains"`
			} `toml:"dkim"`
		} `toml:"plugins"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("persisted config does not parse: %v\n%s", err, raw)
	}
	if !probe.Plugins.DKIM.Enabled || !probe.Plugins.DKIM.Sign || len(probe.Plugins.DKIM.Domains) != 1 {
		t.Fatalf("DKIM config did not survive: %+v", probe.Plugins.DKIM)
	}
	if probe.Plugins.DKIM.Domains[0].PrivateKeyPath != "/run/keys/mail.key" {
		t.Errorf("DKIM key path = %q", probe.Plugins.DKIM.Domains[0].PrivateKeyPath)
	}
}

func TestMailAuthPluginWriteMigratesLegacyTables(t *testing.T) {
	const legacy = `hostname = "mail.example.com"

[inbound_auth]
enabled = true
enforce_dmarc = false

[dkim]
enabled = true

[[dkim.domains]]
domain = "legacy.example.com"
selector = "mail"
private_key_path = "/run/keys/legacy.key"

# This comment belongs to queue and must survive migration.
[queue]
backend = "sqlite"
`
	s, path := testServerWithConfig(t, legacy)
	s.mainConfig.LegacyInboundAuth = true
	s.mainConfig.LegacyDKIM = true
	s.mainConfig.DKIM.Sign = true
	s.mainConfig.DKIM.Domains = []SigningDomainStatus{{
		Domain: "legacy.example.com", Selector: "mail", PrivateKeyPath: "/run/keys/legacy.key",
	}}

	rec := updatePlugin(t, s, "spf", `{"config":{"timeout":12}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("SPF update rejected: %d %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	if strings.Contains(doc, "[inbound_auth]") || strings.Contains(doc, "[dkim]") || strings.Contains(doc, "[[dkim.domains]]") {
		t.Fatalf("legacy tables survived the dashboard migration:\n%s", doc)
	}
	for _, want := range []string{"[plugins.spf]", "[plugins.dkim]", "# This comment belongs to queue", `backend = "sqlite"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("migration removed %q:\n%s", want, doc)
		}
	}
	var probe struct {
		Plugins struct {
			SPF struct {
				Enabled bool `toml:"enabled"`
				Timeout int  `toml:"timeout"`
			} `toml:"spf"`
			DKIM struct {
				Enabled bool `toml:"enabled"`
				Sign    bool `toml:"sign"`
			} `toml:"dkim"`
		} `toml:"plugins"`
		Queue struct {
			Backend string `toml:"backend"`
		} `toml:"queue"`
	}
	if err := toml.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("migrated config does not parse: %v\n%s", err, raw)
	}
	if !probe.Plugins.SPF.Enabled || probe.Plugins.SPF.Timeout != 12 || !probe.Plugins.DKIM.Enabled || !probe.Plugins.DKIM.Sign {
		t.Errorf("canonical plugin settings were not retained: %+v", probe.Plugins)
	}
	if probe.Queue.Backend != "sqlite" {
		t.Errorf("queue backend changed to %q", probe.Queue.Backend)
	}
}

func TestDisablingOutboundAuthOperationsReportsRestart(t *testing.T) {
	cases := []struct {
		plugin string
		body   string
		setup  func(*MainConfig)
	}{
		{
			plugin: "dkim",
			body:   `{"config":{"sign":false}}`,
			setup: func(c *MainConfig) {
				c.DKIM.Enabled = true
				c.DKIM.Sign = true
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.plugin, func(t *testing.T) {
			s, _ := testServerWithConfig(t, pluginTestTOML)
			tc.setup(s.mainConfig)
			rec := updatePlugin(t, s, tc.plugin, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("update rejected: %d %s", rec.Code, rec.Body.String())
			}
			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["requires_restart"] != true || response["applies_on_reload"] == true {
				t.Errorf("response = %v; removing an active outbound signer/sealer needs restart", response)
			}
		})
	}
}

// TestPluginSettingsReportEveryProblem: a form that reports one error per
// attempt is a form the operator gives up on.
func TestPluginSettingsReportEveryProblem(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)
	rec := updatePlugin(t, s, "clamav", `{"config":{"address":"nope","timeout":0}}`)
	body := rec.Body.String()
	if !strings.Contains(body, "address") || !strings.Contains(body, "timeout") {
		t.Errorf("both problems should be reported at once, got %q", body)
	}
}

// TestPluginSettingsAbsentKeysAreLeftAlone lets the UI send a partial update
// without having to restate settings it does not show.
func TestPluginSettingsAbsentKeysAreLeftAlone(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)
	rec := updatePlugin(t, s, "clamav", `{"config":{"timeout":60}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update rejected: %d %s", rec.Code, rec.Body.String())
	}
	if s.mainConfig.Antivirus.Address != "clam:3310" {
		t.Errorf("an untouched field changed: address = %q", s.mainConfig.Antivirus.Address)
	}
	if s.mainConfig.Antivirus.Timeout != 60 {
		t.Errorf("timeout = %d, want 60", s.mainConfig.Antivirus.Timeout)
	}
}

// TestAccessControlListsCanBeCleared: an empty list is a value, not an absence.
// Treating it as "no change" would make a deny list impossible to empty from
// the UI, and the operator would be left believing they had removed a rule.
func TestAccessControlListsCanBeCleared(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)
	s.mainConfig.AccessControl.DenyIPs = []string{"10.0.0.0/8"}

	rec := updatePlugin(t, s, "access_control", `{"config":{"deny_ips":[]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update rejected: %d %s", rec.Code, rec.Body.String())
	}
	if len(s.mainConfig.AccessControl.DenyIPs) != 0 {
		t.Errorf("the list was not cleared: %v", s.mainConfig.AccessControl.DenyIPs)
	}
}

// TestPluginUpdateNeedsSomethingToDo guards against an empty body being read as
// "disable", which is what happens when a missing boolean defaults to false.
func TestPluginUpdateNeedsSomethingToDo(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)
	rec := updatePlugin(t, s, "clamav", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an empty update should be refused, got %d", rec.Code)
	}
	if !s.mainConfig.Antivirus.Enabled {
		t.Error("an empty update disabled the scanner")
	}
}

// TestScannerSettingsAreNotWrittenAsZeros: a config file with no scanner
// section at all produces an empty struct when the plugin is toggled on.
// Writing that out would replace a working address with "" and a timeout with
// 0 — which is not "the default" but "no timeout".
func TestScannerSettingsAreNotWrittenAsZeros(t *testing.T) {
	const minimal = "hostname = \"mail.example.com\"\n"
	s, path := testServerWithConfig(t, minimal)
	s.mainConfig.Antivirus = nil

	rec := updatePlugin(t, s, "clamav", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle rejected: %d %s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, unwanted := range []string{`address = ""`, "timeout = 0", "scan_limit = 0"} {
		if strings.Contains(string(raw), unwanted) {
			t.Errorf("toggling a plugin wrote %q into the config:\n%s", unwanted, raw)
		}
	}
}

// TestRBLCannotBeEnabledWithNoZones: enabled with nothing to query is a filter
// the operator believes is protecting them, and it is also what the SMTP server
// refuses to start with — so it is caught at the form rather than at the next
// restart, when the cause is hours behind.
func TestRBLCannotBeEnabledWithNoZones(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)

	if rec := updatePlugin(t, s, "rbl", `{"enabled":true}`); rec.Code != http.StatusBadRequest {
		t.Errorf("enabling with no zones should be refused, got %d %s", rec.Code, rec.Body.String())
	}

	// With zones, it is accepted.
	rec := updatePlugin(t, s, "rbl", `{"enabled":true,"config":{"zones":["zen.example.org"]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enabling with a zone was refused: %d %s", rec.Code, rec.Body.String())
	}
	if !s.mainConfig.RBL.Enabled || len(s.mainConfig.RBL.Zones) != 1 {
		t.Errorf("config = %+v, want enabled with one zone", s.mainConfig.RBL)
	}
}

// TestRBLReportsNeedsConfigUntilItHasZones.
//
// The UI hides a disabled plugin's settings tab, and the server refuses to
// enable this one without zones. Together that was a dead end: the toggle
// answered "add at least one blocklist zone" and the form for adding one only
// appeared once the plugin was enabled. needs_config is what lets the UI show
// the form first, so it has to be reported accurately.
func TestRBLReportsNeedsConfigUntilItHasZones(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)

	needsConfig := func() bool {
		req := httptest.NewRequest(http.MethodGet, "/api/config/plugins", nil)
		rec := httptest.NewRecorder()
		s.handleGetPlugins(rec, req)

		var body struct {
			Plugins []map[string]interface{} `json:"plugins"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode plugins: %v", err)
		}
		for _, p := range body.Plugins {
			if p["name"] == "rbl" {
				return p["needs_config"] == true
			}
		}
		t.Fatal("rbl is missing from the plugin list")
		return false
	}

	if !needsConfig() {
		t.Error("with no zones configured, rbl must report needs_config so its form is reachable")
	}

	rec := updatePlugin(t, s, "rbl", `{"config":{"zones":["zen.example.org"]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("saving zones was refused: %d %s", rec.Code, rec.Body.String())
	}
	if needsConfig() {
		t.Error("once zones are configured the plugin no longer needs configuration")
	}

	// And now the plain toggle works, which is the whole point.
	if rec := updatePlugin(t, s, "rbl", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Errorf("enabling after configuring should succeed, got %d %s", rec.Code, rec.Body.String())
	}
}

// TestRBLSettingsSurviveAReload writes through to the file and reads it back
// with the real parser, since a zone list that does not persist is a blocklist
// that stops working at the next restart.
func TestRBLSettingsSurviveAReload(t *testing.T) {
	s, path := testServerWithConfig(t, pluginTestTOML)

	rec := updatePlugin(t, s, "rbl", `{"enabled":true,"config":{"zones":["zen.example.org","bl.example.net"],"reject":true,"timeout":8}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update rejected: %d %s", rec.Code, rec.Body.String())
	}

	var probe struct {
		RBL struct {
			Enabled bool     `toml:"enabled"`
			Zones   []string `toml:"zones"`
			Reject  bool     `toml:"reject"`
			Timeout int      `toml:"timeout"`
		} `toml:"rbl"`
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := toml.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("config no longer parses: %v\n%s", err, raw)
	}
	if len(probe.RBL.Zones) != 2 || probe.RBL.Zones[0] != "zen.example.org" {
		t.Errorf("zones = %v, want both, in order", probe.RBL.Zones)
	}
	if !probe.RBL.Enabled || !probe.RBL.Reject || probe.RBL.Timeout != 8 {
		t.Errorf("rbl = %+v, want the submitted values", probe.RBL)
	}
}

// TestMassMailerTogglesWithoutRestart: the campaign machinery lives in this
// process, so reporting "restart required" would teach operators to restart for
// changes that do not need it.
func TestMassMailerTogglesWithoutRestart(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)

	rec := updatePlugin(t, s, "mass_mailer", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable rejected: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["requires_restart"] == true {
		t.Error("the mass mailer should take effect immediately")
	}
	if store, runner := s.massMailer(); store == nil || runner == nil {
		t.Fatal("enabling the plugin did not build the campaign store and runner")
	}

	// And off again.
	if rec := updatePlugin(t, s, "mass_mailer", `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("disable rejected: %d %s", rec.Code, rec.Body.String())
	}
	if store, _ := s.massMailer(); store != nil {
		t.Error("disabling the plugin left the campaign store behind")
	}
}
