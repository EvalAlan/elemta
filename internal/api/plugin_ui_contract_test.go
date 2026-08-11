package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The dashboard renders every plugin's settings form from PLUGIN_SETTINGS_SCHEMA
// in web/static/app.js, while the API decides which settings exist. Those two
// live in different languages, in different files, and nothing connects them.
//
// The failure is silent and one-directional: add a setting to the API and the
// form simply does not show it. Nothing errors, no test fails, and the operator
// concludes the feature does not exist. This is the same class of problem as
// TestToSMTPConfig_AllFieldsMapped in internal/config, and it gets the same
// treatment — a tripwire that fails when the two drift apart.

const uiSchemaPath = "../../web/static/app.js"

var (
	// A schema entry: `    name: {  ... },` at exactly four spaces of indent.
	uiPluginBlock = regexp.MustCompile(`(?s)\n    ([a-z_]+): \{(.*?)\n    \},`)
	uiFieldKey    = regexp.MustCompile(`key: '([a-z_]+)'`)
)

// uiSchema maps each plugin name to the settings its form can edit. A nil slice
// means the plugin reuses a hand-built panel and has no generated form.
func uiSchema(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(uiSchemaPath)
	if err != nil {
		t.Fatalf("reading the dashboard schema: %v", err)
	}
	source := string(raw)

	start := strings.Index(source, "const PLUGIN_SETTINGS_SCHEMA")
	if start < 0 {
		t.Fatal("PLUGIN_SETTINGS_SCHEMA is gone from app.js; this test needs updating")
	}
	source = source[start:]

	schema := map[string][]string{}
	for _, match := range uiPluginBlock.FindAllStringSubmatch(source, -1) {
		name, body := match[1], match[2]
		if strings.Contains(body, "panelId:") {
			// Reuses an existing hand-written panel, so there is no generated
			// form to compare against.
			schema[name] = nil
			continue
		}
		var keys []string
		for _, field := range uiFieldKey.FindAllStringSubmatch(body, -1) {
			keys = append(keys, field[1])
		}
		schema[name] = keys
	}
	if len(schema) == 0 {
		t.Fatal("parsed no plugins out of app.js; this test needs updating")
	}
	return schema
}

// TestEverySettingTheAPIExposesIsEditableInTheDashboard fails when the API
// advertises a setting the form cannot edit.
func TestEverySettingTheAPIExposesIsEditableInTheDashboard(t *testing.T) {
	s, _ := testServerWithConfig(t, pluginTestTOML)
	// Give every mail-auth plugin a configuration, or its config block comes
	// back nil and the plugin is skipped — which would make this test pass by
	// examining nothing.
	s.mainConfig.SPF = &SPFStatus{Enabled: true, Timeout: 10}
	s.mainConfig.DKIM = &DKIMStatus{Enabled: true, Verify: true}
	s.mainConfig.DMARC = &DMARCStatus{Enabled: true, Timeout: 10}
	s.mainConfig.ARC = &ARCStatus{Enabled: true, Verify: true, Timeout: 10}

	req := httptest.NewRequest(http.MethodGet, "/api/config/plugins", nil)
	rec := httptest.NewRecorder()
	s.handleGetPlugins(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin list = %d %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Plugins []map[string]interface{} `json:"plugins"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode plugins: %v", err)
	}
	if len(body.Plugins) == 0 {
		t.Fatal("the API returned no plugins")
	}

	schema := uiSchema(t)
	checked := 0

	for _, plugin := range body.Plugins {
		name, _ := plugin["name"].(string)
		config, ok := plugin["config"].(map[string]interface{})
		if !ok || len(config) == 0 {
			continue
		}

		fields, present := schema[name]
		if !present {
			t.Errorf("plugin %q has settings in the API but no entry in PLUGIN_SETTINGS_SCHEMA, so its form cannot be rendered", name)
			continue
		}
		if fields == nil {
			continue // hand-built panel
		}

		editable := map[string]bool{}
		for _, key := range fields {
			editable[key] = true
		}
		var missing []string
		for key := range config {
			if !editable[key] {
				missing = append(missing, key)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("plugin %q exposes settings the dashboard cannot edit: %v\n"+
				"add them to PLUGIN_SETTINGS_SCHEMA in web/static/app.js", name, missing)
		}
		checked++
	}

	// Guard against the test quietly checking nothing, which is how a tripwire
	// stops being one.
	if checked < 4 {
		t.Fatalf("only compared %d plugins; expected at least the four mail-auth ones", checked)
	}
}

// TestDashboardOffersOnlyCanonicalizationsTheServerAccepts. The server rejects
// anything but simple and relaxed, so a free-text box could only ever produce a
// value that fails to save.
func TestDashboardOffersOnlyCanonicalizationsTheServerAccepts(t *testing.T) {
	raw, err := os.ReadFile(uiSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)

	canonField := regexp.MustCompile(`key: '(header|body)_canonicalization'[^}]*?type: '([a-z]+)'[^}]*?options: \[([^\]]*)\]`)
	matches := canonField.FindAllStringSubmatch(source, -1)
	if len(matches) < 4 {
		t.Fatalf("found %d canonicalization selects; DKIM and ARC should contribute two each", len(matches))
	}

	for _, m := range matches {
		if m[2] != "select" {
			t.Errorf("%s_canonicalization is a %q input; only two values are valid so it must be a select", m[1], m[2])
		}
		options := strings.NewReplacer("'", "", " ", "").Replace(m[3])
		for _, option := range strings.Split(options, ",") {
			if option == "" {
				continue
			}
			// validateCanonicalization is what the server applies to these.
			if err := validateCanonicalization(option); err != nil {
				t.Errorf("the dashboard offers canonicalization %q, which the server rejects: %v", option, err)
			}
		}
	}
}
