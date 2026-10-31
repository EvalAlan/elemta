package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/stretchr/testify/require"
)

func TestAbusePolicyIsSavedAndPublished(t *testing.T) {
	base, service := startProvisionAPI(t)
	_ = service
	code, _ := userRequest(t, "GET", base+"/api/abuse", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code)
	code, body := userRequest(t, "GET", base+"/api/abuse", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	var status struct {
		Policy abuse.Policy `json:"policy"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &status))
	require.Equal(t, abuse.DefaultPolicy().ConnectionsPerAddress, status.Policy.ConnectionsPerAddress)

	code, body = userRequest(t, "PUT", base+"/api/abuse/policy", "root", testAdminPassword, map[string]any{"mode": "enforce", "connections_per_address": 7, "allowlist": []string{" 203.0.113.9 ", ""}})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"published":true`)
	code, body = userRequest(t, "GET", base+"/api/abuse", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"connections_per_address":7`)
	require.Contains(t, body, `"203.0.113.9"`)

	for name, policy := range map[string]map[string]any{
		"mode":      {"mode": "sometimes", "connections_per_address": 7},
		"limit":     {"mode": "enforce", "connections_per_address": 0},
		"allowlist": {"mode": "enforce", "connections_per_address": 7, "allowlist": []string{"nonsense"}},
	} {
		code, body = userRequest(t, "PUT", base+"/api/abuse/policy", "root", testAdminPassword, policy)
		require.Equal(t, http.StatusBadRequest, code, name+": "+body)
	}
	code, _ = userRequest(t, "PUT", base+"/api/abuse/policy", "viewer", testUserPassword, map[string]any{"mode": "off", "connections_per_address": 7})
	require.Equal(t, http.StatusForbidden, code)
}

func TestAbuseBlocksFromTheConsole(t *testing.T) {
	base, _ := startProvisionAPI(t)
	block := func(body map[string]any, want int) string {
		t.Helper()
		code, out := userRequest(t, "POST", base+"/api/abuse/blocks", "root", testAdminPassword, body)
		require.Equal(t, want, code, out)
		return out
	}
	code, _ := userRequest(t, "POST", base+"/api/abuse/blocks", "viewer", testUserPassword, map[string]any{"address": "203.0.113.9", "minutes": 5})
	require.Equal(t, http.StatusForbidden, code)
	block(map[string]any{"address": "203.0.113.9", "minutes": 60, "reason": "testing"}, http.StatusOK)
	block(map[string]any{"address": "nonsense", "minutes": 60}, http.StatusBadRequest)
	block(map[string]any{"address": "203.0.113.10", "minutes": 0}, http.StatusBadRequest)
	// The tests sign in from loopback, which is exempt and is also "you".
	block(map[string]any{"address": "127.0.0.1", "minutes": 5}, http.StatusBadRequest)

	code, body := userRequest(t, "GET", base+"/api/abuse", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"network":"203.0.113.9"`)
	require.Contains(t, body, `"you_exempt":true`)
	require.Contains(t, body, `"action":"blocked"`)

	code, body = userRequest(t, "DELETE", base+"/api/abuse/blocks?address=203.0.113.9", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	code, body = userRequest(t, "GET", base+"/api/abuse", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.NotContains(t, body, `"network":"203.0.113.9","reason"`)
	require.Contains(t, body, `"action":"unblocked"`)
}

// The file is what outlasts Valkey and a restart.
func TestAbusePolicyPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "elemta.toml")
	require.NoError(t, os.WriteFile(path, []byte("local_domains = [\"example.com\"]\n"), 0o600))
	s := &Server{configPath: path, mainConfig: &MainConfig{}}
	s.mainConfig.Abuse = &abuse.Policy{Mode: abuse.ModeLog, ConnectionsPerAddress: 30, Allowlist: []string{"203.0.113.9"}}
	require.NoError(t, s.persistConfig())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, want := range []string{"[abuse]", `mode = "log"`, "connections_per_address = 30", "203.0.113.9"} {
		require.True(t, strings.Contains(string(data), want), "%s missing from:\n%s", want, data)
	}
}
