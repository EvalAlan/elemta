package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDomainDKIMLifecycle(t *testing.T) {
	base, _ := startProvisionAPI(t)
	call := func(method, path string, body any, want int) string {
		t.Helper()
		code, out := userRequest(t, method, base+"/api/provision"+path, "root", testAdminPassword, body)
		require.Equal(t, want, code, out)
		return out
	}
	var view domainSettingsView
	require.NoError(t, json.Unmarshal([]byte(call("GET", "/domains/example.com/settings", nil, 200)), &view))
	require.Equal(t, signingNoKey, view.Signing)
	require.Equal(t, "active", view.Status)

	out := call("POST", "/domains/example.com/dkim/keys", map[string]string{"selector": "mail2026", "algorithm": "ed25519"}, 200)
	require.NoError(t, json.Unmarshal([]byte(out), &view))
	require.Len(t, view.Keys, 1)
	require.Equal(t, "mail2026._domainkey.example.com", view.Keys[0].DNSName)
	require.False(t, view.Keys[0].Active, "a new key must not sign before DNS has it")
	require.NotContains(t, out, "PRIVATE KEY")

	call("POST", "/domains/example.com/dkim/keys", map[string]string{"selector": "mail2026"}, http.StatusConflict)
	call("POST", "/domains/example.com/dkim/keys", map[string]string{"selector": "../x"}, http.StatusBadRequest)
	call("POST", "/domains/absent.example/dkim/keys", map[string]string{"selector": "a"}, http.StatusNotFound)

	require.NoError(t, json.Unmarshal([]byte(call("PUT", "/domains/example.com/dkim/signing", map[string]any{"enabled": true, "selector": "mail2026"}, 200)), &view))
	require.Equal(t, signingOn, view.Signing)
	require.True(t, view.Keys[0].Active)

	call("DELETE", "/domains/example.com/dkim/keys/mail2026", nil, http.StatusBadRequest)
	require.NoError(t, json.Unmarshal([]byte(call("PUT", "/domains/example.com/dkim/signing", map[string]any{"enabled": false}, 200)), &view))
	require.Equal(t, signingOff, view.Signing)
	require.False(t, strings.Contains(call("GET", "/domains/example.com/settings", nil, 200), "PRIVATE KEY"))
}

func TestDomainDKIMNeedsAdministrator(t *testing.T) {
	base, _ := startProvisionAPI(t)
	code, _ := userRequest(t, "POST", base+"/api/provision/domains/example.com/dkim/keys", "viewer", testUserPassword, map[string]string{"selector": "a"})
	require.Equal(t, http.StatusForbidden, code)
	code, _ = userRequest(t, "GET", base+"/api/provision/domains/example.com/settings", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code)
}
