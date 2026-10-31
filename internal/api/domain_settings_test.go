package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/dnshealth"
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

func TestDomainDNSHealth(t *testing.T) {
	var asked dnshealth.Options
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		s.dnsHealth = func(_ context.Context, o dnshealth.Options) dnshealth.Report {
			asked = o
			return dnshealth.Report{Domain: o.Domain, Status: dnshealth.StatusWarn, Checks: []dnshealth.Check{{ID: "mx", Status: dnshealth.StatusWarn}}}
		}
	})
	path := base + "/api/provision/domains/example.com/dns-health"

	code, body := userRequest(t, "GET", path, "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	var report dnshealth.Report
	require.NoError(t, json.Unmarshal([]byte(body), &report))
	require.Equal(t, "example.com", report.Domain)
	require.Equal(t, dnshealth.StatusWarn, report.Status)
	require.Equal(t, "example.com", asked.Domain)
	require.Equal(t, dnshealth.SigningNo, asked.Signing)

	code, _ = userRequest(t, "GET", path, "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code)
	// A domain this server doesn't host is not a free DNS and HTTPS probe.
	code, _ = userRequest(t, "GET", base+"/api/provision/domains/other.example/dns-health", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusNotFound, code)
}

func TestDNSHealthUsesTheKeysThatSign(t *testing.T) {
	var asked dnshealth.Options
	s := &Server{dnsHealth: func(_ context.Context, o dnshealth.Options) dnshealth.Report {
		asked = o
		return dnshealth.Report{}
	}}
	s.runDNSHealth(context.Background(), domainSettingsView{Domain: "example.com", Signing: signingOn, Keys: []dkimKeyView{
		{Selector: "old", DNSName: "old._domainkey.example.com", Record: "old"},
		{Selector: "new", Active: true, DNSName: "new._domainkey.example.com", Record: "new"},
	}})
	require.Equal(t, dnshealth.SigningOn, asked.Signing)
	require.Equal(t, []dnshealth.DKIMKey{{Name: "new._domainkey.example.com", Record: "new"}}, asked.DKIMKeys)

	for _, state := range []string{signingOff, signingPluginOff} {
		s.runDNSHealth(context.Background(), domainSettingsView{Domain: "example.com", Signing: state})
		require.Equal(t, dnshealth.SigningOff, asked.Signing, state)
	}
}
