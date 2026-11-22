package api

import (
	"net/http"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/stretchr/testify/require"
)

func TestAbuseIsAPlugin(t *testing.T) {
	var server *Server
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		s.mainConfig = &MainConfig{Hostname: "mail.example.com"}
		server = s
	})
	call := func(user, password, method, path string, body any) (int, string) {
		return userRequest(t, method, base+"/api"+path, user, password, body)
	}
	root := func(method, path string, body any) (int, string) {
		return call("root", testAdminPassword, method, path, body)
	}

	code, body := root("GET", "/config/plugins", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"name":"abuse"`)

	code, body = root("PUT", "/abuse/policy", map[string]any{"alert_email": []string{"ops@example.com"}, "failures_per_address": 33})
	require.Equal(t, http.StatusOK, code, body)

	code, body = call("viewer", testUserPassword, "PUT", "/config/plugins/abuse", map[string]any{"enabled": false})
	require.Equal(t, http.StatusForbidden, code, body)
	require.Equal(t, abuse.ModeEnforce, server.abuse.Policy().Mode)

	code, body = root("PUT", "/config/plugins/abuse", map[string]any{"enabled": false})
	require.Equal(t, http.StatusOK, code, body)
	p := server.abuse.Policy()
	require.Equal(t, abuse.ModeOff, p.Mode)
	require.Equal(t, 33, p.FailuresPerAddress, "the switch lost the settings")
	require.Equal(t, []string{"ops@example.com"}, p.AlertEmail, "alerts must outlive the plugin")

	code, body = root("PUT", "/config/plugins/abuse", map[string]any{"enabled": true})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, abuse.ModeEnforce, server.abuse.Policy().Mode)

	// On already: switching on again doesn't turn log-only into enforcing.
	code, body = root("PUT", "/abuse/policy", map[string]any{"mode": "log"})
	require.Equal(t, http.StatusOK, code, body)
	code, body = root("PUT", "/config/plugins/abuse", map[string]any{"enabled": true})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, abuse.ModeLog, server.abuse.Policy().Mode)

	code, body = root("PUT", "/config/plugins/abuse", map[string]any{"config": map[string]any{"mode": "off"}})
	require.Equal(t, http.StatusBadRequest, code, body)
}
