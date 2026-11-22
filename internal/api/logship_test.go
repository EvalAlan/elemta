package api

import (
	"net/http"
	"testing"

	"github.com/EvalAlan/elemta/internal/logship"
	"github.com/stretchr/testify/require"
)

func TestLogShippingAPI(t *testing.T) {
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		s.mainConfig = &MainConfig{Hostname: "mail.example.com"}
		s.SetLogShipper(logship.NewShipper(t.TempDir(), "", []string{"https://es.example.com:9200"}, nil))
	})
	call := func(user, password, method, path string, body any) (int, string) {
		return userRequest(t, method, base+"/api"+path, user, password, body)
	}
	for _, c := range [][2]string{{"GET", "/log-shipping"}, {"PUT", "/log-shipping"}, {"POST", "/log-shipping/test"}} {
		code, body := call("viewer", testUserPassword, c[0], c[1], map[string]any{})
		require.Equal(t, http.StatusForbidden, code, body)
	}
	settings := map[string]any{"url": "https://es.example.com:9200"}
	code, body := call("root", testAdminPassword, "PUT", "/log-shipping", map[string]any{"settings": settings, "credential": map[string]any{"api_key": "never-shown"}})
	require.Equal(t, http.StatusOK, code, body)

	for _, path := range []string{"/log-shipping", "/config", "/config/plugins"} {
		code, body = call("root", testAdminPassword, "GET", path, nil)
		require.Equal(t, http.StatusOK, code, body)
		require.NotContains(t, body, "never-shown", path)
	}
	code, body = call("root", testAdminPassword, "GET", "/log-shipping", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"credential_set":true`)

	require.Contains(t, body, `"destinations":["https://es.example.com:9200"]`)
	code, body = call("root", testAdminPassword, "POST", "/log-shipping/test", map[string]any{"settings": map[string]any{"url": "http://127.0.0.1:1"}})
	require.Equal(t, http.StatusBadRequest, code, body)
	require.Contains(t, body, logship.DestinationsEnv)

	// Nothing can carry the logs, so it can't be switched on.
	code, body = call("root", testAdminPassword, "PUT", "/config/plugins/log_shipping", map[string]any{"enabled": true})
	require.Equal(t, http.StatusBadRequest, code, body)
	require.Contains(t, body, "Valkey")
}
