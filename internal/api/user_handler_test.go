package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/EvalAlan/elemta/internal/auth"
)

const (
	testAdminPassword = "admin-password-1"
	testUserPassword  = "viewer-password-1"
)

// startUserServer runs a real server, routes and middleware included, over a
// users file holding one admin and one standard user.
func startUserServer(t *testing.T) (base, usersFile string) {
	t.Helper()
	adminHash, err := auth.HashPassword(testAdminPassword)
	require.NoError(t, err)
	viewerHash, err := auth.HashPassword(testUserPassword)
	require.NoError(t, err)

	usersFile = filepath.Join(t.TempDir(), "users.txt")
	require.NoError(t, os.WriteFile(usersFile,
		[]byte("root:"+adminHash+":admin\nviewer:"+viewerHash+":user\n"), 0600))

	s, err := NewServer(&Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:0",
		WebRoot:     t.TempDir(),
		AuthEnabled: true,
		AuthFile:    usersFile,
	}, (*MainConfig)(nil), t.TempDir(), 0, "")
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	return "http://" + waitReady(t, s), usersFile
}

func userRequest(t *testing.T, method, url, user, password string, body interface{}) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.SetBasicAuth(user, password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func TestUserManagementLifecycle(t *testing.T) {
	base, usersFile := startUserServer(t)

	code, body := userRequest(t, "GET", base+"/api/users", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"username":"viewer"`)
	require.NotContains(t, body, "$2", "password hashes must never leave the server")

	code, body = userRequest(t, "POST", base+"/api/users", "root", testAdminPassword,
		map[string]string{"username": "ops", "password": "ops-password-12", "role": "operator"})
	require.Equal(t, http.StatusCreated, code, body)

	// The new account works immediately, with the operator's permissions.
	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "ops", "ops-password-12", nil)
	require.Equal(t, http.StatusOK, code)
	code, _ = userRequest(t, "GET", base+"/api/users", "ops", "ops-password-12", nil)
	require.Equal(t, http.StatusForbidden, code, "an operator must not manage users")

	code, body = userRequest(t, "PUT", base+"/api/users/ops/role", "root", testAdminPassword,
		map[string]string{"role": "admin"})
	require.Equal(t, http.StatusOK, code, body)
	code, _ = userRequest(t, "GET", base+"/api/users", "ops", "ops-password-12", nil)
	require.Equal(t, http.StatusOK, code, "promotion to admin must apply at once")

	code, body = userRequest(t, "PUT", base+"/api/users/ops/password", "root", testAdminPassword,
		map[string]string{"password": "new-ops-password"})
	require.Equal(t, http.StatusOK, code, body)
	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "ops", "ops-password-12", nil)
	require.Equal(t, http.StatusUnauthorized, code, "the old password must stop working")

	code, body = userRequest(t, "DELETE", base+"/api/users/ops", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "ops", "new-ops-password", nil)
	require.Equal(t, http.StatusUnauthorized, code)

	data, err := os.ReadFile(usersFile)
	require.NoError(t, err)
	require.NotContains(t, string(data), "ops:")
	require.Contains(t, string(data), "root:")
}

func TestUserManagementGuards(t *testing.T) {
	base, _ := startUserServer(t)

	code, _ := userRequest(t, "POST", base+"/api/users", "viewer", testUserPassword,
		map[string]string{"username": "x", "password": "long-enough-pw", "role": "admin"})
	require.Equal(t, http.StatusForbidden, code, "a standard user must not create accounts")

	code, body := userRequest(t, "DELETE", base+"/api/users/root", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusConflict, code, body)

	code, body = userRequest(t, "PUT", base+"/api/users/root/role", "root", testAdminPassword,
		map[string]string{"role": "user"})
	require.Equal(t, http.StatusConflict, code, "demoting the last admin locks everyone out: %s", body)

	code, _ = userRequest(t, "POST", base+"/api/users", "root", testAdminPassword,
		map[string]string{"username": "short", "password": "tooshort", "role": "user"})
	require.Equal(t, http.StatusBadRequest, code)

	code, _ = userRequest(t, "POST", base+"/api/users", "root", testAdminPassword,
		map[string]string{"username": "bad:name", "password": "long-enough-pw", "role": "user"})
	require.Equal(t, http.StatusBadRequest, code, "a colon would corrupt the users file")

	code, _ = userRequest(t, "POST", base+"/api/users", "root", testAdminPassword,
		map[string]string{"username": "nobody", "password": "long-enough-pw", "role": "superuser"})
	require.Equal(t, http.StatusBadRequest, code)

	code, _ = userRequest(t, "POST", base+"/api/users", "root", testAdminPassword,
		map[string]string{"username": "viewer", "password": "long-enough-pw", "role": "user"})
	require.Equal(t, http.StatusConflict, code)
}

// A form on another site can post text/plain with a JSON-looking body and the
// admin's cookie attached. Only application/json is accepted.
func TestUserManagementRequiresJSONContentType(t *testing.T) {
	base, _ := startUserServer(t)
	req, err := http.NewRequest("POST", base+"/api/users",
		strings.NewReader(`{"username":"evil","password":"long-enough-pw","role":"admin"}`))
	require.NoError(t, err)
	req.SetBasicAuth("root", testAdminPassword)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestChangeOwnPassword(t *testing.T) {
	base, _ := startUserServer(t)

	code, _ := userRequest(t, "POST", base+"/api/account/password", "viewer", testUserPassword,
		map[string]string{"current_password": "wrong-password", "new_password": "fresh-password-1"})
	require.Equal(t, http.StatusForbidden, code)

	code, body := userRequest(t, "POST", base+"/api/account/password", "viewer", testUserPassword,
		map[string]string{"current_password": testUserPassword, "new_password": "fresh-password-1"})
	require.Equal(t, http.StatusOK, code, body)

	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "viewer", "fresh-password-1", nil)
	require.Equal(t, http.StatusOK, code)
}

// Accounts changed with the CLI must apply to a running server without a
// restart; removing one must revoke access.
func TestUsersFileEditsApplyWithoutRestart(t *testing.T) {
	base, usersFile := startUserServer(t)

	code, _ := userRequest(t, "GET", base+"/api/queue/stats", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusOK, code)

	data, err := os.ReadFile(usersFile)
	require.NoError(t, err)
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "viewer:") {
			kept = append(kept, line)
		}
	}
	tmp := usersFile + ".edit"
	require.NoError(t, os.WriteFile(tmp, []byte(strings.Join(kept, "\n")), 0600))
	require.NoError(t, os.Rename(tmp, usersFile))

	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusUnauthorized, code)
}

// Liveness answers anyone; the operational detail needs a login.
func TestHealthDetailNeedsAuth(t *testing.T) {
	base, _ := startUserServer(t)

	resp, err := http.Get(base + "/api/health")
	require.NoError(t, err)
	var anon map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&anon))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "healthy", anon["status"])
	require.NotContains(t, anon, "queue", "queue depths must not be public")
	require.NotContains(t, anon, "server_version")

	code, body := userRequest(t, "GET", base+"/api/health", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"queue"`)
}
