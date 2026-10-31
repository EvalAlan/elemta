package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/stretchr/testify/require"
)

type adminDirectory struct{ account *provision.Account }

func (d *adminDirectory) List(context.Context) ([]provision.Account, error) {
	if d.account == nil {
		return []provision.Account{}, nil
	}
	return []provision.Account{*d.account}, nil
}
func (d *adminDirectory) Get(context.Context, string) (provision.Account, error) {
	if d.account == nil {
		return provision.Account{}, provision.ErrNotFound
	}
	return *d.account, nil
}
func (d *adminDirectory) Create(_ context.Context, in provision.Create) (provision.Account, error) {
	d.account = &provision.Account{Address: in.Address, Name: in.Name, Status: "active", QuotaBytes: in.QuotaBytes, Aliases: []string{}}
	return *d.account, nil
}
func (d *adminDirectory) Update(_ context.Context, _ string, p provision.Patch) (provision.Account, error) {
	if p.Name != nil {
		d.account.Name = *p.Name
	}
	if p.Status != nil {
		d.account.Status = *p.Status
	}
	if p.QuotaBytes != nil {
		d.account.QuotaBytes = *p.QuotaBytes
	}
	return *d.account, nil
}
func (d *adminDirectory) Delete(context.Context, string) error { d.account = nil; return nil }
func (d *adminDirectory) Alias(_ context.Context, _, alias string, add bool) (provision.Account, error) {
	if add {
		d.account.Aliases = append(d.account.Aliases, alias)
	} else {
		d.account.Aliases = []string{}
	}
	return *d.account, nil
}

func startProvisionAPI(t *testing.T) (string, *provision.Service) {
	t.Helper()
	return startProvisionAPIWith(t, nil)
}

// startProvisionAPIWith lets a test adjust the server before it starts.
func startProvisionAPIWith(t *testing.T, adjust func(*Server)) (string, *provision.Service) {
	t.Helper()
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	admin, err := auth.HashPassword(testAdminPassword)
	require.NoError(t, err)
	viewer, err := auth.HashPassword(testUserPassword)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(users, []byte("root:"+admin+":admin\nviewer:"+viewer+":user\n"), 0o600))
	path := filepath.Join(dir, "elemta.toml")
	require.NoError(t, os.WriteFile(path, []byte("local_domains = [\"example.com\"]\n"), 0o600))
	s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: dir, AuthEnabled: true, AuthFile: users}, nil, dir, 0, path)
	require.NoError(t, err)
	service := &provision.Service{Directory: &adminDirectory{}, Routing: provision.FileDomains{Path: path}, Revoke: func(context.Context, string) error { return nil }, Reset: func(context.Context, string, string) error { return nil }}
	s.SetProvisioner(service)
	s.SetAbuse(abuse.New("test", "", nil))
	if adjust != nil {
		adjust(s)
	}
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	return "http://" + waitReady(t, s), service
}
func TestMailboxAdministrationPermissionsAndLifecycle(t *testing.T) {
	base, service := startProvisionAPI(t)
	code, _ := userRequest(t, "GET", base+"/api/provision/accounts", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code)
	response, err := http.Get(base + "/api/provision/status")
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	code, body := userRequest(t, "POST", base+"/api/provision/accounts", "root", testAdminPassword, map[string]any{"address": "dana@example.com", "name": "<img src=x onerror=alert(1)>", "password": "private-initial-password", "quota_bytes": int64(5 << 30)})
	require.Equal(t, http.StatusCreated, code, body)
	require.NotContains(t, body, "private-initial-password")
	require.NotContains(t, body, `"password"`)
	var account provision.Account
	require.NoError(t, json.Unmarshal([]byte(body), &account))
	require.Equal(t, int64(5<<30), account.QuotaBytes)
	code, body = userRequest(t, "PATCH", base+"/api/provision/accounts/dana@example.com", "root", testAdminPassword, map[string]any{"status": "disabled"})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"disabled"`)
	code, body = userRequest(t, "POST", base+"/api/provision/accounts/dana@example.com/aliases", "root", testAdminPassword, map[string]string{"alias": "sales@example.com"})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "sales@example.com")
	resets := 0
	service.Reset = func(context.Context, string, string) error { resets++; return nil }
	code, body = userRequest(t, "POST", base+"/api/provision/accounts/dana@example.com/password", "root", testAdminPassword, map[string]string{"password": "new-private-password"})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, 1, resets)
	require.NotContains(t, body, "new-private-password")
	code, body = userRequest(t, "DELETE", base+"/api/provision/domains", "root", testAdminPassword, map[string]string{"name": "example.com"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = userRequest(t, "DELETE", base+"/api/provision/accounts/dana@example.com", "root", testAdminPassword, map[string]string{"confirm": "wrong@example.com"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = userRequest(t, "DELETE", base+"/api/provision/accounts/dana@example.com", "root", testAdminPassword, map[string]string{"confirm": "dana@example.com"})
	require.Equal(t, http.StatusOK, code, body)
	code, body = userRequest(t, "POST", base+"/api/provision/domains", "root", testAdminPassword, map[string]string{"name": "second.example"})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"requires_restart":true`)
}
func TestMailboxAdministrationRefusesFormBodies(t *testing.T) {
	base, _ := startProvisionAPI(t)
	req, err := http.NewRequest("POST", base+"/api/provision/accounts", strings.NewReader("address=bad@example.com"))
	require.NoError(t, err)
	req.SetBasicAuth("root", testAdminPassword)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusUnsupportedMediaType, response.StatusCode)
}
