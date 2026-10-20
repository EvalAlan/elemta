package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/stretchr/testify/require"
)

// mapDirectory holds several accounts, so scoping has something to filter.
type mapDirectory struct {
	mu       sync.Mutex
	accounts map[string]*provision.Account
}

func (d *mapDirectory) List(context.Context) ([]provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []provision.Account{}
	for _, a := range d.accounts {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
func (d *mapDirectory) Get(_ context.Context, address string) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[address]; ok {
		return *a, nil
	}
	return provision.Account{}, provision.ErrNotFound
}
func (d *mapDirectory) Create(_ context.Context, in provision.Create) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := &provision.Account{Address: in.Address, Name: in.Name, Status: "active", QuotaBytes: in.QuotaBytes, Aliases: []string{}}
	d.accounts[in.Address] = a
	return *a, nil
}
func (d *mapDirectory) Update(_ context.Context, address string, p provision.Patch) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.accounts[address]
	if p.Name != nil {
		a.Name = *p.Name
	}
	return *a, nil
}
func (d *mapDirectory) Delete(_ context.Context, address string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.accounts, address)
	return nil
}
func (d *mapDirectory) Alias(_ context.Context, address, alias string, add bool) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.accounts[address]
	if add {
		a.Aliases = append(a.Aliases, alias)
	}
	return *a, nil
}

const testDomainAdminPassword = "domain-admin-password-1"

func TestDelegatedDomainAdministration(t *testing.T) {
	dir := t.TempDir()
	hash := func(pw string) string {
		h, err := auth.HashPassword(pw)
		require.NoError(t, err)
		return h
	}
	users := filepath.Join(dir, "users")
	require.NoError(t, os.WriteFile(users, []byte(
		"root:"+hash(testAdminPassword)+":admin\n"+
			"viewer:"+hash(testUserPassword)+":user\n"+
			"deleg:"+hash(testDomainAdminPassword)+":domain-admin,domain:example.com\n"+
			"nodom:"+hash(testDomainAdminPassword)+":domain-admin\n"), 0o600))
	config := filepath.Join(dir, "elemta.toml")
	require.NoError(t, os.WriteFile(config, []byte("local_domains = [\"example.com\", \"other.example\"]\n"), 0o600))
	s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: dir, AuthEnabled: true, AuthFile: users}, nil, dir, 0, config)
	require.NoError(t, err)
	directory := &mapDirectory{accounts: map[string]*provision.Account{
		"dana@example.com":  {Address: "dana@example.com", Name: "Dana", Status: "active", Aliases: []string{}},
		"eve@other.example": {Address: "eve@other.example", Name: "Eve", Status: "active", Aliases: []string{}},
	}}
	fake := &fakeMailboxAdmin{classes: map[string]mailpolicy.Class{"staff": {Name: "staff"}}, policy: map[string]mailpolicy.AccountPolicy{}, lists: map[string]mailpolicy.List{}, routes: map[string]mailpolicy.DomainRoute{}, held: map[string]bool{}}
	mailbox := httptest.NewServer(fake)
	t.Cleanup(mailbox.Close)
	client, err := mailpolicy.NewClient(mailbox.URL, "token")
	require.NoError(t, err)
	s.SetProvisioner(&provision.Service{Directory: directory, Routing: provision.FileDomains{Path: config}, Mailbox: client,
		Revoke: func(context.Context, string) error { return nil }, Reset: func(context.Context, string, string) error { return nil }})
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	base := "http://" + waitReady(t, s)

	as := func(user, password string) func(method, path string, body any) (int, string) {
		return func(method, path string, body any) (int, string) {
			return userRequest(t, method, base+path, user, password, body)
		}
	}
	deleg, root := as("deleg", testDomainAdminPassword), as("root", testAdminPassword)

	// The server's own views are closed to a domain administrator, not to
	// the existing read-only roles.
	code, _ := deleg("GET", "/api/queue/stats", nil)
	require.Equal(t, http.StatusForbidden, code)
	code, _ = deleg("GET", "/api/logs", nil)
	require.Equal(t, http.StatusForbidden, code)
	code, _ = as("viewer", testUserPassword)("GET", "/api/queue/stats", nil)
	require.Equal(t, http.StatusOK, code)
	code, _ = deleg("GET", "/api/users", nil)
	require.Equal(t, http.StatusForbidden, code)

	// A domain administrator without domains can do nothing.
	code, body := as("nodom", testDomainAdminPassword)("GET", "/api/provision/status", nil)
	require.Equal(t, http.StatusForbidden, code, body)
	require.Contains(t, body, "no domains")

	code, body = deleg("GET", "/api/provision/status", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"scope":{"all":false,"domains":["example.com"]}`)
	code, body = root("GET", "/api/provision/status", nil)
	require.Contains(t, body, `"scope":{"all":true}`, body)

	// Accounts: only theirs, listed and changed.
	code, body = deleg("GET", "/api/provision/accounts", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "dana@example.com")
	require.NotContains(t, body, "eve@other.example")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/accounts", map[string]any{"address": "new@other.example", "name": "New", "password": "private-initial-password"}},
		{"GET", "/accounts/eve@other.example", nil},
		{"PATCH", "/accounts/eve@other.example", map[string]any{"name": "Mallory"}},
		{"DELETE", "/accounts/eve@other.example", map[string]any{"confirm": "eve@other.example"}},
		{"POST", "/accounts/eve@other.example/password", map[string]any{"password": "new-private-password"}},
		{"POST", "/accounts/dana@example.com/aliases", map[string]any{"alias": "dana@other.example"}},
		{"GET", "/accounts/eve@other.example/policy", nil},
		{"POST", "/purge", map[string]any{"address": "eve@other.example", "confirm": "eve@other.example"}},
		{"POST", "/lists", map[string]any{"address": "team@other.example"}},
		{"PUT", "/lists/team@other.example", map[string]any{"name": "x"}},
		{"PUT", "/domains/other.example/catch-all", map[string]any{"address": "dana@example.com"}},
		// System-wide settings, even for their own domain.
		{"POST", "/domains", map[string]any{"name": "third.example"}},
		{"PUT", "/classes/staff", map[string]any{"settings": map[string]any{"quota_bytes": 0}}},
		{"PUT", "/domains/example.com/class", map[string]any{"class": "staff"}},
		{"POST", "/domain-aliases", map[string]any{"alias": "alias.example", "target": "example.com"}},
	} {
		code, body := deleg(c.method, "/api/provision"+c.path, c.body)
		require.Equal(t, http.StatusForbidden, code, "%s %s: %s", c.method, c.path, body)
	}
	require.Equal(t, "Eve", directory.accounts["eve@other.example"].Name)

	code, body = deleg("POST", "/api/provision/accounts", map[string]any{"address": "lee@example.com", "name": "Lee", "password": "private-initial-password"})
	require.Equal(t, http.StatusCreated, code, body)
	code, body = deleg("POST", "/api/provision/accounts/lee@example.com/aliases", map[string]any{"alias": "lee.park@example.com"})
	require.Equal(t, http.StatusOK, code, body)
	code, body = deleg("GET", "/api/provision/domains", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"example.com"`)
	require.NotContains(t, body, "other.example")
	code, body = deleg("POST", "/api/provision/lists", map[string]any{"address": "team@example.com", "members": []string{"dana@example.com", "partner@elsewhere.example"}})
	require.Equal(t, http.StatusCreated, code, body)

	// Classes: assigned, but a system administrator's overrides stay, and
	// an account on legal hold keeps its class.
	quota := int64(1 << 30)
	fake.policy["dana@example.com"] = mailpolicy.AccountPolicy{Address: "dana@example.com", Settings: mailpolicy.Settings{QuotaBytes: &quota}}
	code, body = deleg("PUT", "/api/provision/accounts/dana@example.com/policy", map[string]any{"class": "staff", "settings": map[string]any{"quota_bytes": 0}})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "staff", fake.policy["dana@example.com"].Class)
	require.Equal(t, quota, *fake.policy["dana@example.com"].Settings.QuotaBytes)
	fake.held["dana@example.com"] = true
	code, body = deleg("PUT", "/api/provision/accounts/dana@example.com/policy", map[string]any{"class": ""})
	require.Equal(t, http.StatusForbidden, code, body)
	require.Contains(t, body, "legal hold")

	// Domain assignment through the Users API.
	code, body = root("POST", "/api/users", map[string]any{"username": "lee-admin", "password": "long-enough-password", "role": "domain-admin"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = root("POST", "/api/users", map[string]any{"username": "lee-admin", "password": "long-enough-password", "role": "domain-admin", "domains": []string{"exa,mple.com"}})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = root("POST", "/api/users", map[string]any{"username": "lee-admin", "password": "long-enough-password", "role": "domain-admin", "domains": []string{"Other.Example", "example.com"}})
	require.Equal(t, http.StatusCreated, code, body)
	require.Contains(t, body, `"roles":["domain-admin"]`)
	require.Contains(t, body, `"domains":["example.com","other.example"]`)
	code, body = as("lee-admin", "long-enough-password")("GET", "/api/provision/accounts", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "eve@other.example")
	// Narrowing the domains applies at once.
	code, body = root("PUT", "/api/users/lee-admin/role", map[string]any{"role": "domain-admin", "domains": []string{"example.com"}})
	require.Equal(t, http.StatusOK, code, body)
	code, body = as("lee-admin", "long-enough-password")("GET", "/api/provision/accounts", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.NotContains(t, body, "eve@other.example")

	// Every change is in the audit log; a domain administrator reads only
	// their domains' entries.
	actions := map[string]mailpolicy.AuditEntry{}
	for _, e := range fake.audit {
		actions[e.Action+" "+e.Target] = e
	}
	created := actions["account-create lee@example.com"]
	require.Equal(t, "deleg", created.Actor)
	require.Equal(t, "dashboard", created.Source)
	require.Equal(t, "example.com", created.Domain)
	require.NotEmpty(t, created.Client)
	require.Equal(t, "lee.park@example.com", actions["alias-add lee@example.com"].Detail)
	require.Contains(t, actions["account-policy dana@example.com"].Detail, "class staff")
	require.Equal(t, "(system)", actions["dashboard-user-create lee-admin"].Domain)
	require.Contains(t, actions["dashboard-user-role lee-admin"].Detail, "domains example.com")
	for _, e := range fake.audit {
		require.NotContains(t, e.Detail, "password", "audit entries never carry passwords")
	}

	code, body = deleg("GET", "/api/provision/audit", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "domain=example.com", fake.queries[len(fake.queries)-1])
	var page struct{ Entries []mailpolicy.AuditEntry }
	require.NoError(t, json.Unmarshal([]byte(body), &page))
	require.NotEmpty(t, page.Entries)
	for _, e := range page.Entries {
		require.Equal(t, "example.com", e.Domain)
	}
	code, body = root("GET", "/api/provision/audit?actor=deleg&limit=50", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.False(t, strings.Contains(fake.queries[len(fake.queries)-1], "domain="))
	require.Contains(t, fake.queries[len(fake.queries)-1], "actor=deleg")
}
