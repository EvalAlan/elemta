package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/stretchr/testify/require"
)

func TestDMARCAdminAPI(t *testing.T) {
	var mu sync.Mutex
	var seen, queries []string
	auditDown := false
	// Two cells' answers, joined as the router joins them.
	started := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	addresses := []mailpolicy.DMARCAddress{
		{Domain: "example.com", Address: "rua@example.com", BackfillStarted: &started, BackfillFinished: &finished, BackfillRead: 3},
		{Domain: "example.com", Address: "rua@example.com", BackfillStarted: &started, BackfillRead: 4},
		{Domain: "other.example", Address: "rua@other.example"},
	}
	mailbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/v1/admin/audit" && auditDown:
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/v1/admin/dmarc/addresses":
			_ = json.NewEncoder(w).Encode(addresses)
		case strings.HasSuffix(r.URL.Path, "/summary"), strings.HasSuffix(r.URL.Path, "/sources"):
			queries = append(queries, r.URL.RawQuery)
			_, _ = w.Write([]byte("[]"))
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(mailbox.Close)
	client, err := mailpolicy.NewClient(mailbox.URL, "token")
	require.NoError(t, err)

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
			"deleg:"+hash(testDomainAdminPassword)+":domain-admin,domain:example.com\n"), 0o600))
	config := filepath.Join(dir, "elemta.toml")
	require.NoError(t, os.WriteFile(config, []byte("local_domains = [\"example.com\", \"other.example\"]\n"), 0o600))
	s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: dir, AuthEnabled: true, AuthFile: users}, nil, dir, 0, config)
	require.NoError(t, err)
	s.SetProvisioner(&provision.Service{Directory: &mapDirectory{accounts: map[string]*provision.Account{}}, Routing: provision.FileDomains{Path: config}, Mailbox: client,
		Revoke: func(context.Context, string) error { return nil }})
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	base := "http://" + waitReady(t, s) + "/api/provision/dmarc/"
	as := func(user, password string) func(method, path string, body any) (int, string) {
		return func(method, path string, body any) (int, string) {
			return userRequest(t, method, base+path, user, password, body)
		}
	}
	root, deleg := as("root", testAdminPassword), as("deleg", testDomainAdminPassword)

	code, body := as("viewer", testUserPassword)("GET", "summary", nil)
	require.Equal(t, http.StatusForbidden, code, body)

	code, body = deleg("GET", "addresses", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.NotContains(t, body, "other.example")
	var got struct{ Addresses []mailpolicy.DMARCAddress }
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	require.Len(t, got.Addresses, 1)
	require.Equal(t, int64(7), got.Addresses[0].BackfillRead)
	require.Nil(t, got.Addresses[0].BackfillFinished, "finished before the last cell")

	// With no domain named, theirs and not everyone's.
	for _, path := range []string{"summary", "sources"} {
		code, body = deleg("GET", path, nil)
		require.Equal(t, http.StatusOK, code, body)
		require.Contains(t, queries[len(queries)-1], "domain=example.com")
		code, body = deleg("GET", path+"?domain=other.example", nil)
		require.Equal(t, http.StatusForbidden, code, body)
		code, body = root("GET", path+"?days=90", nil)
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, "days=90", queries[len(queries)-1])
		code, _ = root("GET", path+"?days=0", nil)
		require.Equal(t, http.StatusBadRequest, code)
	}

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "addresses/example.com", map[string]string{"address": "rua@example.com"}},
		{"DELETE", "addresses/example.com", nil},
		{"POST", "addresses/example.com/backfill", nil},
	} {
		code, body := deleg(c.method, c.path, c.body)
		require.Equal(t, http.StatusForbidden, code, "%s %s: %s", c.method, c.path, body)
	}

	code, body = root("PUT", "addresses/example.com", map[string]string{"address": "rua@elsewhere.example"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = root("PUT", "addresses/unknown.example", map[string]string{"address": "rua@example.com"})
	require.Equal(t, http.StatusNotFound, code, body)
	code, body = root("PUT", "addresses/example.com", map[string]string{"address": "rua@other.example"})
	require.Equal(t, http.StatusOK, code, body)

	started1 := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range seen {
			if r == "POST /v1/admin/dmarc/addresses/example.com/backfill" {
				return true
			}
		}
		return false
	}
	mu.Lock()
	auditDown = true
	mu.Unlock()
	code, body = root("POST", "addresses/example.com/backfill", nil)
	require.Equal(t, http.StatusServiceUnavailable, code, body)
	require.False(t, started1(), "read a mailbox without recording it")
	mu.Lock()
	auditDown = false
	mu.Unlock()
	code, body = root("POST", "addresses/example.com/backfill", nil)
	require.Equal(t, http.StatusAccepted, code, body)
	require.True(t, started1())
}
