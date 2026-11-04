package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// complianceMailbox answers the mailbox's compliance and audit endpoints.
type complianceMailbox struct {
	mu        sync.Mutex
	queries   []mailpolicy.ComplianceQuery
	audit     []mailpolicy.AuditEntry
	auditDown bool
}

func (m *complianceMailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.URL.Path {
	case "/v1/admin/audit":
		if m.auditDown {
			http.Error(w, `{"error":"unavailable"}`, http.StatusInternalServerError)
			return
		}
		var e mailpolicy.AuditEntry
		_ = json.NewDecoder(r.Body).Decode(&e)
		m.audit = append(m.audit, e)
		_ = json.NewEncoder(w).Encode(e)
	case "/v1/admin/compliance/search", "/v1/admin/compliance/export":
		var q mailpolicy.ComplianceQuery
		_ = json.NewDecoder(r.Body).Decode(&q)
		m.queries = append(m.queries, q)
		if strings.HasSuffix(r.URL.Path, "export") {
			w.Header().Set("Content-Type", "application/mbox")
			_, _ = io.WriteString(w, "From MAILER-DAEMON Mon Nov  2 10:00:00 2026\nSubject: found\n\nbody\n\n")
			return
		}
		_ = json.NewEncoder(w).Encode(mailpolicy.ComplianceResult{Total: 1, Unindexed: 2, Hits: []mailpolicy.ComplianceHit{{Ref: "m:7:3", Account: "dana@example.com", Folder: "INBOX", From: "Dana <dana@example.com>", Subject: "found <b>not markup</b>", Size: 2048, Date: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)}}})
	case "/v1/admin/compliance/message":
		if r.URL.Query().Get("ref") != "m:7:3" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not found"}`)
			return
		}
		w.Header().Set(mailpolicy.ComplianceAccountHeader, "dana@example.com")
		_, _ = io.WriteString(w, "Subject: found\r\n\r\nbody\r\n")
	default:
		http.NotFound(w, r)
	}
}

func (m *complianceMailbox) entries() []mailpolicy.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailpolicy.AuditEntry(nil), m.audit...)
}

// startComplianceServer runs the dashboard with a compliance officer, the
// other roles, and a fake mailbox.
func startComplianceServer(t *testing.T, webRoot string) (string, *complianceMailbox) {
	t.Helper()
	dir := t.TempDir()
	hash := func(pw string) string {
		h, err := auth.HashPassword(pw)
		require.NoError(t, err)
		return h
	}
	users := filepath.Join(dir, "users")
	require.NoError(t, os.WriteFile(users, []byte(
		"root:"+hash(testAdminPassword)+":admin\n"+
			"officer:"+hash(testUserPassword)+":compliance\n"+
			"viewer:"+hash(testUserPassword)+":user\n"+
			"deleg:"+hash(testDomainAdminPassword)+":domain-admin,domain:example.com\n"), 0o600))
	if webRoot == "" {
		webRoot = dir
	}
	s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: webRoot, AuthEnabled: true, AuthFile: users}, nil, dir, 0, "")
	require.NoError(t, err)
	fake := &complianceMailbox{}
	mailbox := httptest.NewServer(fake)
	t.Cleanup(mailbox.Close)
	client, err := mailpolicy.NewClient(mailbox.URL, "token")
	require.NoError(t, err)
	s.SetProvisioner(&provision.Service{Mailbox: client})
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	return "http://" + waitReady(t, s), fake
}

func TestComplianceSearchAndExport(t *testing.T) {
	base, fake := startComplianceServer(t, "")

	query := map[string]any{"text": "merger", "since": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "domains": []string{"sneaky.example"}}

	// Only system administrators and the compliance role.
	for _, who := range []struct{ user, password string }{{"viewer", testUserPassword}, {"deleg", testDomainAdminPassword}} {
		code, body := userRequest(t, "POST", base+"/api/compliance/search", who.user, who.password, query)
		require.Equal(t, http.StatusForbidden, code, "%s: %s", who.user, body)
		code, _ = userRequest(t, "GET", base+"/api/compliance/message?ref=m:7:3", who.user, who.password, nil)
		require.Equal(t, http.StatusForbidden, code, who.user)
	}
	require.Empty(t, fake.entries())

	code, body := userRequest(t, "POST", base+"/api/compliance/search", "officer", testUserPassword, query)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"account":"dana@example.com"`)
	code, body = userRequest(t, "POST", base+"/api/compliance/search", "root", testAdminPassword, query)
	require.Equal(t, http.StatusOK, code, body)
	// The searcher can't set the domains a search is confined to.
	require.Len(t, fake.queries, 2)
	require.Empty(t, fake.queries[0].Domains)
	// Every search is recorded, away from domain administrators.
	entries := fake.entries()
	require.Len(t, entries, 2)
	require.Equal(t, "officer", entries[0].Actor)
	require.Equal(t, "compliance-search", entries[0].Action)
	require.Equal(t, "all mailboxes", entries[0].Target)
	require.Equal(t, "(system)", entries[0].Domain)
	require.Equal(t, `words "merger"; since 2026-01-01: 1 found`, entries[0].Detail)

	// An empty search is refused before reaching the mailbox.
	code, body = userRequest(t, "POST", base+"/api/compliance/search", "officer", testUserPassword, map[string]any{})
	require.Equal(t, http.StatusBadRequest, code)
	require.Contains(t, body, "give at least one")
	require.Len(t, fake.queries, 2)

	// Export, as the browser's form posts it: a file to save.
	form := url.Values{"query": {`{"accounts":["dana@example.com"],"text":"merger"}`}}
	req, err := http.NewRequest("POST", base+"/api/compliance/export", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth("officer", testUserPassword)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	require.Equal(t, "application/mbox", resp.Header.Get("Content-Type"))
	require.Contains(t, resp.Header.Get("Content-Disposition"), `attachment; filename="compliance-export-`)
	require.Contains(t, string(data), "Subject: found")
	entries = fake.entries()
	require.Equal(t, "compliance-export", entries[2].Action)
	require.Equal(t, "dana@example.com", entries[2].Target)

	// One message, recorded against the account the mailbox names.
	code, body = userRequest(t, "GET", base+"/api/compliance/message?ref=m:7:3", "officer", testUserPassword, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "Subject: found")
	entries = fake.entries()
	require.Equal(t, "compliance-view", entries[3].Action)
	require.Equal(t, "dana@example.com", entries[3].Target)
	for _, ref := range []string{"m:7:4", "x", "m:1:1\r\nX: y", "../../etc"} {
		code, _ = userRequest(t, "GET", base+"/api/compliance/message?ref="+url.QueryEscape(ref), "officer", testUserPassword, nil)
		require.Equal(t, http.StatusNotFound, code, ref)
	}
	require.Len(t, fake.entries(), 4, "nothing found, nothing recorded")

	// What can't be recorded isn't done.
	fake.mu.Lock()
	fake.auditDown = true
	fake.mu.Unlock()
	code, body = userRequest(t, "POST", base+"/api/compliance/search", "officer", testUserPassword, query)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.NotContains(t, body, "dana@example.com")
	code, body = userRequest(t, "POST", base+"/api/compliance/export", "officer", testUserPassword, query)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.NotContains(t, body, "Subject: found")
	code, body = userRequest(t, "GET", base+"/api/compliance/message?ref=m:7:3", "officer", testUserPassword, nil)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.NotContains(t, body, "Subject: found")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	// The refused search ran and was thrown away; the export never started.
	require.Len(t, fake.queries, 4)
}
