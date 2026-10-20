package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/stretchr/testify/require"
)

// fakeMailboxAdmin is just enough of the mailbox admin API for the
// dashboard routes: classes, account policy, purge, lists and routes.
type fakeMailboxAdmin struct {
	mu      sync.Mutex
	classes map[string]mailpolicy.Class
	policy  map[string]mailpolicy.AccountPolicy
	lists   map[string]mailpolicy.List
	routes  map[string]mailpolicy.DomainRoute
	purged  []string
	held    map[string]bool
	audit   []mailpolicy.AuditEntry
	queries []string // audit queries received
}

func (f *fakeMailboxAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/admin/")
	enc := json.NewEncoder(w)
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = enc.Encode(map[string]string{"error": msg})
	}
	switch {
	case p == "classes":
		out := []mailpolicy.Class{}
		for _, c := range f.classes {
			out = append(out, c)
		}
		_ = enc.Encode(out)
	case p == "domains":
		_ = enc.Encode([]mailpolicy.DomainPolicy{})
	case strings.HasPrefix(p, "classes/"):
		name := strings.TrimPrefix(p, "classes/")
		if r.Method == "DELETE" {
			fail(http.StatusConflict, "class \""+name+"\" is still used by accounts or domains; move them first")
			return
		}
		var c mailpolicy.Class
		_ = json.NewDecoder(r.Body).Decode(&c)
		if c.Settings.QuotaBytes != nil && *c.Settings.QuotaBytes < 0 {
			fail(http.StatusBadRequest, "quota_bytes must be 0 (unlimited) up to 1 PiB")
			return
		}
		f.classes[name] = c
		_ = enc.Encode(c)
	case strings.HasPrefix(p, "accounts/") && strings.HasSuffix(p, "/policy"):
		a := strings.TrimSuffix(strings.TrimPrefix(p, "accounts/"), "/policy")
		if r.Method == "PUT" {
			var ap mailpolicy.AccountPolicy
			_ = json.NewDecoder(r.Body).Decode(&ap)
			f.policy[a] = ap
		}
		eff := mailpolicy.Builtin()
		eff.Address, eff.Class = a, f.policy[a].Class
		eff.LegalHold = f.held[a]
		_ = enc.Encode(mailpolicy.AccountView{Policy: f.policy[a], Effective: eff})
	case strings.HasPrefix(p, "accounts/") && strings.HasSuffix(p, "/purge"):
		a := strings.TrimSuffix(strings.TrimPrefix(p, "accounts/"), "/purge")
		f.purged = append(f.purged, a)
		_ = enc.Encode(mailpolicy.PurgeResult{Address: a, Accounts: 1, Messages: 7})
	case strings.HasPrefix(p, "addresses/"):
		_ = enc.Encode(mailpolicy.AddressInfo{Address: strings.TrimPrefix(p, "addresses/")})
	case p == "lists":
		out := []mailpolicy.List{}
		for _, l := range f.lists {
			out = append(out, l)
		}
		_ = enc.Encode(out)
	case strings.HasPrefix(p, "lists/"):
		a := strings.TrimPrefix(p, "lists/")
		switch r.Method {
		case "GET":
			l, ok := f.lists[a]
			if !ok {
				fail(http.StatusNotFound, "no list "+a)
				return
			}
			_ = enc.Encode(l)
		case "PUT":
			var l mailpolicy.List
			_ = json.NewDecoder(r.Body).Decode(&l)
			l.Address = a
			f.lists[a] = l
			_ = enc.Encode(l)
		case "DELETE":
			delete(f.lists, a)
			_ = enc.Encode(map[string]bool{"ok": true})
		}
	case p == "audit" && r.Method == "POST":
		var e mailpolicy.AuditEntry
		_ = json.NewDecoder(r.Body).Decode(&e)
		if err := e.Validate(); err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		e.ID = int64(len(f.audit) + 1)
		f.audit = append(f.audit, e)
		_ = enc.Encode(e)
	case p == "audit":
		f.queries = append(f.queries, r.URL.RawQuery)
		domains := r.URL.Query()["domain"]
		out := []mailpolicy.AuditEntry{}
		for i := len(f.audit) - 1; i >= 0; i-- {
			e := f.audit[i]
			keep := len(domains) == 0
			for _, d := range domains {
				keep = keep || e.Domain == d
			}
			if keep {
				out = append(out, e)
			}
		}
		_ = enc.Encode(out)
	case p == "routes":
		out := []mailpolicy.DomainRoute{}
		for _, rt := range f.routes {
			out = append(out, rt)
		}
		_ = enc.Encode(out)
	case strings.HasPrefix(p, "routes/"):
		var rt mailpolicy.DomainRoute
		_ = json.NewDecoder(r.Body).Decode(&rt)
		rt.Domain = strings.TrimPrefix(p, "routes/")
		f.routes[rt.Domain] = rt
		_ = enc.Encode(rt)
	default:
		fail(http.StatusNotFound, "no such route")
	}
}

func TestMailboxAdministrationPolicyAndLists(t *testing.T) {
	base, service := startProvisionAPI(t)
	fake := &fakeMailboxAdmin{classes: map[string]mailpolicy.Class{}, policy: map[string]mailpolicy.AccountPolicy{}, lists: map[string]mailpolicy.List{}, routes: map[string]mailpolicy.DomainRoute{}}
	api := httptest.NewServer(fake)
	t.Cleanup(api.Close)
	call := func(method, path string, body any) (int, string) {
		return userRequest(t, method, base+"/api/provision"+path, "root", testAdminPassword, body)
	}

	// Without the admin API configured the routes explain what to set.
	code, body := call("GET", "/classes", nil)
	require.Equal(t, http.StatusServiceUnavailable, code, body)
	require.Contains(t, body, mailpolicy.TokenEnv)
	code, body = call("GET", "/status", nil)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"mailbox_admin":false`)

	client, err := mailpolicy.NewClient(api.URL, "token")
	require.NoError(t, err)
	service.Mailbox = client
	code, body = call("GET", "/status", nil)
	require.Contains(t, body, `"mailbox_admin":true`, body)

	// A viewer can't reach any of it.
	code, _ = userRequest(t, "GET", base+"/api/provision/classes", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusForbidden, code)

	code, body = call("PUT", "/classes/staff", map[string]any{"description": "Staff", "settings": map[string]any{"quota_bytes": 5 << 30, "protocols": map[string]bool{"pop3": false}}})
	require.Equal(t, http.StatusOK, code, body)
	code, body = call("GET", "/classes", nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"staff"`)
	require.Contains(t, body, `"protocols":["imap","pop3","webmail","dav","submission"]`)
	// The mailbox's own refusals come through with their reasons.
	code, body = call("PUT", "/classes/staff", map[string]any{"settings": map[string]any{"quota_bytes": -1}})
	require.Equal(t, http.StatusBadRequest, code, body)
	require.Contains(t, body, "quota_bytes")
	code, body = call("DELETE", "/classes/staff", nil)
	require.Equal(t, http.StatusConflict, code, body)
	require.Contains(t, body, "still used")

	code, body = call("PUT", "/accounts/dana@example.com/policy", map[string]any{"class": "staff"})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, `"class":"staff"`)

	// Lists.
	code, body = call("POST", "/lists", map[string]any{"address": "team@example.com", "name": "Team", "posting": "members", "members": []string{"a@example.com"}})
	require.Equal(t, http.StatusCreated, code, body)
	code, body = call("POST", "/lists", map[string]any{"address": "team@example.com"})
	require.Equal(t, http.StatusConflict, code, body)
	code, body = call("POST", "/lists", map[string]any{"address": "x@not-local.example"})
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = call("PUT", "/lists/team@example.com", map[string]any{"name": "Team", "members": []string{"a@example.com", "b@example.com"}})
	require.Equal(t, http.StatusOK, code, body)
	require.Len(t, fake.lists["team@example.com"].Members, 2)
	code, body = call("DELETE", "/lists/team@example.com", nil)
	require.Equal(t, http.StatusOK, code, body)

	// Delete with purge removes the account and its mailbox.
	code, body = call("POST", "/accounts", map[string]any{"address": "gone@example.com", "name": "Gone", "password": "private-initial-password"})
	require.Equal(t, http.StatusCreated, code, body)
	code, body = call("DELETE", "/accounts/gone@example.com", map[string]any{"confirm": "gone@example.com", "purge": true})
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "purged (7 messages)")
	require.Equal(t, []string{"gone@example.com"}, fake.purged)
	code, body = call("POST", "/purge", map[string]any{"address": "old@example.com", "confirm": "wrong@example.com"})
	require.Equal(t, http.StatusBadRequest, code, body)
}
