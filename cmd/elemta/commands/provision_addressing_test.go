package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
)

type memDomains struct {
	mu    sync.Mutex
	names []string
}

func (m *memDomains) List(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.names...), nil
}
func (m *memDomains) Set(_ context.Context, names []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.names = names
	return nil
}

// fakeAddressing serves lists, routes and address lookups.
type fakeAddressing struct {
	mu     sync.Mutex
	lists  map[string]mailpolicy.List
	routes map[string]mailpolicy.DomainRoute
}

func (f *fakeAddressing) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/admin/")
	enc := json.NewEncoder(w)
	switch {
	case r.Method == "GET" && strings.HasPrefix(p, "addresses/"):
		a := strings.TrimPrefix(p, "addresses/")
		kind := map[string]string{"dana@example.com": "account"}[a]
		if _, ok := f.lists[a]; ok {
			kind = "list"
		}
		_ = enc.Encode(mailpolicy.AddressInfo{Address: a, Kind: kind})
	case r.Method == "GET" && p == "lists":
		out := []mailpolicy.List{}
		for _, l := range f.lists {
			l.MemberCount = len(l.Members)
			out = append(out, l)
		}
		_ = enc.Encode(out)
	case strings.HasPrefix(p, "lists/") && strings.HasSuffix(p, "/members"):
		a := strings.TrimSuffix(strings.TrimPrefix(p, "lists/"), "/members")
		var in struct{ Add, Remove []string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		l := f.lists[a]
		l.Members = append(l.Members, in.Add...)
		f.lists[a] = l
		_ = enc.Encode(l)
	case strings.HasPrefix(p, "lists/"):
		a := strings.TrimPrefix(p, "lists/")
		switch r.Method {
		case "GET":
			l, ok := f.lists[a]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"no list"}`))
				return
			}
			_ = enc.Encode(l)
		case "PUT":
			var l mailpolicy.List
			_ = json.NewDecoder(r.Body).Decode(&l)
			f.lists[a] = l
			_ = enc.Encode(l)
		case "DELETE":
			delete(f.lists, a)
			_ = enc.Encode(map[string]bool{"ok": true})
		}
	case r.Method == "GET" && p == "routes":
		out := []mailpolicy.DomainRoute{}
		for _, rt := range f.routes {
			out = append(out, rt)
		}
		_ = enc.Encode(out)
	case r.Method == "PUT" && strings.HasPrefix(p, "routes/"):
		var rt mailpolicy.DomainRoute
		_ = json.NewDecoder(r.Body).Decode(&rt)
		rt.Domain = strings.TrimPrefix(p, "routes/")
		f.routes[rt.Domain] = rt
		_ = enc.Encode(rt)
	default:
		http.NotFound(w, r)
	}
}

func TestProvisionCLIAddressing(t *testing.T) {
	fake := &fakeAddressing{lists: map[string]mailpolicy.List{}, routes: map[string]mailpolicy.DomainRoute{}}
	api := httptest.NewServer(fake)
	t.Cleanup(api.Close)
	client, _ := mailpolicy.NewClient(api.URL, "token")
	domains := &memDomains{names: []string{"example.com"}}
	run := func(args ...string) (string, error) {
		cmd := newProvisionCommand(func() (*provision.Service, error) {
			return &provision.Service{Directory: goneDirectory{}, Routing: domains, Mailbox: client}, nil
		})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}

	if _, err := run("create-list", "team@example.com", "--name", "Team", "--posting", "members", "--members", "dana@example.com, ext@remote.example"); err != nil {
		t.Fatal(err)
	}
	if l := fake.lists["team@example.com"]; l.Posting != "members" || len(l.Members) != 2 {
		t.Fatalf("list saved as %+v", l)
	}
	if _, err := run("create-list", "team@example.com"); err == nil {
		t.Error("creating an existing list succeeded")
	}
	if _, err := run("create-list", "x@elsewhere.example"); err == nil || !strings.Contains(err.Error(), "configure domain") {
		t.Errorf("list outside a local domain: %v", err)
	}
	if _, err := run("add-members", "team@example.com", "a@remote.example", "b@remote.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("set-list", "team@example.com", "--owner", "dana@example.com"); err != nil {
		t.Fatal(err)
	}
	out, err := run("get-list", "team@example.com")
	if err != nil || !strings.Contains(out, "b@remote.example") || !strings.Contains(out, "Owner:        dana@example.com") || !strings.Contains(out, "Members:      4") {
		t.Fatalf("get-list: %v\n%s", err, out)
	}
	// A list's address can't become an account alias.
	cmd := newProvisionCommand(func() (*provision.Service, error) {
		return &provision.Service{Directory: goneDirectory{}, Routing: domains, Mailbox: client}, nil
	})
	cmd.SetArgs([]string{"aaa", "dana@example.com", "team@example.com"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "distribution list") {
		t.Fatalf("alias on a list address: %v", err)
	}

	// Catch-all: the target must exist.
	if _, err := run("set-catch-all", "example.com", "nobody@example.com"); err == nil {
		t.Error("catch-all to a missing address accepted")
	}
	if _, err := run("set-catch-all", "example.com", "dana@example.com"); err != nil || fake.routes["example.com"].CatchAll != "dana@example.com" {
		t.Fatalf("catch-all: %v %+v", err, fake.routes)
	}

	// A domain alias adds the alias as a local domain and keeps the catch-all.
	if _, err := run("create-domain-alias", "example.net", "example.com"); err != nil {
		t.Fatal(err)
	}
	names, _ := domains.List(context.Background())
	if strings.Join(names, ",") != "example.com,example.net" || fake.routes["example.net"].AliasOf != "example.com" {
		t.Fatalf("after domain alias: %v %+v", names, fake.routes)
	}
	if _, err := run("create-domain-alias", "example.com", "example.net"); err == nil {
		t.Error("an existing local domain became an alias")
	}
	if _, err := run("delete-domain-alias", "example.net"); err != nil {
		t.Fatal(err)
	}
	if names, _ = domains.List(context.Background()); strings.Join(names, ",") != "example.com" {
		t.Fatalf("after removing the alias: %v", names)
	}
	if out, err := run("list-domains"); err != nil || !strings.Contains(out, "dana@example.com") {
		t.Fatalf("list-domains: %v\n%s", err, out)
	}
}
