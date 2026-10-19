package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
)

// goneDirectory knows only dana@example.com; any other address is deleted.
type goneDirectory struct{ cliDirectory }

func (goneDirectory) Get(_ context.Context, address string) (provision.Account, error) {
	if address != "dana@example.com" {
		return provision.Account{}, provision.ErrNotFound
	}
	return provision.Account{Address: address, Status: "active", Aliases: []string{}}, nil
}

// fakeMailboxAdmin keeps classes in memory and records purges.
type fakeMailboxAdmin struct {
	mu      sync.Mutex
	classes map[string]mailpolicy.Class
	purged  []string
}

func (f *fakeMailboxAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/admin/")
	switch {
	case r.Method == "GET" && path == "classes":
		out := []mailpolicy.Class{}
		for _, c := range f.classes {
			out = append(out, c)
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == "GET" && strings.HasPrefix(path, "classes/"):
		c, ok := f.classes[strings.TrimPrefix(path, "classes/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"no such class"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(c)
	case r.Method == "PUT" && strings.HasPrefix(path, "classes/"):
		var c mailpolicy.Class
		_ = json.NewDecoder(r.Body).Decode(&c)
		f.classes[c.Name] = c
		_ = json.NewEncoder(w).Encode(c)
	case r.Method == "POST" && strings.HasSuffix(path, "/purge"):
		address := strings.TrimSuffix(strings.TrimPrefix(path, "accounts/"), "/purge")
		f.purged = append(f.purged, address)
		_ = json.NewEncoder(w).Encode(mailpolicy.PurgeResult{Address: address, Accounts: 1, Messages: 3})
	default:
		http.NotFound(w, r)
	}
}

func TestProvisionCLIClassesAndPurge(t *testing.T) {
	admin := &fakeMailboxAdmin{classes: map[string]mailpolicy.Class{}}
	api := httptest.NewServer(admin)
	t.Cleanup(api.Close)
	client, err := mailpolicy.NewClient(api.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := newProvisionCommand(func() (*provision.Service, error) {
			return &provision.Service{Directory: goneDirectory{}, Mailbox: client}, nil
		})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}

	if _, err := run("set-class", "staff", "--description", "Staff", "--quota", "5G", "--max-attachment", "10M", "--protocols", "pop3=off,imap=on", "--filters", "off"); err != nil {
		t.Fatal(err)
	}
	s := admin.classes["staff"].Settings
	if *s.QuotaBytes != 5<<30 || *s.MaxAttachmentBytes != 10<<20 || s.Protocols["pop3"] || !s.Protocols["imap"] || *s.Filters {
		t.Fatalf("class saved as %+v", s)
	}
	// Changing one setting keeps the others; "inherit" unsets one.
	if _, err := run("set-class", "staff", "--quota", "inherit", "--protocols", "imap=inherit"); err != nil {
		t.Fatal(err)
	}
	s = admin.classes["staff"].Settings
	if s.QuotaBytes != nil || s.MaxAttachmentBytes == nil || len(s.Protocols) != 1 || admin.classes["staff"].Description != "Staff" {
		t.Fatalf("after a partial change: %+v", admin.classes["staff"])
	}
	if _, err := run("set-class", "staff", "--protocols", "gopher=on"); err == nil {
		t.Error("unknown protocol accepted")
	}
	if _, err := run("set-class", "staff", "--filters", "maybe"); err == nil {
		t.Error("bad switch value accepted")
	}
	out, err := run("get-class", "staff")
	if err != nil || !strings.Contains(out, "max attachment:  10M") || !strings.Contains(out, "protocol pop3:   off") {
		t.Fatalf("get-class: %v\n%s", err, out)
	}

	// Purge needs the confirmation, and refuses an account that still exists.
	if _, err := run("purge-account", "gone@example.com"); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("purge without confirmation: %v", err)
	}
	if _, err := run("purge-account", "dana@example.com", "--confirm", "dana@example.com"); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("purge of a live account: %v", err)
	}
	out, err = run("purge-account", "gone@example.com", "--confirm", "gone@example.com")
	if err != nil || len(admin.purged) != 1 || admin.purged[0] != "gone@example.com" || !strings.Contains(out, "3 messages") {
		t.Fatalf("purge: %v %v\n%s", err, admin.purged, out)
	}

	// Without the admin API the commands explain what to set.
	cmd := newProvisionCommand(func() (*provision.Service, error) { return &provision.Service{Directory: goneDirectory{}}, nil })
	cmd.SetArgs([]string{"list-classes"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), mailpolicy.TokenEnv) {
		t.Fatalf("without the admin API: %v", err)
	}
}
