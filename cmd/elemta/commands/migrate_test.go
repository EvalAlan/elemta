package commands

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
)

// memDirectory is a directory that really creates accounts.
type memDirectory struct {
	mu       sync.Mutex
	accounts map[string]*provision.Account
	created  []string
}

func (d *memDirectory) List(context.Context) ([]provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []provision.Account
	for _, a := range d.accounts {
		out = append(out, *a)
	}
	return out, nil
}
func (d *memDirectory) Get(_ context.Context, address string) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[address]; ok {
		return *a, nil
	}
	return provision.Account{}, provision.ErrNotFound
}
func (d *memDirectory) Create(_ context.Context, in provision.Create) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := &provision.Account{Address: in.Address, Name: in.Name, Status: "active", QuotaBytes: in.QuotaBytes, Aliases: []string{}}
	d.accounts[in.Address] = a
	d.created = append(d.created, in.Address)
	return *a, nil
}
func (d *memDirectory) Update(context.Context, string, provision.Patch) (provision.Account, error) {
	return provision.Account{}, provision.ErrUnavailable
}
func (d *memDirectory) Delete(context.Context, string) error { return provision.ErrUnavailable }
func (d *memDirectory) Alias(_ context.Context, address, alias string, add bool) (provision.Account, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.accounts[address]
	a.Aliases = append(a.Aliases, alias)
	return *a, nil
}

func TestMigrateAccountsCSV(t *testing.T) {
	fake := &fakeAddressing{lists: map[string]mailpolicy.List{}, routes: map[string]mailpolicy.DomainRoute{}}
	api := httptest.NewServer(fake)
	t.Cleanup(api.Close)
	client, _ := mailpolicy.NewClient(api.URL, "token")
	dir := &memDirectory{accounts: map[string]*provision.Account{}}
	domains := &memDomains{names: []string{"example.com"}}
	csvPath := filepath.Join(t.TempDir(), "accounts.csv")
	csv := "type,address,name,quota,password,aliases,class,members,owner,posting\n" +
		"# comment lines are skipped\n" +
		"account,dana@example.com,Dana Jones,5G,a-long-initial-password,dj@example.com;dana.jones@example.com,,,,\n" +
		"account,lee@example.com,,0,,,,,,\n" +
		"list,team@example.com,Team,,,,,dana@example.com|lee@example.com|partner@other.example,dana@example.com,members\n" +
		"account,bad-address,,,,,,,,\n"
	if err := os.WriteFile(csvPath, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	squash := func(v string) string { return strings.Join(strings.Fields(v), " ") }
	run := func() (string, error) {
		cmd := newMigrateCommand(func() (*provision.Service, error) {
			return &provision.Service{Directory: dir, Routing: domains, Mailbox: client}, nil
		})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"accounts", "--csv", csvPath})
		err := cmd.Execute()
		return squash(out.String()), err
	}
	out, err := run()
	if err == nil || !strings.Contains(err.Error(), "1 rows had problems") {
		t.Fatalf("expected the bad row reported: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Accounts created: 2") || !strings.Contains(out, "Aliases added: 2") || !strings.Contains(out, "Lists saved: 1") {
		t.Errorf("summary:\n%s", out)
	}
	if !strings.Contains(out, "Random passwords (reset before use): lee@example.com") || strings.Contains(out, "a-long-initial-password") {
		t.Errorf("password reporting:\n%s", out)
	}
	if l := fake.lists["team@example.com"]; l.Owner != "dana@example.com" || len(l.Members) != 3 || l.Posting != "members" {
		t.Errorf("list = %+v", l)
	}
	// The same file again changes nothing.
	out, _ = run()
	if !strings.Contains(out, "Accounts created: 0") || !strings.Contains(out, "Accounts already there: 2") || !strings.Contains(out, "Aliases added: 0") || len(dir.created) != 2 {
		t.Errorf("rerun:\n%s", out)
	}
}
