package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type memoryDirectory struct{ accounts map[string]Account }

func (m *memoryDirectory) List(context.Context) ([]Account, error) {
	out := []Account{}
	for _, a := range m.accounts {
		out = append(out, a)
	}
	return out, nil
}
func (m *memoryDirectory) Get(_ context.Context, key string) (Account, error) {
	a, ok := m.accounts[key]
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}
func (m *memoryDirectory) Create(_ context.Context, in Create) (Account, error) {
	if _, ok := m.accounts[in.Address]; ok {
		return Account{}, ErrExists
	}
	a := Account{Address: in.Address, Name: in.Name, Status: "active", QuotaBytes: in.QuotaBytes, Aliases: []string{}}
	m.accounts[a.Address] = a
	return a, nil
}
func (m *memoryDirectory) Update(ctx context.Context, key string, p Patch) (Account, error) {
	a, err := m.Get(ctx, key)
	if err != nil {
		return a, err
	}
	if p.Name != nil {
		a.Name = *p.Name
	}
	if p.Status != nil {
		a.Status = *p.Status
	}
	if p.QuotaBytes != nil {
		a.QuotaBytes = *p.QuotaBytes
	}
	m.accounts[key] = a
	return a, nil
}
func (m *memoryDirectory) Delete(ctx context.Context, key string) error {
	if _, err := m.Get(ctx, key); err != nil {
		return err
	}
	delete(m.accounts, key)
	return nil
}
func (m *memoryDirectory) Alias(ctx context.Context, key, alias string, add bool) (Account, error) {
	a, err := m.Get(ctx, key)
	if err != nil {
		return a, err
	}
	if add {
		a.Aliases = append(a.Aliases, alias)
	} else {
		a.Aliases = []string{}
	}
	m.accounts[key] = a
	return a, nil
}
func testService(t *testing.T) *Service {
	t.Helper()
	path := filepath.Join(t.TempDir(), "elemta.toml")
	if err := os.WriteFile(path, []byte("# preserve this comment\nlocal_domains = [\"example.com\"]\n[webmail]\npage_size = 50\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Service{Directory: &memoryDirectory{accounts: map[string]Account{}}, Routing: FileDomains{Path: path}, Revoke: func(context.Context, string) error { return nil }, Reset: func(context.Context, string, string) error { return nil }}
}
func TestAccountValidationAndRevocation(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	for _, address := range []string{"../../etc/passwd@example.com", "x@y@z", "a\nb@example.com", "a..b@example.com", "a@-bad.example", "\"quoted\"@example.com"} {
		if _, err := Address(address); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %q", address)
		}
	}
	in := Create{Address: "Dana@Example.COM", Name: "Dana", Password: "long secure password", QuotaBytes: 5 << 30}
	a, err := s.Create(ctx, in)
	if err != nil || a.Address != "dana@example.com" {
		t.Fatalf("create: %+v %v", a, err)
	}
	in.Address = "other@unknown.example"
	if _, err = s.Create(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("unconfigured domain accepted")
	}
	in.Address = "other@example.com"
	in.Password = "short"
	if _, err = s.Create(ctx, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("weak password accepted")
	}
	if _, err = s.Alias(ctx, a.Address, a.Address, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("primary address accepted as alias")
	}
	if _, err = s.Alias(ctx, a.Address, "sales@unknown.example", true); !errors.Is(err, ErrInvalid) {
		t.Fatal("alias outside local domains")
	}
	disabled := "disabled"
	calls := 0
	s.Revoke = func(ctx context.Context, key string) error { calls++; return nil }
	if _, err = s.Update(ctx, a.Address, Patch{Status: &disabled}); err != nil || calls != 2 {
		t.Fatalf("suspend revocation: %d %v", calls, err)
	}
	s.Revoke = func(context.Context, string) error { return errors.New("session store offline") }
	if err = s.Delete(ctx, a.Address); err == nil {
		t.Fatal("delete bypassed revocation failure")
	}
	if _, err = s.Get(ctx, a.Address); err != nil {
		t.Fatal("account removed despite failed revocation")
	}
	s.Reset = func(context.Context, string, string) error { return errors.New("directory refused reset") }
	if err = s.Password(ctx, a.Address, "another secure password"); err == nil {
		t.Fatal("reset failure hidden")
	}
}
func TestDomainsPreserveConfigAndRejectOccupiedDeletion(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	if err := s.Domain(ctx, "second.example", true); err != nil {
		t.Fatal(err)
	}
	in := Create{Address: "dana@second.example", Name: "Dana", Password: "long secure password"}
	if _, err := s.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := s.Domain(ctx, "second.example", false); !errors.Is(err, ErrInvalid) {
		t.Fatal("occupied domain removed")
	}
	doc, err := os.ReadFile(s.Routing.(FileDomains).Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "# preserve this comment") || !strings.Contains(string(doc), "page_size = 50") {
		t.Fatal("unrelated config lost")
	}
	if err = s.Domain(ctx, "example.com", true); !errors.Is(err, ErrExists) {
		t.Fatal("duplicate domain accepted")
	}
}
func TestQuotaBounds(t *testing.T) {
	for raw, want := range map[string]int64{"0": 0, "5G": 5 << 30, "20MiB": 20 << 20, "1024": 1024} {
		got, err := ParseQuota(raw)
		if err != nil || got != want {
			t.Fatalf("%s: %d %v", raw, got, err)
		}
	}
	for _, raw := range []string{"-1", "1.5G", "9999999999999999999G", "9000000G"} {
		if _, err := ParseQuota(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %q", raw)
		}
	}
}
func TestConfigLockIsSharedAndCancellable(t *testing.T) {
	s := testService(t)
	routing := s.Routing.(FileDomains)
	unlock, err := routing.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = (FileDomains{Path: routing.Path}).Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second writer did not wait: %v", err)
	}
}
