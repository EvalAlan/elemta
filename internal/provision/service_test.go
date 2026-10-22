package provision

import (
	"context"
	"errors"
	"fmt"
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
	if p.Forward != nil {
		a.Forward = *p.Forward
	}
	if p.ForwardKeepCopy != nil {
		a.ForwardKeepCopy = *p.ForwardKeepCopy
	}
	if p.SendAs != nil {
		a.SendAs = *p.SendAs
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

func TestSuspendedStatus(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	var revoked []string
	s.Revoke = func(_ context.Context, a string) error { revoked = append(revoked, a); return nil }
	a, err := s.Create(ctx, Create{Address: "lee@example.com", Name: "Lee", Password: "long secure password"})
	if err != nil {
		t.Fatal(err)
	}
	suspended := "suspended"
	got, err := s.Update(ctx, a.Address, Patch{Status: &suspended})
	if err != nil || got.Status != "suspended" {
		t.Fatalf("suspend: %+v %v", got, err)
	}
	if len(revoked) == 0 {
		t.Error("suspending didn't end the account's sessions")
	}
	frozen := "frozen"
	if _, err := s.Update(ctx, a.Address, Patch{Status: &frozen}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown status accepted: %v", err)
	}
}

func TestForwardingAndSendAs(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	a, err := s.Create(ctx, Create{Address: "kim@example.com", Name: "Kim", Password: "long secure password"})
	if err != nil {
		t.Fatal(err)
	}
	keep := true
	got, err := s.Update(ctx, a.Address, Patch{
		Forward:         &[]string{" Far@Remote.Example ", "far@remote.example", ""},
		ForwardKeepCopy: &keep,
		SendAs:          &[]string{"Sales@Example.com", "@Brand.Example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Forward, ",") != "far@remote.example" || !got.ForwardKeepCopy {
		t.Errorf("forwarding = %v keep %v", got.Forward, got.ForwardKeepCopy)
	}
	if strings.Join(got.SendAs, ",") != "sales@example.com,@brand.example" {
		t.Errorf("send as = %v", got.SendAs)
	}
	for name, p := range map[string]Patch{
		"forward to itself":  {Forward: &[]string{"kim@example.com"}},
		"bad forward":        {Forward: &[]string{"not an address"}},
		"bad send-as domain": {SendAs: &[]string{"@-bad-"}},
	} {
		if _, err := s.Update(ctx, a.Address, p); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	// Three by default, without a class of service saying otherwise.
	four := []string{"a@remote.example", "b@remote.example", "c@remote.example", "d@remote.example"}
	if _, err := s.Update(ctx, a.Address, Patch{Forward: &four}); !errors.Is(err, ErrInvalid) {
		t.Errorf("four forwarding addresses accepted by default: %v", err)
	}
	many := make([]string, maxForward+1)
	for i := range many {
		many[i] = fmt.Sprintf("f%d@remote.example", i)
	}
	if _, err := s.Update(ctx, a.Address, Patch{Forward: &many}); !errors.Is(err, ErrInvalid) {
		t.Errorf("%d forwarding addresses accepted: %v", len(many), err)
	}
	if got, err := s.Update(ctx, a.Address, Patch{Forward: &[]string{}}); err != nil || len(got.Forward) != 0 {
		t.Errorf("clearing forwarding: %v %v", got.Forward, err)
	}
}
