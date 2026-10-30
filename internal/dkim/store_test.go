package dkim

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempStore(t *testing.T) Store {
	t.Helper()
	return StoreFor(filepath.Join(t.TempDir(), "elemta.toml"))
}

func TestGeneratedKeyDoesNotSignUntilActivated(t *testing.T) {
	s := tempStore(t)
	for _, algorithm := range []string{AlgorithmRSA, AlgorithmEd25519} {
		key, err := s.Generate("example.org", "s-"+strings.ReplaceAll(algorithm, "-", ""), algorithm)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(key.Record, "v=DKIM1; k=") || !strings.Contains(key.Record, "; p=") {
			t.Fatalf("record = %q", key.Record)
		}
		info, err := os.Stat(s.keyPath("example.org", key.Selector))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("private key mode = %v", info.Mode())
		}
		if cfg := s.Apply(nil, true, nil); cfg != nil {
			t.Fatalf("an inactive key produced signing config: %+v", cfg)
		}
	}
	if err := s.Activate("example.org", "s-ed25519"); err != nil {
		t.Fatal(err)
	}
	cfg := s.Apply(nil, true, nil)
	if cfg == nil || !cfg.Enabled || len(cfg.Domains) != 1 || cfg.Domains[0].Selector != "s-ed25519" {
		t.Fatalf("apply = %+v", cfg)
	}
	signer, err := NewSigner(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte("From: a@example.org\r\nSubject: x\r\n\r\nhi\r\n"), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "s=s-ed25519") {
		t.Fatalf("not signed with the stored key:\n%s", signed)
	}
}

func TestApplyLaysStoreOverConfiguration(t *testing.T) {
	s := tempStore(t)
	configured := &Config{Enabled: true, Domains: []DomainConfig{
		{Domain: "example.org", Selector: "old", PrivateKeyPath: "/nowhere/old.key"},
		{Domain: "other.example", Selector: "keep", PrivateKeyPath: "/nowhere/keep.key"},
	}}
	if _, err := s.Generate("example.org", "new", AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("example.org", "new"); err != nil {
		t.Fatal(err)
	}
	cfg := s.Apply(configured, true, nil)
	if len(cfg.Domains) != 2 || cfg.Domains[0].Domain != "other.example" || cfg.Domains[1].Selector != "new" {
		t.Fatalf("domains = %+v", cfg.Domains)
	}
	if len(configured.Domains) != 2 || configured.Domains[0].Selector != "old" {
		t.Fatal("the caller's configuration was changed")
	}
	if err := s.SetSigning("other.example", false); err != nil {
		t.Fatal(err)
	}
	if cfg = s.Apply(configured, true, nil); len(cfg.Domains) != 1 || cfg.Domains[0].Domain != "example.org" {
		t.Fatalf("signing off left %+v", cfg.Domains)
	}
	if got := s.Apply(configured, false, nil); got != configured {
		t.Fatal("a disabled plugin must leave the configuration alone")
	}
}

// The signer refuses to start on a bad key; the store must not hand it one.
func TestDamagedStoreCannotStopTheServer(t *testing.T) {
	s := tempStore(t)
	if _, err := s.Generate("example.org", "a", AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("example.org", "a"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.keyPath("example.org", "a")); err != nil {
		t.Fatal(err)
	}
	configured := &Config{Enabled: true, Domains: []DomainConfig{{Domain: "example.org", Selector: "cfg", PrivateKeyPath: "/k"}}}
	if cfg := s.Apply(configured, true, nil); len(cfg.Domains) != 1 || cfg.Domains[0].Selector != "cfg" {
		t.Fatalf("missing key = %+v", cfg)
	}
	if err := os.WriteFile(s.ManifestPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg := s.Apply(configured, true, nil); cfg != configured {
		t.Fatalf("unreadable store = %+v", cfg)
	}
}

func TestActiveKeyCannotBeRenamedOrDeleted(t *testing.T) {
	s := tempStore(t)
	for _, sel := range []string{"a", "b"} {
		if _, err := s.Generate("example.org", sel, AlgorithmEd25519); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Activate("example.org", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("example.org", "a"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete active = %v", err)
	}
	if err := s.Rename("example.org", "a", "c"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rename active = %v", err)
	}
	if err := s.Rename("example.org", "b", "a"); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto a taken selector = %v", err)
	}
	if err := s.Rename("example.org", "b", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("example.org", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.keyPath("example.org", "c")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private key left behind: %v", err)
	}
}

func TestSelectorCannotEscapeTheStore(t *testing.T) {
	s := tempStore(t)
	for _, sel := range []string{"../evil", "a/b", "", "UPPER", "-a"} {
		if _, err := s.Generate("example.org", sel, AlgorithmEd25519); !errors.Is(err, ErrInvalid) {
			t.Errorf("selector %q: %v", sel, err)
		}
	}
	if _, err := s.Generate("../etc", "a", AlgorithmEd25519); !errors.Is(err, ErrInvalid) {
		t.Errorf("domain with a path: %v", err)
	}
}

func TestKeyPathStaysInsideTheStore(t *testing.T) {
	s := tempStore(t)
	for _, tc := range [][2]string{{"../../etc", "a"}, {"example.org", "../../../passwd"}, {"..", ".."}, {"/etc", "/shadow"}} {
		if got := s.keyPath(tc[0], tc[1]); !strings.HasPrefix(got, s.Dir+string(filepath.Separator)) {
			t.Errorf("keyPath(%q, %q) = %q, outside %q", tc[0], tc[1], got, s.Dir)
		}
	}
}

func TestImportReproducesPublicRecord(t *testing.T) {
	s := tempStore(t)
	key, err := s.Generate("example.org", "a", AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.keyPath("example.org", "a"))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := s.Import("example.net", "b", string(data))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Record != key.Record || !imported.Imported {
		t.Fatalf("imported = %+v", imported)
	}
	if _, err = s.Import("example.net", "c", "not a key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("garbage import = %v", err)
	}
}

func TestCheckDNS(t *testing.T) {
	s := tempStore(t)
	mine, err := s.Generate("example.org", "a", AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Generate("example.org", "b", AlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(values []string, err error) func(context.Context, string) ([]string, error) {
		return func(context.Context, string) ([]string, error) { return values, err }
	}
	split := mine.Record[:40] + " " + mine.Record[40:]
	for name, tc := range map[string]struct {
		values []string
		err    error
		want   string
	}{
		"match":         {[]string{mine.Record}, nil, DNSMatch},
		"split by host": {[]string{split}, nil, DNSMatch},
		"other key":     {[]string{other.Record}, nil, DNSMismatch},
		"unrelated txt": {[]string{"google-site-verification=x"}, nil, DNSMissing},
		"revoked":       {[]string{"v=DKIM1; p="}, nil, DNSMissing},
		"nxdomain":      {nil, &net.DNSError{IsNotFound: true}, DNSMissing},
	} {
		got, _, err := CheckDNS(context.Background(), lookup(tc.values, tc.err), "a._domainkey.example.org", mine.Record)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
		}
	}
	if _, _, err := CheckDNS(context.Background(), lookup(nil, &net.DNSError{IsTimeout: true}), "n", mine.Record); err == nil {
		t.Error("a DNS failure must not read as a missing record")
	}
}
