package commands

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/dkim"
)

func runDKIM(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"dkim"}, args...))
	err := rootCmd.Execute()
	return out.String(), err
}

// check must refuse until DNS serves the new key, and pass once it does.
func TestDKIMCheckGatesTheSwitch(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "new.key")
	out, err := runDKIM(t, "keygen", "--domain", "example.com", "--selector", "s2", "--type", "ed25519", "--out", key)
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	if !strings.Contains(out, "s2._domainkey.example.com") {
		t.Fatalf("keygen did not print the record name:\n%s", out)
	}

	pub, err := dkim.LoadPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := dkim.DNSRecord(pub)
	other, _ := dkim.GenerateKey("ed25519", 0)
	stale, _ := dkim.DNSRecord(other.Public())

	served := []string{stale}
	orig := dkimLookupTXT
	dkimLookupTXT = func(ctx context.Context, name string) ([]string, error) { return served, nil }
	t.Cleanup(func() { dkimLookupTXT = orig })

	if _, err := runDKIM(t, "check", "--domain", "example.com", "--selector", "s2", "--key", key); err == nil {
		t.Fatal("check passed while DNS served a different key")
	}
	served = []string{record}
	if out, err := runDKIM(t, "check", "--domain", "example.com", "--selector", "s2", "--key", key); err != nil {
		t.Fatalf("check failed once DNS served the key: %v\n%s", err, out)
	}
}
