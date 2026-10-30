package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/EvalAlan/elemta/internal/dkim"
)

// The console and the SMTP server share only the runtime volume, so a change
// to the DKIM manifest has to look like a configuration change to the watcher.
func TestReloadHashCoversManagedDKIMKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elemta.toml")
	if err := os.WriteFile(path, []byte("hostname = \"mx\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := dkim.StoreFor(path)
	if _, err = store.Generate("example.org", "a", dkim.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	generated, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if generated == before {
		t.Fatal("generating a key doesn't reach the reload watcher")
	}
	if err = store.Activate("example.org", "a"); err != nil {
		t.Fatal(err)
	}
	if activated, _ := hashFile(path); activated == generated {
		t.Fatal("activating a key doesn't reach the reload watcher")
	}
}
