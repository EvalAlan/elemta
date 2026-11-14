package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// An auth file path that is a directory (what Docker leaves when a file it
// should bind-mount is missing) stops startup; it used to turn
// authentication off.
func TestCheckAuthFileRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := checkAuthFile(true, dir); err == nil {
		t.Error("a directory was accepted as the auth file")
	}
	file := filepath.Join(dir, "users.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkAuthFile(true, file); err != nil {
		t.Errorf("a real file was refused: %v", err)
	}
	if err := checkAuthFile(true, filepath.Join(dir, "missing.json")); err != nil {
		t.Errorf("a missing file is the server's to report, not this check's: %v", err)
	}
	if err := checkAuthFile(false, dir); err != nil {
		t.Errorf("auth explicitly off isn't this check's business: %v", err)
	}
}
