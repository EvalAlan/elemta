package offsite

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A failed run keeps the last success, so the admin console can say how long
// the WAL has been stuck, and every run counts what is still waiting.
func TestWALStatus(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	path := filepath.Join(out, "wal-status.json")
	read := func() WALStatus {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var st WALStatus
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	// Before any success, a failure has no last success to carry.
	if err := WriteWALStatus(path, dir, t0, 0, errors.New("no bucket")); err != nil {
		t.Fatal(err)
	}
	if st := read(); st.OK || st.LastSuccess != "" {
		t.Fatalf("first failure: %+v", st)
	}

	if err := WriteWALStatus(path, dir, t0.Add(5*time.Minute), 3, nil); err != nil {
		t.Fatal(err)
	}
	st := read()
	if !st.OK || st.LastSuccess != "2026-11-21T10:05:00Z" || st.Uploaded != 3 || st.Waiting != 0 {
		t.Fatalf("success: %+v", st)
	}

	for _, name := range []string{"000000010000000000000007", "000000010000000000000008", "not-wal.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteWALStatus(path, dir, t0.Add(10*time.Minute), 0, errors.New("access denied")); err != nil {
		t.Fatal(err)
	}
	st = read()
	if st.OK || st.Attempted != "2026-11-21T10:10:00Z" || st.LastSuccess != "2026-11-21T10:05:00Z" || st.Waiting != 2 {
		t.Fatalf("failure after success: %+v", st)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(out, ".wal-status-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}
