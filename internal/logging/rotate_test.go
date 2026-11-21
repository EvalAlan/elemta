package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func size(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

// The file rotates once it's full, keeping one older copy, so the two stay
// under twice the limit however long the server runs.
func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elemta.log")
	const max = 4 * rotateCheckEvery
	r, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := append(bytes.Repeat([]byte("x"), 1023), '\n')
	for i := 0; i < 40*1024; i++ { // 40 MiB, ten times the limit
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	cur, old := size(t, path), size(t, path+".1")
	if cur > max+rotateCheckEvery || old > max+rotateCheckEvery || old < max {
		t.Fatalf("current %d, rotated %d, limit %d", cur, old, max)
	}
	if left, _ := filepath.Glob(path + ".2"); len(left) != 0 {
		t.Fatal("kept more than one old file")
	}
}

// Two processes share the file in the compose stack (the MTA and the admin
// console). Each follows the other's rotation instead of writing on into the
// renamed file.
func TestRotatingFileShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elemta.log")
	const max = 2 * rotateCheckEvery
	a, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := openRotating(path, max)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	line := append(bytes.Repeat([]byte("y"), 1023), '\n')
	for i := 0; i < 20*1024; i++ {
		w := a
		if i%2 == 1 {
			w = b
		}
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if cur, old := size(t, path), size(t, path+".1"); cur > max+2*rotateCheckEvery || old > max+2*rotateCheckEvery {
		t.Fatalf("current %d, rotated %d, limit %d", cur, old, max)
	}
}

// A file left oversized by an older version is moved aside at start.
func TestRotatingFileStartsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elemta.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("z"), 3*rotateCheckEvery), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := openRotating(path, 2*rotateCheckEvery)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if size(t, path) != 0 || size(t, path+".1") != 3*rotateCheckEvery {
		t.Fatalf("current %d, rotated %d", size(t, path), size(t, path+".1"))
	}
}

// An empty [logging] file means stdout only.
func TestInitializeLoggingWithoutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "elemta.log")
	InitializeLogging("info", path)
	if size(t, path) <= 0 {
		t.Fatal("configured file not written")
	}
	InitializeLogging("info", "")
	before := size(t, path)
	InitializeLogging("info", "")
	if size(t, path) != before {
		t.Fatal("wrote to the file with file = \"\"")
	}
}
