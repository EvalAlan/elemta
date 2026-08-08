package smtp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spoolFileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read spool dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && isSpoolFileName(e.Name()) {
			n++
		}
	}
	return n
}

func TestMessageSpool_StaysInMemoryBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	s := NewMessageSpool(dir, 1024)
	defer func() { _ = s.Close() }()

	payload := []byte(strings.Repeat("a", 512))
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	if s.OnDisk() {
		t.Error("spool spilled to disk below the threshold")
	}
	if s.Path() != "" {
		t.Errorf("no file should exist yet, got path %q", s.Path())
	}
	if got := s.Size(); got != int64(len(payload)) {
		t.Errorf("size = %d, want %d", got, len(payload))
	}
	if n := spoolFileCount(t, dir); n != 0 {
		t.Errorf("expected no spool files on disk, found %d", n)
	}
}

func TestMessageSpool_SpillsAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	s := NewMessageSpool(dir, 1024)
	defer func() { _ = s.Close() }()

	payload := []byte(strings.Repeat("b", 4096))
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !s.OnDisk() {
		t.Fatal("spool did not spill above the threshold")
	}
	if s.Path() == "" {
		t.Fatal("spilled spool has no path")
	}
	if n := spoolFileCount(t, dir); n != 1 {
		t.Errorf("expected 1 spool file, found %d", n)
	}

	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat spool file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("spool file mode = %04o, want 0600 (message data must not be world-readable)", perm)
	}
}

// TestMessageSpool_ContentSurvivesSpill is the property the whole refactor
// rests on: what comes out must be byte-identical to what went in, regardless
// of whether the data crossed the threshold mid-write.
func TestMessageSpool_ContentSurvivesSpill(t *testing.T) {
	cases := []struct {
		name      string
		threshold int64
		chunks    []string
	}{
		{"entirely in memory", 1 << 20, []string{"hello ", "world\r\n"}},
		{"entirely on disk", 0, []string{"hello ", "world\r\n"}},
		{"spills mid-write", 8, []string{"hello ", "world\r\n", "more data\r\n"}},
		{"spills exactly at boundary", 6, []string{"hello ", "world\r\n"}},
		{"binary content", 4, []string{"\x00\x01\x02", "\xff\xfe\r\n"}},
		{"empty", 16, nil},
		{"many small writes", 32, func() []string {
			out := make([]string, 200)
			for i := range out {
				out[i] = "line\r\n"
			}
			return out
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := NewMessageSpool(dir, tc.threshold)
			defer func() { _ = s.Close() }()

			var want bytes.Buffer
			for _, c := range tc.chunks {
				if _, err := s.Write([]byte(c)); err != nil {
					t.Fatalf("write: %v", err)
				}
				want.WriteString(c)
			}

			if got := s.Size(); got != int64(want.Len()) {
				t.Errorf("Size() = %d, want %d", got, want.Len())
			}

			r, err := s.Reader()
			if err != nil {
				t.Fatalf("reader: %v", err)
			}
			defer func() { _ = r.Close() }()

			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read all: %v", err)
			}
			if !bytes.Equal(got, want.Bytes()) {
				t.Errorf("content mismatch\n  want %q\n  got  %q", want.String(), string(got))
			}

			viaBytes, err := s.Bytes()
			if err != nil {
				t.Fatalf("bytes: %v", err)
			}
			if !bytes.Equal(viaBytes, want.Bytes()) {
				t.Errorf("Bytes() mismatch\n  want %q\n  got  %q", want.String(), string(viaBytes))
			}
		})
	}
}

// TestMessageSpool_ReaderIsSeekableAndRepeatable covers what DKIM needs: hash
// the body in one pass, rewind, replay it in a second.
func TestMessageSpool_ReaderIsSeekableAndRepeatable(t *testing.T) {
	for _, threshold := range []int64{1 << 20, 0} {
		dir := t.TempDir()
		s := NewMessageSpool(dir, threshold)

		payload := []byte("Subject: test\r\n\r\nbody content\r\n")
		if _, err := s.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}

		r, err := s.Reader()
		if err != nil {
			t.Fatalf("reader: %v", err)
		}

		first, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("first read: %v", err)
		}
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			t.Fatalf("seek: %v", err)
		}
		second, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("second read: %v", err)
		}

		if !bytes.Equal(first, second) || !bytes.Equal(first, payload) {
			t.Errorf("threshold %d: two passes differ\n  first  %q\n  second %q", threshold, first, second)
		}
		_ = r.Close()

		// Independent readers must not interfere with one another.
		r1, err := s.Reader()
		if err != nil {
			t.Fatalf("reader 1: %v", err)
		}
		r2, err := s.Reader()
		if err != nil {
			t.Fatalf("reader 2: %v", err)
		}
		b1, _ := io.ReadAll(r1)
		b2, _ := io.ReadAll(r2)
		if !bytes.Equal(b1, b2) {
			t.Errorf("threshold %d: independent readers disagree", threshold)
		}
		_ = r1.Close()
		_ = r2.Close()
		_ = s.Close()
	}
}

// TestMessageSpool_CloseRemovesBackingFile is the leak test. A spool file that
// outlives its session accumulates until it fills the queue filesystem.
func TestMessageSpool_CloseRemovesBackingFile(t *testing.T) {
	dir := t.TempDir()
	s := NewMessageSpool(dir, 0)

	if _, err := s.Write([]byte("some data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := s.Path()
	if path == "" {
		t.Fatal("expected a spool file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("spool file should exist: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("spool file survived Close: %v", err)
	}
	if n := spoolFileCount(t, dir); n != 0 {
		t.Errorf("expected no spool files after Close, found %d", n)
	}

	// Close must be safe to call again, since it runs from deferred cleanup
	// on paths that may already have closed it.
	if err := s.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

func TestMessageSpool_UseAfterCloseIsRefused(t *testing.T) {
	s := NewMessageSpool(t.TempDir(), 0)
	if _, err := s.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := s.Write([]byte("more")); err == nil {
		t.Error("write after close should fail")
	}
	if _, err := s.Reader(); err == nil {
		t.Error("reader after close should fail")
	}
}

func TestSweepOrphanedSpools(t *testing.T) {
	dir := t.TempDir()

	// Two orphans and one unrelated file that must survive.
	for _, name := range []string{spoolFilePrefix + "aaa", spoolFilePrefix + "bbb"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write orphan: %v", err)
		}
	}
	keep := filepath.Join(dir, "queue-message-id")
	if err := os.WriteFile(keep, []byte("real message"), 0o600); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}

	removed, err := SweepOrphanedSpools(dir)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("sweep removed a file it did not create: %v", err)
	}
	if n := spoolFileCount(t, dir); n != 0 {
		t.Errorf("expected no spool files after sweep, found %d", n)
	}
}

func TestSweepOrphanedSpools_MissingDirIsNotAnError(t *testing.T) {
	removed, err := SweepOrphanedSpools(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("sweep of a missing directory returned %v, want nil", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
