package offsite

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestIsWALName(t *testing.T) {
	for name, want := range map[string]bool{
		"000000010000000000000003":                 true,
		"00000002.history":                         true,
		"000000010000000000000003.00000028.backup": true,
		".000000010000000000000003.tmp":            false,
		"000000010000000000000003.partial":         false,
		"00000001000000000000000g":                 false,
		"../etc/passwd":                            false,
		"elemta-20261114T000000Z.tar.gz.age":       false,
	} {
		if IsWALName(name) != want {
			t.Errorf("IsWALName(%q) = %v", name, !want)
		}
	}
}

func TestSealFileRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "000000010000000000000003")
	want := bytes.Repeat([]byte{0}, walSegmentSize)
	copy(want, "some WAL records")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := SealFile(&sealed, path, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if sealed.Len() > 1<<16 {
		t.Errorf("an almost empty segment sealed to %d bytes; it should compress", sealed.Len())
	}
	if bytes.Contains(sealed.Bytes(), []byte("some WAL records")) {
		t.Fatal("sealed file holds plaintext")
	}
	var got bytes.Buffer
	if err := OpenFile(&got, bytes.NewReader(sealed.Bytes()), id); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("round trip changed the file")
	}
	other, _ := age.GenerateX25519Identity()
	if err := OpenFile(&bytes.Buffer{}, bytes.NewReader(sealed.Bytes()), other); err == nil {
		t.Fatal("opened with the wrong identity")
	}
}

func walObjs(names ...string) []WALObject {
	var out []WALObject
	for _, n := range names {
		out = append(out, WALObject{Name: n})
	}
	return out
}

func TestWALGaps(t *testing.T) {
	objs := walObjs(
		"000000010000000000000001",
		"000000010000000000000002",
		"000000010000000000000002.00000028.backup",
		"000000010000000000000003",
		"000000010000000000000005", // 4 is missing
		"0000000100000000000000FF",
		"000000010000000100000000", // crossing into the next log file is no gap
		"00000002.history",
		"000000020000000100000001", // a new timeline starts its own run
	)
	if got := LatestBaseStart(objs); got != "000000010000000000000002" {
		t.Fatalf("LatestBaseStart = %q", got)
	}
	gaps := WALGaps(objs, "000000010000000000000002", 3)
	if strings.Join(gaps, ",") != "000000010000000000000004,000000010000000000000006,000000010000000000000007" {
		t.Errorf("gaps = %v", gaps)
	}
	if g := WALGaps(walObjs("0000000100000000000000FE", "0000000100000000000000FF", "000000010000000100000000"), "", 10); len(g) != 0 {
		t.Errorf("a log file boundary reported as a gap: %v", g)
	}
	// Before the newest base backup's start a hole doesn't matter.
	if g := WALGaps(walObjs("000000010000000000000001", "000000010000000000000009", "00000001000000000000000A"), "000000010000000000000009", 10); len(g) != 0 {
		t.Errorf("a hole before the base backup reported: %v", g)
	}
}

func TestPruneWAL(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	objs := []WALObject{
		{Name: "a", Uploaded: now.Add(-20 * 24 * time.Hour)},
		{Name: "b", Uploaded: now.Add(-13 * 24 * time.Hour)},
		{Name: "c", Uploaded: now},
	}
	drop := PruneWAL(objs, 14*24*time.Hour)
	if len(drop) != 1 || drop[0].Name != "a" {
		t.Fatalf("drop = %+v", drop)
	}
	// Measured from the newest upload, not the clock: an archive that
	// stopped a month ago keeps its last fortnight.
	old := []WALObject{{Name: "x", Uploaded: now.Add(-40 * 24 * time.Hour)}, {Name: "y", Uploaded: now.Add(-30 * 24 * time.Hour)}}
	if drop := PruneWAL(old, 14*24*time.Hour); len(drop) != 0 {
		t.Fatalf("pruned a stopped archive: %+v", drop)
	}
}

func TestPushWALRefusesShortSegments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "000000010000000000000003"), []byte("cut short"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{cfg: Config{Prefix: "elemta/"}}
	n, err := c.PushWAL(t.Context(), dir, "unused")
	if err == nil || n != 0 || !strings.Contains(err.Error(), "not a whole segment") {
		t.Fatalf("PushWAL = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "000000010000000000000003")); err != nil {
		t.Fatal("the short segment was removed")
	}
}
