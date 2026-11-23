package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLogLines writes one JSON log line per event type, a second apart from
// start, to path.
func writeLogLines(t *testing.T, path string, start time.Time, eventTypes ...string) {
	t.Helper()
	var b strings.Builder
	for i, et := range eventTypes {
		ts := start.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(&b, `{"time":%q,"level":"INFO","msg":"line %d","event_type":%q}`+"\n", ts, i, et)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func eventTypesOf(logs []MessageLog) []string {
	out := make([]string, len(logs))
	for i, l := range logs {
		out[i] = l.EventType
	}
	return out
}

// Right after a rotation the live file holds only the minutes since, so a
// type filter has to reach into the rotated file to find anything.
func TestTailLogFileReadsRotatedFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("logs", 0o750); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join("logs", "elemta.log")
	base := time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)
	writeLogLines(t, live+".1", base, "reception", "delivery", "reception")
	writeLogLines(t, live, base.Add(time.Hour), "system", "rejection")

	s := &Server{}

	logs, err := s.tailLogFile(live, 50, "reception", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := eventTypesOf(logs); strings.Join(got, ",") != "reception,reception" {
		t.Fatalf("reception filter = %v, want two receptions from the rotated file", got)
	}

	logs, err = s.tailLogFile(live, 50, "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "reception,delivery,reception,system,rejection"
	if got := strings.Join(eventTypesOf(logs), ","); got != want {
		t.Fatalf("all types = %s, want %s (oldest first, across both files)", got, want)
	}

	// With enough matches in the live file, the rotated one is not read,
	// and the limit keeps the newest.
	logs, err = s.tailLogFile(live, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(eventTypesOf(logs), ","); got != "rejection" {
		t.Fatalf("limit 1 = %s, want rejection", got)
	}
}

// A writer that has not noticed the rotation keeps appending to ".1", so
// lines there can be newer than some in the live file.
func TestTailLogFileOrdersAcrossFilesByTime(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("logs", 0o750); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join("logs", "elemta.log")
	base := time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)
	writeLogLines(t, live, base, "system")
	writeLogLines(t, live+".1", base.Add(time.Minute), "delivery")

	logs, err := (&Server{}).tailLogFile(live, 50, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(eventTypesOf(logs), ","); got != "system,delivery" {
		t.Fatalf("order = %s, want system,delivery", got)
	}
}

func TestTailLogFileWithoutRotatedFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("logs", 0o750); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join("logs", "elemta.log")
	writeLogLines(t, live, time.Now(), "reception")

	logs, err := (&Server{}).tailLogFile(live, 50, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
}
