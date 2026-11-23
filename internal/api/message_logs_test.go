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

// writeRawLines writes the given JSON log lines to path.
func writeRawLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Every event type reaches the tab, under its category. Info-level lines of
// any type outside seven used to be dropped before the filter ran.
func TestLogsTabCategorizesEveryEventType(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("logs", 0o750); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join("logs", "elemta.log")
	writeRawLines(t, live,
		`{"time":"2026-11-23T01:00:00Z","level":"INFO","msg":"message_received","event_type":"message_received"}`,
		`{"time":"2026-11-23T01:00:01Z","level":"INFO","msg":"SMTP command processed","event_type":"rcpt_to_accepted"}`,
		`{"time":"2026-11-23T01:00:02Z","level":"INFO","msg":"message_scanned","event_type":"scan"}`,
		`{"time":"2026-11-23T01:00:03Z","level":"INFO","msg":"mailbox: signed in","event_type":"authentication"}`,
		`{"time":"2026-11-23T01:00:04Z","level":"INFO","msg":"something new","event_type":"brand_new_type"}`,
		`{"time":"2026-11-23T01:00:05Z","level":"INFO","msg":"message_reception","event_type":"reception"}`,
		`{"time":"2026-11-23T01:00:06Z","level":"WARN","msg":"SMTP command refused","response":"550 5.7.1 no"}`,
	)
	s := &Server{}

	all, err := s.tailLogFile(live, 50, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(all))
	for i, l := range all {
		got[i] = l.EventType + "/" + l.EventAction
	}
	want := "reception/message_received,session/rcpt_to_accepted,scan/,authentication/,system/brand_new_type,reception/,rejection/"
	if strings.Join(got, ",") != want {
		t.Fatalf("all types:\n got %s\nwant %s", strings.Join(got, ","), want)
	}

	// The pre-filter has to find message_received for "reception", though
	// the line doesn't contain the word.
	rec, err := s.tailLogFile(live, 50, "reception", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 2 || rec[0].EventAction != "message_received" || rec[1].Message != "message_reception" {
		t.Fatalf("reception filter = %+v", rec)
	}

	// A rejection known only from its 5xx reply still matches its filter.
	rej, err := s.tailLogFile(live, 50, "rejection", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rej) != 1 || rej[0].Message != "SMTP command refused" {
		t.Fatalf("rejection filter = %+v", rej)
	}

	sys, err := s.tailLogFile(live, 50, "system", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sys) != 1 || sys[0].EventAction != "brand_new_type" {
		t.Fatalf("system filter = %+v", sys)
	}
}

func TestEveryCategoryHasAFilterOption(t *testing.T) {
	t.Chdir("../..")
	page, err := os.ReadFile("web/static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range logCategories {
		if seen[c] {
			continue
		}
		seen[c] = true
		if !strings.Contains(string(page), `<option value="`+c+`">`) {
			t.Errorf("category %q has no option in the Logs tab's filter", c)
		}
	}
}
