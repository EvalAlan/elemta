package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupStatus(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	dir := t.TempDir()
	s := &Server{configPath: filepath.Join(dir, "elemta.toml")}
	write := func(json string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "backup-status.json"), []byte(json), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if st := s.backupStatus(now); st.Status != "unknown" || st.Configured || !strings.Contains(st.Message, "aren't set up") {
		t.Errorf("no status file: %+v", st)
	}

	for _, c := range []struct {
		name, json, status, says string
	}{
		{"fresh, drilled", `{"attempted":"` + ago(9*time.Hour) + `","ok":true,"message":"Backed up.","object":"elemta/x","bytes":42,"last_success":"` + ago(9*time.Hour) + `","last_drill":"` + ago(3*24*time.Hour) + `","drill_ok":true}`, "ok", "Backed up."},
		{"last run failed, earlier one recent", `{"attempted":"` + ago(time.Hour) + `","ok":false,"stage":"upload","message":"The backup failed during the upload step.","last_success":"` + ago(25*time.Hour) + `","last_drill":"` + ago(24*time.Hour) + `","drill_ok":true}`, "warning", "last run failed"},
		{"a day and a half late", `{"attempted":"` + ago(40*time.Hour) + `","ok":true,"message":"Backed up.","last_success":"` + ago(40*time.Hour) + `","last_drill":"` + ago(40*time.Hour) + `","drill_ok":true}`, "warning", "40 hours old"},
		{"three days without one", `{"attempted":"` + ago(time.Hour) + `","ok":false,"stage":"backup","message":"The backup failed during the backup step.","last_success":"` + ago(80*time.Hour) + `","last_drill":"` + ago(80*time.Hour) + `","drill_ok":true}`, "critical", "3 days old"},
		{"never succeeded", `{"attempted":"` + ago(time.Hour) + `","ok":false,"stage":"upload","message":"The backup failed during the upload step.","last_success":"","last_drill":"","drill_ok":true}`, "critical", "No backup has succeeded"},
		{"drill failed", `{"attempted":"` + ago(time.Hour) + `","ok":true,"message":"Backed up.","last_success":"` + ago(time.Hour) + `","last_drill":"` + ago(time.Hour) + `","drill_ok":false}`, "warning", "drill failed"},
		{"no drill in weeks", `{"attempted":"` + ago(time.Hour) + `","ok":true,"message":"Backed up.","last_success":"` + ago(time.Hour) + `","last_drill":"` + ago(20*24*time.Hour) + `","drill_ok":true}`, "warning", "no restore drill"},
		{"unreadable", `{not json`, "warning", "couldn't be read"},
	} {
		write(c.json)
		st := s.backupStatus(now)
		if st.Status != c.status || !strings.Contains(st.Message, c.says) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, st.Status, st.Message, c.status, c.says)
		}
	}
}
