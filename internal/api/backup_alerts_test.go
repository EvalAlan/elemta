package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A WAL problem used to read as "ok" on the Health page: the backup's
// message said so, but its status didn't.
func TestBackupStatusWAL(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	dir := t.TempDir()
	s := &Server{configPath: filepath.Join(dir, "elemta.toml")}
	write := func(name, json string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(json), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	good := `{"attempted":"` + ago(time.Hour) + `","ok":true,"message":"Backed up.","last_success":"` + ago(time.Hour) + `","last_drill":"` + ago(time.Hour) + `","drill_ok":true,"wal":""}`

	write("backup-status.json", good)
	write("wal-status.json", `{"attempted":"`+ago(3*time.Minute)+`","ok":true,"last_success":"`+ago(3*time.Minute)+`","waiting":0}`)
	if st := s.backupStatus(now); st.Status != "ok" || st.WALLastSuccess != ago(3*time.Minute) {
		t.Errorf("fresh WAL: %+v", st)
	}

	write("wal-status.json", `{"attempted":"`+ago(2*time.Minute)+`","ok":false,"last_success":"`+ago(3*time.Hour)+`","waiting":36}`)
	if st := s.backupStatus(now); st.Status != "warning" || !strings.Contains(st.Message, "3 hours") || !strings.Contains(st.Message, "36 WAL files") {
		t.Errorf("stuck WAL: %+v", st)
	}

	write("wal-status.json", `{"attempted":"`+ago(2*time.Minute)+`","ok":false,"last_success":"","waiting":4}`)
	if st := s.backupStatus(now); st.Status != "warning" || !strings.Contains(st.Message, "haven't gone off-site since") {
		t.Errorf("WAL never sent: %+v", st)
	}

	// A critical backup stays the headline.
	write("backup-status.json", `{"attempted":"`+ago(time.Hour)+`","ok":false,"stage":"upload","message":"The backup failed during the upload step.","last_success":"`+ago(50*time.Hour)+`","last_drill":"`+ago(50*time.Hour)+`","drill_ok":true}`)
	if st := s.backupStatus(now); st.Status != "critical" || strings.Contains(st.Message, "WAL") {
		t.Errorf("critical backup with stuck WAL: %+v", st)
	}

	// The backup run's own WAL report.
	os.Remove(filepath.Join(dir, "wal-status.json"))
	write("backup-status.json", `{"attempted":"`+ago(time.Hour)+`","ok":true,"message":"Backed up, but the database's WAL archive is missing files since the last base backup.","last_success":"`+ago(time.Hour)+`","last_drill":"`+ago(time.Hour)+`","drill_ok":true,"wal":"gap"}`)
	if st := s.backupStatus(now); st.Status != "warning" || !strings.Contains(st.Message, "missing files") {
		t.Errorf("WAL gap: %+v", st)
	}
}

func TestBackupAlerter(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	var a backupAlerter
	st := func(status string) BackupStatus {
		return BackupStatus{Configured: true, Status: status, Message: "msg " + status, LastSuccess: "2026-11-21T03:00:00Z"}
	}
	step := func(at time.Duration, s BackupStatus, wantSend bool, wantSubject string) {
		t.Helper()
		subject, body, send := a.next(s, "mail.example.com", t0.Add(at))
		if send != wantSend || (send && !strings.Contains(subject, wantSubject)) {
			t.Fatalf("at %v status %s: send %v subject %q", at, s.Status, send, subject)
		}
		if send && !strings.Contains(body, s.Message) {
			t.Fatalf("body %q lacks the status message", body)
		}
	}

	step(0, BackupStatus{Status: "unknown"}, false, "")                    // not set up: silent
	step(0, st("ok"), false, "")                                           // fine: silent
	step(10*time.Minute, st("warning"), true, "Backup problem")            // worse: tell
	step(20*time.Minute, st("warning"), false, "")                         // same: don't repeat
	step(30*time.Minute, st("critical"), true, "have stopped")             // worse again: tell
	step(40*time.Minute, st("warning"), false, "")                         // better but bad: quiet
	step(50*time.Minute, st("critical"), true, "have stopped")             // relapse: tell
	step(50*time.Minute+alertRepeat, st("critical"), true, "have stopped") // a day on: remind
	step(25*time.Hour+time.Minute, st("ok"), true, "working again")        // recovered: tell once
	step(26*time.Hour, st("ok"), false, "")
}
