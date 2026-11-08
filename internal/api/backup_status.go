package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Off-site backup status.
//
// scripts/backup-offsite.sh runs on the host from a systemd timer, outside
// every container, so nothing here could see whether it ran. It leaves the
// result of each run in backup-status.json beside the runtime configuration,
// on the volume this process already mounts, and this turns it into the
// one line an operator needs. A backup that silently stopped running is
// found out on the day it's needed, which is the worst day to find out.

const (
	// Backups run every 6 hours. backupWarnAfter allows one run to be late
	// or to fail without raising anything; a second miss is worth a look.
	backupWarnAfter = 14 * time.Hour
	// backupCriticalAfter is a day and a half: most of a week's worth of
	// runs missed, no longer a hiccup.
	backupCriticalAfter = 36 * time.Hour
	// drillWarnAfter is two missed weekly drills.
	drillWarnAfter = 15 * 24 * time.Hour
)

// backupRun is what backup-offsite.sh writes after each run.
type backupRun struct {
	Attempted   string `json:"attempted"`
	OK          bool   `json:"ok"`
	Stage       string `json:"stage"`
	Message     string `json:"message"`
	Object      string `json:"object"`
	Bytes       int64  `json:"bytes"`
	LastSuccess string `json:"last_success"`
	LastDrill   string `json:"last_drill"`
	DrillOK     bool   `json:"drill_ok"`
}

// BackupStatus is what the Health page shows.
type BackupStatus struct {
	Configured  bool   `json:"configured"`
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	LastDrill   string `json:"last_drill,omitempty"`
	Object      string `json:"object,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	// Status is ok, warning, critical or unknown, decided here so the page
	// and the API can't disagree about the thresholds.
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.backupStatus(time.Now()))
}

// backupStatusPath is beside the runtime configuration, where the host job
// writes it, or empty when this process has no configuration file.
func (s *Server) backupStatusPath() string {
	if s.configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.configPath), "backup-status.json")
}

func (s *Server) backupStatus(now time.Time) BackupStatus {
	st := BackupStatus{Status: "unknown"}
	path := s.backupStatusPath()
	if path == "" {
		st.Message = "No configuration is available to this process."
		return st
	}
	// #nosec G304 -- a fixed name beside the operator's configuration file
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		st.Message = "Off-site backups aren't set up on this server. See docs/production-compose.md, \"Backups\"."
		return st
	}
	var run backupRun
	if err == nil {
		err = json.Unmarshal(data, &run)
	}
	if err != nil {
		st.Status = "warning"
		st.Message = "The last backup's status couldn't be read."
		return st
	}
	st.Configured = true
	st.LastAttempt, st.LastSuccess, st.LastDrill = run.Attempted, run.LastSuccess, run.LastDrill
	if run.OK {
		st.Object, st.Bytes = run.Object, run.Bytes
	}

	success, ok := parseRFC3339(run.LastSuccess)
	age := now.Sub(success)
	switch {
	case !ok:
		st.Status = "critical"
		st.Message = "No backup has succeeded yet. " + run.Message
	case age > backupCriticalAfter:
		st.Status = "critical"
		st.Message = fmt.Sprintf("The last good backup is %s old. %s", humanAge(age), run.Message)
	case !run.OK:
		st.Status = "warning"
		st.Message = fmt.Sprintf("The last run failed; the last good backup is %s old. %s", humanAge(age), run.Message)
	case age > backupWarnAfter:
		st.Status = "warning"
		st.Message = fmt.Sprintf("The last backup is %s old; one runs every 6 hours.", humanAge(age))
	default:
		st.Status = "ok"
		st.Message = run.Message
	}
	if st.Status == "ok" {
		drill, drilled := parseRFC3339(run.LastDrill)
		switch {
		case !run.DrillOK:
			st.Status = "warning"
			st.Message = "Backed up, but the last restore drill failed. Run scripts/restore-drill.sh on a fresh backup to see why."
		case !drilled || now.Sub(drill) > drillWarnAfter:
			st.Status = "warning"
			st.Message = "Backed up, but no restore drill has run in over two weeks."
		}
	}
	return st
}

func parseRFC3339(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// humanAge says how old something is in the unit that reads naturally.
func humanAge(d time.Duration) string {
	switch h := int(d.Hours()); {
	case h < 1:
		return "less than an hour"
	case h < 48:
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	default:
		return fmt.Sprintf("%d days", h/24)
	}
}
