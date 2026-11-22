package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Backup alerts.
//
// The Health page shows when backups or the WAL upload stop, but only to
// someone who opens it, and a backup that quietly stopped is usually found
// on the day it's needed. The admin process already reads the status the
// host jobs leave (backup_status.go), so it checks it every few minutes
// and emails the alert addresses (the Abuse settings' "alert email") when it
// gets worse, again each day it stays bad, and once when it recovers.

const backupAlertPoll = 10 * time.Minute

// backupAlerter words the emails; alerter decides when there is one.
type backupAlerter struct{ alerter }

func backupLevel(status string) int {
	switch status {
	case "warning":
		return 1
	case "critical":
		return 2
	}
	return 0
}

// next returns the email to send for st, if any.
func (a *backupAlerter) next(st BackupStatus, host string, now time.Time) (subject, body string, send bool) {
	if !st.Configured {
		return "", "", false
	}
	level := backupLevel(st.Status)
	send, recovered := a.observe(level, now)
	if !send {
		return "", "", false
	}
	if recovered {
		return "Backups are working again on " + host,
			fmt.Sprintf("The backup problem reported earlier has cleared.\n\n%s\n\nLast good backup: %s\n", st.Message, orNone(st.LastSuccess)), true
	}
	subject = "Backup problem on " + host
	if level == 2 {
		subject = "Backups have stopped on " + host
	}
	body = fmt.Sprintf("%s\n\nLast good backup: %s\n", st.Message, orNone(st.LastSuccess))
	if st.WALLastSuccess != "" {
		body += fmt.Sprintf("Last WAL upload: %s\n", st.WALLastSuccess)
	}
	body += "\nThe Health page in the admin console shows the current state. This is repeated daily until it's fixed.\n"
	return subject, body, true
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// watchBackups checks the backup status until stop closes.
func (s *Server) watchBackups(stop <-chan struct{}) {
	if s.abuse == nil || s.backupStatusPath() == "" {
		return
	}
	host := s.alertHost()
	var a backupAlerter
	ticker := time.NewTicker(backupAlertPoll)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		subject, body, send := a.next(s.backupStatus(time.Now()), host, time.Now())
		if !send {
			continue
		}
		slog.Warn("Backup alert", "subject", subject)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if !s.abuse.Notify(ctx, subject, body) {
			slog.Warn("Backup alert not emailed: set alert addresses on the Abuse page")
		}
		cancel()
	}
}

// alertHost names this server in alert emails.
func (s *Server) alertHost() string {
	if s.mainConfig != nil && s.mainConfig.Hostname != "" {
		return s.mainConfig.Hostname
	}
	host, _ := os.Hostname()
	return host
}
