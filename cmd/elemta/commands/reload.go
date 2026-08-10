package commands

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"time"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/smtp"
)

// Reload triggers.
//
// Two, because they answer different questions.
//
// SIGHUP is what an operator or an init system expects to work, and what
// `docker kill -s HUP` gives you.
//
// Watching the file is what makes the web interface useful. The UI and the SMTP
// server are separate processes — separate containers, in the shipped compose
// stack — so the UI cannot signal the server. Since both now read one shared
// configuration file, the server noticing that the file changed is the whole
// mechanism: no control socket, no new listening port, no credentials to
// manage between the two.

// configReloadInterval is how often the file is checked. A stat and a read of a
// small file; the cost is irrelevant next to being able to say "changes apply
// within a few seconds" in the UI.
const configReloadInterval = 5 * time.Second

// watchConfigForReload reloads the server when the configuration file changes,
// and on SIGHUP. It returns when ctx is cancelled.
//
// Content is compared by hash rather than modification time. A bind-mounted or
// volume-backed file can have its timestamp changed by things that are not
// edits — and, more to the point, persistConfig writes by renaming a temporary
// file into place, so an unchanged save would still look like a new mtime and
// reload the server for nothing.
func watchConfigForReload(ctx context.Context, server *smtp.Server, configPath string, reloadRequests <-chan os.Signal) {
	lastHash, _ := hashFile(configPath)

	ticker := time.NewTicker(configReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-reloadRequests:
			slog.Info("SIGHUP received, reloading configuration", "config", configPath)
			if h, err := hashFile(configPath); err == nil {
				lastHash = h
			}
			applyReload(ctx, server, configPath)

		case <-ticker.C:
			hash, err := hashFile(configPath)
			if err != nil {
				// The file being briefly absent is what a rename-into-place
				// looks like from here. Complaining every five seconds about a
				// file that is about to reappear is noise, so this is quiet and
				// the next tick picks it up.
				continue
			}
			if hash == lastHash {
				continue
			}
			lastHash = hash
			slog.Info("Configuration file changed, reloading", "config", configPath)
			applyReload(ctx, server, configPath)
		}
	}
}

// applyReload loads the file and hands it to the server.
//
// A configuration that fails to load or to build leaves the server running as
// it was. An operator who saves something invalid should get an error in the
// log and a server that still delivers mail, not an outage.
func applyReload(ctx context.Context, server *smtp.Server, configPath string) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		slog.Error("Reload failed: configuration could not be loaded; keeping the running configuration",
			"config", configPath, "error", err)
		return
	}

	smtpConfig, err := cfg.ToSMTPConfig()
	if err != nil {
		slog.Error("Reload failed: configuration is not valid; keeping the running configuration",
			"config", configPath, "error", err)
		return
	}

	if err := server.Reload(ctx, smtpConfig); err != nil {
		slog.Error("Reload failed; keeping the running configuration", "error", err)
		return
	}
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured startup path
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return string(sum[:]), nil
}
