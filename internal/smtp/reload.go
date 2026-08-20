package smtp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/busybox42/elemta/internal/authresult"
)

// Reloading configuration without a restart.
//
// Restarting an MTA to change a setting is not free: connections in progress
// are dropped, and a session killed mid-DATA is a message the sender has to
// send again. Every scanner and policy setting in this server previously said
// "requires restart", which meant either taking that cost or leaving the
// setting unapplied.
//
// What reloads and what does not is a deliberate line, not an accident of
// implementation:
//
//   - Reloadable: the things a session consults through a component object —
//     the scanners, the allow/deny lists, the blocklists. A session captures
//     these when it is created, so replacing the server's copy affects the next
//     session and leaves sessions already running with the configuration they
//     started under. A message is never half-scanned by two different policies.
//
//   - Not reloadable: anything baked into the *Config that running sessions
//     hold a pointer to — the listen address, size limits, timeouts, the queue
//     backend. Mutating that struct underneath a live session would be a data
//     race, and the honest answer is that those still need a restart.
//
// Saying which is which matters more than covering everything: an operator who
// believes a setting took effect when it did not is worse off than one who is
// told to restart.

// reloadableComponents is what Reload swaps. Grouping them makes the set
// explicit rather than something to be inferred from the body of Reload.
type reloadableComponents struct {
	scanners      *ScannerManager
	accessControl *AccessControl
	rbl           *RBLChecker
	authVerifier  *authresult.Verifier
}

// Reload rebuilds the reloadable components from a freshly loaded
// configuration and swaps them in.
//
// Everything is built before anything is swapped, so a configuration that fails
// to build — an unparseable deny rule, a blocklist enabled with no zones —
// leaves the server running exactly as it was. A reload that half-applies is
// worse than one that is refused.
func (s *Server) Reload(ctx context.Context, newConfig *Config) error {
	if newConfig == nil {
		return fmt.Errorf("no configuration to reload")
	}

	next, err := s.buildReloadable(ctx, newConfig, s.slogger)
	if err != nil {
		return err
	}

	s.pluginMu.Lock()
	s.scannerManager = next.scanners
	s.accessControl = next.accessControl
	s.rblChecker = next.rbl
	s.authVerifier = next.authVerifier
	s.pluginMu.Unlock()

	// The queue manager is not rebuilt on reload — it owns the queue and
	// replacing it would strand in-flight work — but settings that only change
	// how it writes can be applied to the live one. Without this the tombstone
	// setting saved, reported success, and did nothing until a restart.
	if m, ok := s.queueManager.(interface{ SetTombstoneBody(bool) }); ok {
		m.SetTombstoneBody(newConfig.QueueRetainTombstoneBody == nil ||
			*newConfig.QueueRetainTombstoneBody)
	}

	s.slogger.Info("Configuration reloaded",
		"event_type", "system",
		"antivirus", next.scanners.HasAntivirusScanners(),
		"antispam", next.scanners.HasAntispamScanners(),
		"access_control", next.accessControl.Enabled(),
		"rbl", next.rbl.Enabled(),
		"mail_auth", next.authVerifier.Enabled(),
		"retain_tombstone_body", newConfig.QueueRetainTombstoneBody == nil || *newConfig.QueueRetainTombstoneBody,
		"note", "listen address, size limits, timeouts and the queue backend still need a restart",
	)
	return nil
}

// buildReloadable constructs the swappable components, failing as a unit.
func (s *Server) buildReloadable(ctx context.Context, config *Config, logger *slog.Logger) (*reloadableComponents, error) {
	scanners := NewScannerManager(config, s)
	if err := scanners.Initialize(ctx); err != nil {
		// Consistent with startup: an unreachable scanner is a warning, not a
		// refusal, or a scanner outage would also become a reload outage.
		logger.Warn("Error initializing scanners during reload", "error", err)
	}

	accessControl, err := NewAccessControl(config.AccessControl, logger)
	if err != nil {
		return nil, fmt.Errorf("access control configuration: %w", err)
	}

	rbl, err := NewRBLChecker(config.RBL, logger)
	if err != nil {
		return nil, fmt.Errorf("rbl configuration: %w", err)
	}

	return &reloadableComponents{
		scanners:      scanners,
		accessControl: accessControl,
		rbl:           rbl,
		authVerifier:  authresult.New(authPluginRuntimeConfig(config)),
	}, nil
}

// currentAccessControl exists because reload writes this field while the accept
// loop reads it. Reading the struct field directly would be a data race that
// only shows up when an operator saves a setting during traffic — which is
// precisely when it would happen.
//
// There is no matching accessor for the scanners or the blocklists: the session
// path reads all three together under a single RLock, so that a reload landing
// between two of them cannot give one session the old policy for one and the
// new policy for another. Per-component accessors there would quietly lose that.
func (s *Server) currentAccessControl() *AccessControl {
	s.pluginMu.RLock()
	defer s.pluginMu.RUnlock()
	return s.accessControl
}
