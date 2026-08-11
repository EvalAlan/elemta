package config

import (
	"fmt"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
)

// ToSMTPConfig converts the top-level elemta configuration into the SMTP
// server's configuration.
//
// This is the single conversion point between the two config structs. It exists
// because the mapping used to be an inline struct literal in the server command,
// where every field had to be remembered by hand — fields that were forgotten
// silently took their Go zero value, which quietly disabled security controls
// such as strict_line_endings and left retry/queue tuning at zero.
//
// Two rules keep that from happening again:
//   - Every field is assigned here, in the same order as smtp.Config declares it.
//   - smtp.ApplyDefaults is called at the end so this path gets exactly the same
//     defaults as smtp.LoadConfig.
//
// TestToSMTPConfig_AllFieldsMapped enforces the first rule via reflection.
func (c *Config) ToSMTPConfig() (*smtp.Config, error) {
	out := &smtp.Config{
		ListenAddr:    c.EffectiveListenAddr(),
		QueueDir:      c.EffectiveQueueDir(),
		QueueBackend:  c.Queue.Backend,
		MaxSize:       c.EffectiveMaxSize(),
		DevMode:       c.Server.DevMode,
		AllowedRelays: c.AllowedRelays,
		LocalDomains:  c.EffectiveLocalDomains(),
		Hostname:      c.EffectiveHostname(),
		MaxWorkers:    c.MaxWorkers,
		// Reaches the delivery handler's traffic shaper. Unmapped until now,
		// which is why the setting did nothing.
		MaxConnectionsPerDomain: c.MaxConnectionsPerDomain,
		MaxRetries:              c.MaxRetries,
		MaxQueueTime:            c.MaxQueueTime,
		RetrySchedule:           c.RetrySchedule,

		QueueSQLite: smtp.QueueSQLiteConfig{
			Path:          c.Queue.SQLite.Path,
			BusyTimeoutMS: c.Queue.SQLite.BusyTimeoutMS,
			JournalMode:   c.Queue.SQLite.JournalMode,
			Synchronous:   c.Queue.SQLite.Synchronous,
		},
		QueuePostgres: smtp.QueuePostgresConfig{
			DSN:                    c.Queue.Postgres.DSN,
			MaxOpenConns:           c.Queue.Postgres.MaxOpenConns,
			MaxIdleConns:           c.Queue.Postgres.MaxIdleConns,
			ConnMaxLifetimeSeconds: c.Queue.Postgres.ConnMaxLifetimeSeconds,
		},
		QueueIndexedFS: smtp.QueueIndexedFSConfig{
			IndexPath:         c.Queue.IndexedFS.IndexPath,
			ContentDir:        c.Queue.IndexedFS.ContentDir,
			SyncMode:          c.Queue.IndexedFS.SyncMode,
			RecoveryOnStartup: c.Queue.IndexedFS.RecoveryOnStartup,
		},

		FailedQueueRetentionHours: c.FailedQueueRetentionHours,
		QueueWorkers:              c.QueueProcessor.Workers,

		QueueProcessorEnabled: c.QueueProcessor.Enabled,
		QueueProcessInterval:  c.QueueProcessor.Interval,

		Auth:          c.Auth,
		TLS:           c.TLS,
		Resources:     c.Resources,
		Antivirus:     c.Antivirus,
		AccessControl: c.AccessControl,
		RBL:           c.RBL,
		InboundAuth:   c.InboundAuth,
		Antispam:      c.Antispam,
		Metrics:       c.Metrics,
		Delivery:      c.Delivery,
		DKIM:          c.DKIM,
		Memory:        c.Memory,

		Timeouts: smtp.TimeoutConfig{
			SessionTimeout:    c.Timeouts.SessionTimeout,
			CommandTimeout:    c.Timeouts.CommandTimeout,
			DataTimeout:       c.Timeouts.DataTimeout,
			ShutdownTimeout:   c.Timeouts.ShutdownTimeout,
			ConnectionTimeout: c.Timeouts.ConnectionTimeout,
			AuthTimeout:       c.Timeouts.AuthTimeout,
		},

		StrictLineEndings:   c.StrictLineEndings,
		SpoolThresholdBytes: c.SpoolThresholdBytes,
		TrustedNetworks:     c.TrustedNetworks,
	}

	// Fields below have no counterpart in the top-level config and are left for
	// ApplyDefaults / the SMTP layer to fill in:
	//   Cache, Rules            - not exposed via TOML (json tags only)
	//   KeepDeliveredMessages   - consumed by the queue, not the SMTP server
	//   KeepMessageData         - consumed by the queue, not the SMTP server
	//   QueuePriorityEnabled    - not currently consumed
	//   MessageRetentionHours   - not currently consumed
	//   ConnectTimeout          - not currently consumed
	//   SMTPTimeout             - not currently consumed

	if c.SessionTimeout != "" {
		d, err := time.ParseDuration(c.SessionTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid session_timeout %q: %w", c.SessionTimeout, err)
		}
		out.SessionTimeout = d
	} else {
		out.SessionTimeout = c.Timeouts.SessionTimeout
	}

	if len(c.Plugins.Enabled) > 0 {
		out.Plugins = &smtp.PluginConfig{
			Enabled:    true,
			PluginPath: c.Plugins.Directory,
			Plugins:    c.Plugins.Enabled,
		}
	}

	out.ApplyDefaults()
	return out, nil
}

// EffectiveHostname resolves the hostname from the flat key, falling back to
// the legacy [server] section.
func (c *Config) EffectiveHostname() string {
	if c.Hostname != "" {
		return c.Hostname
	}
	return c.Server.Hostname
}

// EffectiveListenAddr resolves the SMTP listen address. The flat listen_addr
// key wins; the legacy [server] listen key is the fallback.
func (c *Config) EffectiveListenAddr() string {
	if c.ListenAddr != "" {
		return c.ListenAddr
	}
	return c.Server.Listen
}

// EffectiveMaxSize resolves the maximum message size from the flat key,
// falling back to the legacy [server] section.
func (c *Config) EffectiveMaxSize() int64 {
	if c.MaxSize != 0 {
		return c.MaxSize
	}
	return c.Server.MaxSize
}

// EffectiveLocalDomains resolves the local domain list from the flat key,
// falling back to the legacy [server] section.
func (c *Config) EffectiveLocalDomains() []string {
	if len(c.LocalDomains) > 0 {
		return c.LocalDomains
	}
	return c.Server.LocalDomains
}

// EffectiveQueueDir resolves the queue directory, accepting both the flat
// queue_dir key and the nested [queue] dir key.
func (c *Config) EffectiveQueueDir() string {
	if c.QueueDir != "" {
		return c.QueueDir
	}
	return c.Queue.Dir
}

// SetListenAddr overrides the resolved listen address on both the flat and
// legacy keys, so command-line flags apply regardless of which form the
// operator's config file uses.
func (c *Config) SetListenAddr(addr string) {
	c.ListenAddr = addr
	c.Server.Listen = addr
}
