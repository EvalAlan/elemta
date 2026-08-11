package commands

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/busybox42/elemta/internal/api"
	"github.com/busybox42/elemta/internal/config"
	"github.com/spf13/cobra"
)

// convertToAPIMainConfig converts config.Config to api.MainConfig
func convertToAPIMainConfig(cfg *config.Config) *api.MainConfig {
	// Use Server struct fields for primary config, fallback to top-level fields
	hostname := cfg.Server.Hostname
	if hostname == "" {
		hostname = cfg.Hostname // fallback
	}

	listenAddr := cfg.Server.Listen
	if listenAddr == "" {
		listenAddr = cfg.ListenAddr // fallback
	}

	maxSize := cfg.Server.MaxSize
	if maxSize == 0 {
		maxSize = cfg.MaxSize // fallback
	}

	localDomains := cfg.Server.LocalDomains
	if len(localDomains) == 0 {
		localDomains = cfg.LocalDomains // fallback
	}

	queueDir := cfg.Queue.Dir
	if queueDir == "" {
		queueDir = cfg.QueueDir
	}

	var authAllowDeprecatedSHA1 *bool
	if cfg.Auth != nil {
		authAllowDeprecatedSHA1 = cfg.Auth.AllowDeprecatedSHA1
	}

	// Mirror scanner configuration into the API's own types; internal/api
	// cannot import internal/smtp without a cycle.
	var antivirus *api.ScannerStatus
	if av := cfg.Antivirus; av != nil && av.ClamAV != nil {
		antivirus = &api.ScannerStatus{
			Enabled:         av.Enabled && av.ClamAV.Enabled,
			Address:         av.ClamAV.Address,
			Timeout:         av.ClamAV.Timeout,
			ScanLimit:       av.ClamAV.ScanLimit,
			RejectOnFailure: av.RejectOnFailure,
		}
	}
	var accessControl *api.AccessControlStatus
	if ac := cfg.AccessControl; ac != nil {
		accessControl = &api.AccessControlStatus{
			Enabled:      ac.Enabled,
			AllowIPs:     ac.AllowIPs,
			DenyIPs:      ac.DenyIPs,
			AllowDomains: ac.AllowDomains,
			DenyDomains:  ac.DenyDomains,
		}
	}

	var antispam *api.ScannerStatus
	if as := cfg.Antispam; as != nil && as.Rspamd != nil {
		antispam = &api.ScannerStatus{
			Enabled:      as.Enabled && as.Rspamd.Enabled,
			Address:      as.Rspamd.Address,
			Timeout:      as.Rspamd.Timeout,
			ScanLimit:    as.Rspamd.ScanLimit,
			Threshold:    as.Rspamd.Threshold,
			RejectOnSpam: as.RejectOnSpam,
		}
	}

	var rbl *api.RBLStatus
	if r := cfg.RBL; r != nil {
		rbl = &api.RBLStatus{
			Enabled:   r.Enabled,
			Zones:     r.Zones,
			Reject:    r.Reject,
			Timeout:   r.Timeout,
			SkipIPs:   r.SkipIPs,
			CacheTTL:  r.CacheTTL,
			CacheSize: r.CacheSize,
		}
	}

	var massMailer *api.MassMailerStatus
	if mm := cfg.MassMailer; mm != nil {
		massMailer = &api.MassMailerStatus{
			Enabled:              mm.Enabled,
			DefaultRatePerMinute: mm.DefaultRatePerMinute,
			MaxRecipients:        mm.MaxRecipients,
		}
	}

	var spfStatus *api.SPFStatus
	var dkimStatus *api.DKIMStatus
	var dmarcStatus *api.DMARCStatus
	if p := cfg.Plugins.SPF; p != nil {
		spfStatus = &api.SPFStatus{Enabled: p.Enabled, Timeout: p.Timeout}
	}
	if p := cfg.Plugins.DKIM; p != nil {
		domains := make([]api.SigningDomainStatus, 0, len(p.Domains))
		for _, domain := range p.Domains {
			domains = append(domains, api.SigningDomainStatus{
				Domain: domain.Domain, Selector: domain.Selector,
				PrivateKeyPath: domain.PrivateKeyPath,
				HeadersToSign:  append([]string(nil), domain.HeadersToSign...),
			})
		}
		dkimStatus = &api.DKIMStatus{
			Enabled: p.Enabled, Verify: p.Verify, Sign: p.Sign,
			HeaderCanonicalization: p.HeaderCanonicalization,
			BodyCanonicalization:   p.BodyCanonicalization, Domains: domains,
		}
	}
	if p := cfg.Plugins.DMARC; p != nil {
		dmarcStatus = &api.DMARCStatus{Enabled: p.Enabled, Enforce: p.Enforce, Timeout: p.Timeout}
	}
	// Legacy sections remain visible during migration. An explicitly configured
	// plugin table wins; missing plugin tables inherit the old aggregate values.
	// The first successful dashboard write then persists all canonical tables and
	// removes the legacy section, including from an otherwise ambiguous file.
	if cfg.InboundAuth != nil {
		if spfStatus == nil {
			spfStatus = &api.SPFStatus{Enabled: cfg.InboundAuth.Enabled, Timeout: cfg.InboundAuth.Timeout}
		}
		if dkimStatus == nil {
			dkimStatus = &api.DKIMStatus{Enabled: cfg.InboundAuth.Enabled, Verify: cfg.InboundAuth.Enabled}
		}
		if dmarcStatus == nil {
			dmarcStatus = &api.DMARCStatus{Enabled: cfg.InboundAuth.Enabled, Enforce: cfg.InboundAuth.EnforceDMARC, Timeout: cfg.InboundAuth.Timeout}
		}
	}
	if cfg.DKIM != nil {
		if dkimStatus == nil {
			dkimStatus = &api.DKIMStatus{}
		}
		domains := make([]api.SigningDomainStatus, 0, len(cfg.DKIM.Domains))
		for _, domain := range cfg.DKIM.Domains {
			domains = append(domains, api.SigningDomainStatus{
				Domain: domain.Domain, Selector: domain.Selector,
				PrivateKeyPath: domain.PrivateKeyPath, HeadersToSign: append([]string(nil), domain.HeadersToSign...),
			})
		}
		dkimStatus.Enabled = dkimStatus.Enabled || cfg.DKIM.Enabled
		dkimStatus.Sign = cfg.DKIM.Enabled
		dkimStatus.HeaderCanonicalization = cfg.DKIM.HeaderCanonicalization
		dkimStatus.BodyCanonicalization = cfg.DKIM.BodyCanonicalization
		dkimStatus.Domains = domains
	}

	return &api.MainConfig{
		Hostname:                  hostname,
		ListenAddr:                listenAddr,
		QueueDir:                  queueDir,
		QueueBackend:              cfg.Queue.Backend,
		QueueSQLitePath:           cfg.Queue.SQLite.Path,
		QueueSQLiteBusyTimeoutMS:  cfg.Queue.SQLite.BusyTimeoutMS,
		QueueSQLiteJournalMode:    cfg.Queue.SQLite.JournalMode,
		QueueSQLiteSynchronous:    cfg.Queue.SQLite.Synchronous,
		QueuePostgresDSN:          cfg.Queue.Postgres.DSN,
		QueuePostgresMaxOpenConns: cfg.Queue.Postgres.MaxOpenConns,
		QueuePostgresMaxIdleConns: cfg.Queue.Postgres.MaxIdleConns,
		QueuePostgresConnMaxLifeS: cfg.Queue.Postgres.ConnMaxLifetimeSeconds,
		QueueIndexedFSIndexPath:   cfg.Queue.IndexedFS.IndexPath,
		QueueIndexedFSContentDir:  cfg.Queue.IndexedFS.ContentDir,
		QueueIndexedFSSyncMode:    cfg.Queue.IndexedFS.SyncMode,
		QueueIndexedFSRecovery:    cfg.Queue.IndexedFS.RecoveryOnStartup,
		MaxSize:                   maxSize,
		MaxWorkers:                cfg.MaxWorkers,
		MaxRetries:                cfg.MaxRetries,
		MaxQueueTime:              cfg.MaxQueueTime,
		RetrySchedule:             cfg.RetrySchedule,
		SessionTimeout:            cfg.SessionTimeout,
		LocalDomains:              localDomains,
		FailedQueueRetentionHours: cfg.FailedQueueRetentionHours,
		AuthAllowDeprecatedSHA1:   authAllowDeprecatedSHA1,
		RateLimiterPluginConfig:   cfg.RateLimiter,
		TLS:                       cfg.TLS,
		TLSEnabled:                cfg.TLS != nil && cfg.TLS.Enabled,
		TLSCertFile: func() string {
			if cfg.TLS != nil {
				return cfg.TLS.CertFile
			}
			return ""
		}(),
		API:               nil, // API config not available in main config
		MassMailer:        massMailer,
		Antivirus:         antivirus,
		Antispam:          antispam,
		AccessControl:     accessControl,
		RBL:               rbl,
		SPF:               spfStatus,
		DKIM:              dkimStatus,
		DMARC:             dmarcStatus,
		LegacyInboundAuth: cfg.InboundAuth != nil,
		LegacyDKIM:        cfg.DKIM != nil,
	}
}

var (
	webListenAddr string
	webRoot       string
	webQueueDir   string
	authEnabled   bool
	authFile      string
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web interface",
	Long: `Start the Elemta web dashboard interface.
This provides a web-based UI for monitoring and managing mail queues.`,
	Run: runWeb,
}

func init() {
	rootCmd.AddCommand(webCmd)

	// Web-specific flags
	webCmd.Flags().StringVarP(&webListenAddr, "listen", "l", "127.0.0.1:8025", "Address to listen on")
	webCmd.Flags().StringVar(&webRoot, "web-root", "", "Path to web static files")
	webCmd.Flags().StringVar(&webQueueDir, "queue-dir", "", "Path to queue directory")
	webCmd.Flags().BoolVar(&authEnabled, "auth-enabled", false, "Enable authentication and authorization")
	webCmd.Flags().StringVar(&authFile, "auth-file", "", "Path to users file for authentication")
}

func runWeb(cmd *cobra.Command, args []string) {
	// Reuse the root command's already-loaded config so --config is honored.
	cfg := GetConfig()
	if cfg == nil {
		var err error
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			log.Printf("Warning: failed to load config, using defaults: %v", err)
			cfg = config.DefaultConfig()
		}
	}

	// Find config file path for persistence
	resolvedConfigPath, _ := config.FindConfigFile(configPath)

	resolvedWebRoot := webRoot
	if !cmd.Flags().Changed("web-root") {
		resolvedWebRoot = cfg.API.WebRoot
	}
	if resolvedWebRoot == "" {
		resolvedWebRoot = "./web/static"
	}

	resolvedQueueDir := webQueueDir
	if resolvedQueueDir == "" {
		resolvedQueueDir = cfg.Queue.Dir
	}
	if resolvedQueueDir == "" {
		resolvedQueueDir = config.DefaultConfig().Queue.Dir
	}

	resolvedAuthEnabled := authEnabled
	if !cmd.Flags().Changed("auth-enabled") {
		resolvedAuthEnabled = cfg.API.AuthEnabled
	}

	resolvedAuthFile := authFile
	if !cmd.Flags().Changed("auth-file") {
		resolvedAuthFile = cfg.API.AuthFile
	}

	if resolvedAuthEnabled && resolvedAuthFile != "" {
		if fi, err := os.Stat(resolvedAuthFile); err == nil && fi.IsDir() {
			log.Printf("Warning: auth file path %q is a directory; disabling web auth", resolvedAuthFile)
			resolvedAuthEnabled = false
			resolvedAuthFile = ""
		}
	}

	// Create API config
	resolvedListenAddr := webListenAddr
	if !cmd.Flags().Changed("listen") && cfg.API.ListenAddr != "" {
		resolvedListenAddr = cfg.API.ListenAddr
	}

	apiConfig := &api.Config{
		Enabled:     true,
		ListenAddr:  resolvedListenAddr,
		WebRoot:     resolvedWebRoot,
		AuthEnabled: resolvedAuthEnabled,
		AuthFile:    resolvedAuthFile,
		ValkeyAddr:  cfg.API.ValkeyAddr,
		RateLimit: api.RateLimitConfig{
			Enabled:           cfg.API.RateLimit.Enabled,
			RequestsPerSecond: cfg.API.RateLimit.RequestsPerSecond,
			Burst:             cfg.API.RateLimit.Burst,
		},
		CORS: api.CORSConfig{
			Enabled:          cfg.API.CORS.Enabled,
			AllowedOrigins:   cfg.API.CORS.AllowedOrigins,
			AllowedMethods:   cfg.API.CORS.AllowedMethods,
			AllowedHeaders:   cfg.API.CORS.AllowedHeaders,
			AllowCredentials: cfg.API.CORS.AllowCredentials,
			MaxAge:           cfg.API.CORS.MaxAge,
		},
	}

	// Create and start API server.
	//
	// These failures are fatal and the container restart policy will bring the
	// process straight back to fail again, so they have to be findable. Going
	// through log.Fatalf alone routed them through the standard logger at INFO,
	// which meant a misconfigured auth file produced an endless restart loop
	// whose only trace was an INFO line — invisible to anyone filtering on
	// errors. Log at ERROR first, with the remedy, then exit.
	server, err := api.NewServer(apiConfig, convertToAPIMainConfig(cfg), resolvedQueueDir, cfg.FailedQueueRetentionHours, resolvedConfigPath)
	if err != nil {
		slog.Error("Failed to create API server; the web interface cannot start",
			"error", err,
			"auth_enabled", resolvedAuthEnabled,
			"auth_file", resolvedAuthFile,
			"hint", "if this names the auth file, check it exists and is readable by the user the server runs as; `elemta user add` creates it",
		)
		os.Exit(1)
	}

	if err := server.Start(); err != nil {
		slog.Error("Failed to start API server; the web interface cannot start",
			"error", err,
			"listen_addr", resolvedListenAddr,
			"hint", "check that the listen address is free and permitted",
		)
		os.Exit(1)
	}

	fmt.Printf("Elemta web interface started on http://%s\n", resolvedListenAddr)
	fmt.Println("Press Ctrl+C to stop")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down web interface...")
	if err := server.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}
