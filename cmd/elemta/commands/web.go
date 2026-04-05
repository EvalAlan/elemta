package commands

import (
	"fmt"
	"log"
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

	return &api.MainConfig{
		Hostname:                  hostname,
		ListenAddr:                listenAddr,
		QueueDir:                  queueDir,
		QueueBackend:              cfg.Queue.Backend,
		QueueSQLitePath:           cfg.Queue.SQLite.Path,
		QueueSQLiteBusyTimeoutMS:  cfg.Queue.SQLite.BusyTimeoutMS,
		QueueSQLiteJournalMode:    cfg.Queue.SQLite.JournalMode,
		QueueSQLiteSynchronous:    cfg.Queue.SQLite.Synchronous,
		MaxSize:                   maxSize,
		MaxWorkers:                cfg.MaxWorkers,
		MaxRetries:                cfg.MaxRetries,
		MaxQueueTime:              cfg.MaxQueueTime,
		RetrySchedule:             cfg.RetrySchedule,
		SessionTimeout:            cfg.SessionTimeout,
		LocalDomains:              localDomains,
		FailedQueueRetentionHours: cfg.FailedQueueRetentionHours,
		RateLimiterPluginConfig:   cfg.RateLimiter,
		TLS:                       cfg.TLS,
		API:                       nil, // API config not available in main config
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

	// Create and start API server
	server, err := api.NewServer(apiConfig, convertToAPIMainConfig(cfg), resolvedQueueDir, cfg.FailedQueueRetentionHours, resolvedConfigPath)
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
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
