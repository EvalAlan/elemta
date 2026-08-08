package commands

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/busybox42/elemta/internal/logging"
	"github.com/busybox42/elemta/internal/runtimepaths"
	"github.com/busybox42/elemta/internal/server"
	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

// Define flags for server command
var (
	devMode        bool
	noAuthRequired bool
	portFlag       int

	// ServerRunFunc allows mocking the server run function for testing
	ServerRunFunc = func(cmd *cobra.Command, args []string) error {
		startServer()
		return nil
	}
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Elemta MTA server",
	Long:  `Start the Elemta Mail Transfer Agent server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ServerRunFunc(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Add flags to the server command
	serverCmd.Flags().BoolVar(&devMode, "dev", false, "Run server in development mode with simplified settings")
	serverCmd.Flags().BoolVar(&noAuthRequired, "no-auth-required", false, "Disable authentication requirement for server")
	serverCmd.Flags().IntVar(&portFlag, "port", 0, "Override the port to listen on (e.g. --port 2525)")
}

func startServer() {
	slog.Info("Starting Elemta MTA server")

	// Load configuration
	if cfg == nil {
		slog.Error("Configuration not loaded")
		os.Exit(1)
	}

	// Initialize logging with configured level
	logLevel := "INFO" // Default to INFO for production
	if cfg.Logging.Level != "" {
		logLevel = cfg.Logging.Level
	}
	if devMode {
		logLevel = "DEBUG" // Override to DEBUG in dev mode
	}
	logging.InitializeLogging(logLevel)

	slog.Info("Elemta MTA server starting", "event_type", "system",
		"hostname", cfg.Hostname,
		"listen_addr", cfg.ListenAddr,
		"log_level", logLevel,
		"dev_mode", devMode)

	// Apply flag overrides
	if devMode {
		slog.Info("Running in DEVELOPMENT mode - using simplified settings")
		cfg.Server.TLS = false // Disable TLS in dev mode

		// Set other dev mode settings here if needed
		if cfg.Queue.Dir == "" {
			cfg.Queue.Dir = "./queue" // Use local queue directory in dev mode
		}

		// Change to non-privileged port in dev mode if using default port 25
		if cfg.EffectiveListenAddr() == ":25" {
			// Try various development ports (2525-2528) to find one that works
			devPorts := []string{":2525", ":2526", ":2527", ":2528"}
			originalPort := cfg.EffectiveListenAddr()

			for _, port := range devPorts {
				// Try to listen on the port to see if it's available
				listener, err := net.Listen("tcp", port)
				if err == nil {
					// Close the listener, we'll reopen it in the server
					_ = listener.Close() // Ignore error on test listener cleanup
					cfg.SetListenAddr(port)
					slog.Info("DEV MODE: Changed listen port (non-privileged)", "original_port", originalPort, "new_port", port)
					break
				}
			}

			if cfg.EffectiveListenAddr() == ":25" {
				slog.Warn("Could not find an available development port. Will try to use port 25, but this may fail without privileges.")
			}
		}
	}

	// Override port if specified via command line
	if portFlag > 0 {
		// Extract host part from the resolved listen address
		host := ""
		parts := strings.Split(cfg.EffectiveListenAddr(), ":")
		if len(parts) > 1 && parts[0] != "" {
			host = parts[0]
		}

		// Create new listen address with specified port
		cfg.SetListenAddr(fmt.Sprintf("%s:%d", host, portFlag))
		slog.Info("Overriding listen port", "address", cfg.EffectiveListenAddr())
	}

	if noAuthRequired && cfg.Auth != nil {
		slog.Info("Authentication requirement disabled via command line flag")
		cfg.Auth.Required = false
	}

	// Create SMTP server configuration.
	// All field mapping lives in config.ToSMTPConfig so that no field can be
	// silently forgotten here; see internal/config/smtp_config.go.
	if cfg.QueueDir == "" && cfg.Queue.Dir == "" {
		cfg.QueueDir = runtimepaths.Detect().QueueDir // Fallback default
		slog.Debug("using fallback queue directory", "queue_dir", cfg.QueueDir)
	}
	if devMode {
		cfg.Server.DevMode = true
	}

	smtpConfig, err := cfg.ToSMTPConfig()
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("SMTP Config",
		"hostname", smtpConfig.Hostname,
		"listen_addr", smtpConfig.ListenAddr,
		"queue_dir", smtpConfig.QueueDir,
		"queue_backend", smtpConfig.QueueBackend,
		"local_domains", smtpConfig.LocalDomains,
		"max_size", smtpConfig.MaxSize,
		"strict_line_endings", smtpConfig.StrictLineEndingsEnabled())

	// Restore certDir logic for certificate monitoring
	certDir := "/var/elemta/certs" // Default certificate directory
	if cfg.TLS != nil {
		if cfg.TLS.LetsEncrypt.Enabled && cfg.TLS.LetsEncrypt.CacheDir != "" {
			certDir = cfg.TLS.LetsEncrypt.CacheDir
		} else if cfg.TLS.CertFile != "" {
			certDir = getDirectoryFromPath(cfg.TLS.CertFile)
		}
	}

	slog.Info("Queue processor config",
		"enabled", smtpConfig.QueueProcessorEnabled,
		"interval", smtpConfig.QueueProcessInterval,
		"workers", smtpConfig.QueueWorkers)

	// Create SMTP server
	slog.Info("Creating SMTP server")
	server, err := smtp.NewServer(smtpConfig)
	if err != nil {
		slog.Error("Error creating server", "error", err)
		os.Exit(1)
	}

	// Start SMTP server
	slog.Info("Starting SMTP server")
	if err := server.Start(); err != nil {
		slog.Error("Error starting server", "error", err)
		os.Exit(1)
	}

	// Initialize certificate monitoring if TLS is enabled
	if cfg.Server.TLS {
		// Start certificate metrics monitoring in a goroutine
		go initializeCertificateMonitoring(certDir)
	}

	// Log server configuration details
	slog.Info("Server configuration details",
		"hostname", smtpConfig.Hostname,
		"listen_addr", smtpConfig.ListenAddr,
		"queue_dir", smtpConfig.QueueDir,
		"max_size", smtpConfig.MaxSize,
		"queue_processor", smtpConfig.QueueProcessorEnabled,
		"tls_enabled", cfg.Server.TLS,
		"cert_dir", certDir,
		"dev_mode", devMode,
		"auth_required", func() bool {
			if cfg.Auth != nil {
				return cfg.Auth.Required
			}
			return false
		}())

	slog.Info("Elemta MTA starting", "event_type", "system", "listen_addr", smtpConfig.ListenAddr)
	slog.Info("SMTP server started successfully")

	// Wait for signal to quit
	slog.Info("Server running. Press Ctrl+C to stop")

	// Set up signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Wait()
	}()

	select {
	case <-sigChan:
		slog.Info("Shutdown signal received, stopping server")
	case err := <-errChan:
		if err != nil {
			slog.Error("Server error occurred", "error", err)
		} else {
			slog.Info("Server stopped normally")
		}
	}

	// Perform graceful shutdown
	slog.Info("Shutting down server")
	_ = server.Close() // Ignore error on graceful shutdown
}

// initializeCertificateMonitoring starts monitoring TLS certificates
func initializeCertificateMonitoring(certDir string) {
	slog.Info("Starting TLS certificate monitoring", "directory", certDir)

	// Initial scan of certificates
	if err := server.GetCertificateMetrics(certDir+"/fullchain.pem", ""); err != nil {
		slog.Warn("Initial certificate metrics collection failed", "error", err)
	}

	// Start periodic monitoring
	server.MonitorCertificates(certDir, 12*time.Hour)
}

// getDirectoryFromPath extracts the directory part from a file path
func getDirectoryFromPath(path string) string {
	if path == "" {
		return "/var/elemta/certs"
	}

	// Find the last separator
	lastSep := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			lastSep = i
			break
		}
	}

	if lastSep == -1 {
		return "."
	}

	return path[:lastSep]
}
