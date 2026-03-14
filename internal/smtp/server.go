package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	deliverymetrics "github.com/busybox42/elemta/internal/metrics"
	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
	"github.com/sony/gobreaker"
	"golang.org/x/sync/errgroup"
)

// Server represents an SMTP server
type Server struct {
	config          *Config
	listener        net.Listener
	running         bool
	pluginManager   *plugin.Manager
	builtinPlugins  *plugin.BuiltinPlugins // Built-in plugins for spam/antivirus scanning
	authenticator   Authenticator
	metricsManager  *MetricsManager    // Extracted metrics management
	queueManager    queue.QueueManager // Unified queue system
	queueProcessor  *queue.Processor   // Queue processor for message delivery
	tlsManager      TLSHandler
	resourceManager *ResourceManager // Resource management and rate limiting
	slogger         *slog.Logger     // Structured logger for resource management

	// Concurrency management
	workerPool   *WorkerPool        // Standardized worker pool for connection handling
	rootCtx      context.Context    // Server root context for lifecycle management
	rootCancel   context.CancelFunc // Server root context cancellation
	ctx          context.Context    // Server context for graceful shutdown (worker context)
	cancel       context.CancelFunc
	errGroup     *errgroup.Group // Coordinated goroutine management
	shutdownOnce sync.Once       // Ensure shutdown is called only once
}

// initPlugins initializes the plugin manager and builtin plugins.
func initPlugins(config *Config, slogger *slog.Logger) (*plugin.Manager, *plugin.BuiltinPlugins) {
	var pluginManager *plugin.Manager
	var builtinPlugins *plugin.BuiltinPlugins

	if config.Plugins != nil && config.Plugins.Enabled {
		pluginManager = plugin.NewManager(config.Plugins.PluginPath)
		slogger.Info("Plugin system enabled", "path", config.Plugins.PluginPath)

		if err := pluginManager.LoadPlugins(); err != nil {
			slogger.Warn("Failed to load plugins", "error", err)
		}

		if len(config.Plugins.Plugins) > 0 {
			slogger.Info("Attempting to load specified plugins", "count", len(config.Plugins.Plugins))
			for _, pluginName := range config.Plugins.Plugins {
				if err := pluginManager.LoadPlugin(pluginName); err != nil {
					slogger.Warn("Failed to load plugin", "plugin", pluginName, "error", err)
				} else {
					slogger.Info("Successfully loaded plugin", "plugin", pluginName)
				}
			}
		}
	}

	builtinPlugins = plugin.NewBuiltinPlugins()

	if config.Plugins != nil && config.Plugins.Enabled {
		clamAVEnabled := os.Getenv("ELEMTA_DISABLE_CLAMAV") != "true"

		var pluginNames []string
		pluginConfig := make(map[string]map[string]interface{})

		if len(config.Plugins.Plugins) > 0 {
			pluginNames = config.Plugins.Plugins
		} else {
			pluginNames = []string{"rspamd"}
			if clamAVEnabled {
				pluginNames = append(pluginNames, "clamav")
			}
		}

		if clamAVEnabled {
			pluginConfig["clamav"] = map[string]interface{}{
				"host":    "elemta-clamav",
				"port":    3310,
				"timeout": 30,
			}
		}
		pluginConfig["rspamd"] = map[string]interface{}{
			"host":      "elemta-rspamd",
			"port":      11334,
			"timeout":   30,
			"threshold": 5.0,
		}

		if err := builtinPlugins.InitBuiltinPlugins(pluginNames, pluginConfig); err != nil {
			slogger.Warn("Failed to initialize builtin plugins", "error", err)
		} else {
			slogger.Info("Builtin plugins initialized successfully")
		}
	} else {
		slogger.Info("Plugins disabled or not configured")
	}

	return pluginManager, builtinPlugins
}

// initAuthenticator initializes the SMTP authenticator.
func initAuthenticator(config *Config, slogger *slog.Logger) (Authenticator, error) {
	if config.Auth != nil && config.Auth.Enabled {
		slogger.Info("Authentication enabled, initializing authenticator")
		authenticator, err := NewAuthenticator(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize authenticator: %w", err)
		}
		if config.Auth.Required {
			slogger.Info("Authentication will be required for all mail transactions")
		} else {
			slogger.Info("Authentication available but not required")
		}
		return authenticator, nil
	}

	slogger.Info("Authentication disabled, using dummy authenticator")
	return &SMTPAuthenticator{
		config: &AuthConfig{
			Enabled:  false,
			Required: false,
		},
	}, nil
}

// initQueueSystem initializes the queue manager and optional queue processor.
func initQueueSystem(config *Config, slogger *slog.Logger) (*queue.Manager, *queue.Processor) {
	slogger.Info("Initializing unified queue system", "directory", config.QueueDir)
	queueManager := queue.NewManager(config.QueueDir, config.FailedQueueRetentionHours)
	slogger.Info("Unified queue system initialized")

	var queueProcessor *queue.Processor
	if config.QueueProcessorEnabled {
		slogger.Info("Queue processor enabled, initializing")

		deliveryHost := "elemta-dovecot"
		deliveryPort := 2424
		if config.Delivery != nil {
			if config.Delivery.Host != "" {
				deliveryHost = config.Delivery.Host
			}
			if config.Delivery.Port != 0 {
				deliveryPort = config.Delivery.Port
			}
		}

		maxPerDomain := config.MaxConnectionsPerDomain
		if maxPerDomain <= 0 {
			maxPerDomain = 10
		}

		slogger.Info("Creating LMTP delivery handler", "host", deliveryHost, "port", deliveryPort, "max_per_domain", maxPerDomain)
		lmtpHandler := queue.NewLMTPDeliveryHandler(deliveryHost, deliveryPort, maxPerDomain, config.FailedQueueRetentionHours)

		processorConfig := queue.ProcessorConfig{
			Enabled:       config.QueueProcessorEnabled,
			Interval:      time.Duration(config.QueueProcessInterval) * time.Second,
			MaxConcurrent: config.QueueWorkers,
			MaxRetries:    config.MaxRetries,
			RetrySchedule: config.RetrySchedule,
			CleanupAge:    24 * time.Hour,
		}

		slogger.Info("Creating queue processor",
			"enabled", processorConfig.Enabled,
			"interval", processorConfig.Interval,
			"workers", processorConfig.MaxConcurrent)

		queueProcessor = queue.NewProcessor(queueManager, processorConfig, lmtpHandler)
		slogger.Info("Queue processor initialized successfully")

		valkeyAddr := os.Getenv("VALKEY_ADDR")
		if valkeyAddr == "" {
			valkeyAddr = "elemta-valkey:6379"
		}
		metricsStore, err := deliverymetrics.NewValkeyStore(valkeyAddr)
		if err != nil {
			slogger.Warn("Failed to connect to Valkey for metrics", "error", err)
		} else {
			queueProcessor.SetMetricsRecorder(metricsStore)
			slogger.Info("Connected to Valkey for metrics", "address", valkeyAddr)
		}
	} else {
		slogger.Info("Queue processor disabled")
	}

	return queueManager, queueProcessor
}

// initResourceManager initializes resource limits and the resource manager.
func initResourceManager(config *Config, slogger *slog.Logger) (*ResourceManager, *ResourceLimits) {
	var resourceLimits *ResourceLimits
	var resourceManager *ResourceManager

	if config.Resources != nil {
		var memoryConfig *MemoryConfig
		if config.Memory != nil {
			memoryConfig = config.Memory
			slogger.Info("Using memory configuration",
				"total_mb", memoryConfig.MaxMemoryUsage/(1024*1024),
				"per_conn_mb", memoryConfig.PerConnectionMemoryLimit/(1024*1024))
		} else {
			memoryConfig = DefaultMemoryConfig()
			slogger.Info("Using default memory configuration",
				"total_mb", memoryConfig.MaxMemoryUsage/(1024*1024),
				"per_conn_mb", memoryConfig.PerConnectionMemoryLimit/(1024*1024))
		}

		maxConnPerIP := config.Resources.MaxConnectionsPerIP
		if maxConnPerIP == 0 {
			maxConnPerIP = config.Resources.MaxConcurrent
			if maxConnPerIP == 0 {
				maxConnPerIP = 50
			}
		}

		goroutinePoolSize := config.Resources.GoroutinePoolSize
		if goroutinePoolSize == 0 {
			goroutinePoolSize = 100
		}

		rateLimitWindow := time.Duration(config.Resources.RateLimitWindow) * time.Second
		if rateLimitWindow == 0 {
			rateLimitWindow = time.Minute
		}

		maxRequestsPerWindow := config.Resources.MaxRequestsPerWindow
		if maxRequestsPerWindow == 0 {
			maxRequestsPerWindow = config.Resources.MaxConnections * 10
		}

		resourceLimits = &ResourceLimits{
			MaxConnections:            config.Resources.MaxConnections,
			MaxConnectionsPerIP:       maxConnPerIP,
			MaxGoroutines:             config.Resources.MaxConnections * 2,
			ConnectionTimeout:         time.Duration(config.Resources.ConnectionTimeout) * time.Second,
			SessionTimeout:            time.Duration(config.Resources.SessionTimeout) * time.Second,
			IdleTimeout:               time.Duration(config.Resources.IdleTimeout) * time.Second,
			RateLimitWindow:           rateLimitWindow,
			MaxRequestsPerWindow:      maxRequestsPerWindow,
			MaxMemoryUsage:            memoryConfig.MaxMemoryUsage,
			GoroutinePoolSize:         goroutinePoolSize,
			CircuitBreakerEnabled:     true,
			ResourceMonitoringEnabled: true,
			ValkeyURL:                 config.Resources.ValkeyURL,
			ValkeyKeyPrefix:           config.Resources.ValkeyKeyPrefix,
		}

		resourceManager = NewResourceManager(resourceLimits, slogger)
		memoryManager := NewMemoryManager(memoryConfig, slogger)
		resourceManager.SetMemoryManager(memoryManager)
		slogger.Info("Resource manager initialized with memory protection enabled")
	} else {
		resourceLimits = DefaultResourceLimits()
		resourceManager = NewResourceManager(resourceLimits, slogger)
		memoryManager := NewMemoryManager(DefaultMemoryConfig(), slogger)
		resourceManager.SetMemoryManager(memoryManager)
		slogger.Info("Resource manager initialized with default memory protection")
	}

	return resourceManager, resourceLimits
}

// initConcurrency initializes the context hierarchy and worker pool.
func initConcurrency(slogger *slog.Logger, resourceLimits *ResourceLimits) (context.Context, context.CancelFunc, context.Context, context.CancelFunc, *errgroup.Group, context.Context, *WorkerPool) {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(rootCtx)
	errGroup, gctx := errgroup.WithContext(ctx)

	workerPoolConfig := &WorkerPoolConfig{
		Size:               20,
		JobBufferSize:      100,
		ResultBufferSize:   100,
		CircuitBreakerName: "smtp-connections",
		MaxRequests:        1000,
		Interval:           time.Minute,
		Timeout:            30 * time.Second,
		JobTimeout:         5 * time.Minute,
		ShutdownTimeout:    30 * time.Second,
		MaxGoroutines:      int32(resourceLimits.MaxGoroutines),
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			slogger.Info("SMTP connection circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
		},
	}

	workerPool := NewWorkerPool(workerPoolConfig, slogger)
	return rootCtx, rootCancel, ctx, cancel, errGroup, gctx, workerPool
}

// initTLSManager initializes the TLS manager if TLS is enabled.
func initTLSManager(config *Config, slogger *slog.Logger) (TLSHandler, error) {
	if config.TLS != nil && config.TLS.Enabled {
		slogger.Info("TLS enabled, initializing TLS manager")
		tlsManager, err := NewTLSManager(config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TLS manager: %w", err)
		}
		slogger.Info("TLS manager initialized successfully")

		if config.TLS.CertFile != "" {
			slogger.Info("Using TLS certificate", "file", config.TLS.CertFile)
		}
		if config.TLS.LetsEncrypt != nil && config.TLS.LetsEncrypt.Enabled {
			slogger.Info("Let's Encrypt enabled", "domain", config.TLS.LetsEncrypt.Domain)
		}
		return tlsManager, nil
	}

	slogger.Info("TLS disabled")
	return nil, nil
}

// NewServer creates a new SMTP server
func NewServer(config *Config) (*Server, error) {
	// Validate configuration
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("hostname not provided in config and could not be determined: %w", err)
		}
		config.Hostname = hostname
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":2525" // Default SMTP port (non-privileged)
	}

	slogger := slog.Default().With(
		"component", "smtp-server",
		"hostname", config.Hostname,
	)

	slogger.Info("Initializing SMTP server",
		"event_type", "system",
		"hostname", config.Hostname)

	// Log config summaries
	if config.Auth != nil {
		slogger.Info("Auth config loaded",
			"enabled", config.Auth.Enabled,
			"required", config.Auth.Required,
			"datasource", config.Auth.DataSourceType)
	}
	if config.TLS != nil {
		slogger.Info("TLS config loaded",
			"enabled", config.TLS.Enabled,
			"starttls", config.TLS.EnableStartTLS)
	}

	// Initialize subsystems
	pluginManager, builtinPlugins := initPlugins(config, slogger)

	authenticator, err := initAuthenticator(config, slogger)
	if err != nil {
		return nil, err
	}

	metrics := GetMetrics()
	slogger.Info("Metrics system initialized")
	metricsManager := NewMetricsManager(config, slogger, metrics)

	queueManager, queueProcessor := initQueueSystem(config, slogger)
	resourceManager, resourceLimits := initResourceManager(config, slogger)
	rootCtx, rootCancel, _, cancel, errGroup, gctx, workerPool := initConcurrency(slogger, resourceLimits)

	server := &Server{
		config:          config,
		running:         false,
		pluginManager:   pluginManager,
		builtinPlugins:  builtinPlugins,
		authenticator:   authenticator,
		metricsManager:  metricsManager,
		queueManager:    queueManager,
		queueProcessor:  queueProcessor,
		resourceManager: resourceManager,
		slogger:         slogger,
		workerPool:      workerPool,
		rootCtx:         rootCtx,
		rootCancel:      rootCancel,
		ctx:             gctx,
		cancel:          cancel,
		errGroup:        errGroup,
	}

	tlsManager, err := initTLSManager(config, slogger)
	if err != nil {
		return nil, err
	}
	server.tlsManager = tlsManager

	// Initialize scanner manager
	scannerManager := NewScannerManager(config, server)
	if err := scannerManager.Initialize(context.Background()); err != nil {
		slogger.Warn("Error initializing scanner manager",
			"error", err,
			"component", "scanner-manager",
		)
	}

	return server, nil
}

// Addr returns the server's listen address
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	if s.running {
		return fmt.Errorf("server already running")
	}

	s.slogger.Info("Starting SMTP server",
		"event_type", "system",
		"listen_addr", s.config.ListenAddr)

	// Create all required queue directories
	if err := s.setupQueueDirectories(); err != nil {
		return fmt.Errorf("queue directory setup failed: %w", err)
	}

	// Create listener
	s.slogger.Info("Creating TCP listener", "address", s.config.ListenAddr)
	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	s.slogger.Info("SMTP server running",
		"event_type", "system",
		"listen_addr", s.config.ListenAddr)

	// Start the new queue system if available
	if s.queueManager != nil {
		// The new queue system doesn't need explicit startup
		s.slogger.Info("Starting unified queue system")
		// The new queue system doesn't need explicit startup
		s.slogger.Info("Unified queue system started successfully")
	}

	// Start queue processor if available
	if s.queueProcessor != nil {
		s.slogger.Info("Starting queue processor")
		if err := s.queueProcessor.Start(); err != nil {
			s.slogger.Warn("Failed to start queue processor", "error", err)
		} else {
			s.slogger.Info("Queue processor started successfully")
		}
	}

	// Start metrics server if enabled
	if err := s.metricsManager.Start(); err != nil {
		s.slogger.Error("Failed to start metrics server", "error", err)
		return err
	}

	// Start periodic queue size updates
	go s.updateQueueMetricsWithRetry()

	// Start worker pool for connection handling
	s.slogger.Info("Starting worker pool", "workers", s.workerPool.size)
	if err := s.workerPool.Start(); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	// Handle connections with coordinated goroutine management
	s.errGroup.Go(s.acceptConnections)

	return nil
}

// setupQueueDirectories ensures all needed queue directories exist with secure permissions
func (s *Server) setupQueueDirectories() error {
	if s.config.QueueDir == "" {
		return fmt.Errorf("queue directory not configured")
	}

	// Ensure main queue directory exists with secure permissions (0700)
	if err := os.MkdirAll(s.config.QueueDir, 0700); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Create subdirectories for different queue types with secure permissions
	queueTypes := []string{"active", "deferred", "held", "failed", "data", "tmp", "quarantine"}

	for _, qType := range queueTypes {
		qDir := filepath.Join(s.config.QueueDir, qType)
		if err := os.MkdirAll(qDir, 0700); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %w", qType, err)
		}
		s.slogger.Info("Created secure queue directory", "path", qDir, "mode", "0700")
	}

	return nil
}

// updateQueueMetricsWithRetry periodically updates queue size metrics with retry on failure
func (s *Server) updateQueueMetricsWithRetry() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for s.running {
		// Update metrics and log any errors we encounter
		func() {
			// Use defer to catch any panics that might occur
			defer func() {
				if r := recover(); r != nil {
					s.slogger.Error("Panic in queue metrics update", "panic", r)
				}
			}()

			// Update queue metrics
			s.metricsManager.UpdateQueueSizes()
			s.slogger.Debug("Queue metrics updated successfully")
		}()

		<-ticker.C
	}
}

// acceptConnections accepts and handles incoming connections with standardized worker pool
func (s *Server) acceptConnections() error {
	s.slogger.Info("Starting connection acceptance loop")
	s.slogger.Debug("acceptConnections goroutine started")

	for {
		select {
		case <-s.ctx.Done():
			s.slogger.Info("Context cancelled, stopping connection acceptance")
			return s.ctx.Err()
		default:
		}

		// Set a short timeout on accept to allow periodic context checking
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				s.slogger.Error("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout error (expected)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			if s.running {
				s.slogger.Error("Failed to accept connection", "error", err)
			}
			continue
		}

		s.slogger.Debug("Connection accepted", "remote_addr", conn.RemoteAddr().String())

		// Reset deadline after successful accept
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Time{}) // Best effort
		}

		// Check if connection can be accepted based on resource limits
		clientAddr := conn.RemoteAddr().String()
		s.slogger.Debug("Checking if connection can be accepted", "client_addr", clientAddr)
		if !s.resourceManager.CanAcceptConnection(clientAddr) {
			s.slogger.Warn("Connection rejected due to resource limits", "client_ip", clientAddr)
			_ = conn.Close() // Ignore error when rejecting connection
			continue
		}
		s.slogger.Debug("Connection accepted by resource manager")

		// Create connection job for worker pool
		jobID := uuid.New().String()
		connectionJob := &ConnectionJob{
			id:        jobID,
			conn:      conn,
			handler:   s.handleConnectionWithContext,
			priority:  1, // Normal priority
			createdAt: time.Now(),
		}

		// Submit job to worker pool with timeout
		s.slogger.Debug("Submitting connection job to worker pool", "job_id", jobID)
		if err := s.workerPool.SubmitWithTimeout(connectionJob, 5*time.Second); err != nil {
			s.slogger.Warn("Failed to submit connection to worker pool, handling directly",
				"remote_addr", clientAddr,
				"job_id", jobID,
				"error", err,
				"worker_pool_stats", s.workerPool.GetStats(),
			)

			// Fallback: handle connection directly in a tracked goroutine
			s.errGroup.Go(func() error {
				defer func() {
					if r := recover(); r != nil {
						s.slogger.Error("panic in fallback connection handler",
							"remote_addr", clientAddr,
							"job_id", jobID,
							"panic", r,
						)
					}
				}()
				s.handleAndCloseSession(s.ctx, conn)
				return nil
			})
		} else {
			s.slogger.Debug("Connection submitted to worker pool",
				"remote_addr", clientAddr,
				"job_id", jobID,
			)
		}
	}
}

// handleConnectionWithContext processes a connection with proper context handling
// handleConnectionWithContext handles a connection with context support
func (s *Server) handleConnectionWithContext(ctx context.Context, conn interface{}) error {
	s.slogger.Debug("handleConnectionWithContext called")
	netConn, ok := conn.(net.Conn)
	if !ok {
		s.slogger.Debug("Invalid connection type")
		return fmt.Errorf("invalid connection type")
	}
	s.slogger.Debug("Connection type is valid, proceeding with session handling")

	// Ensure connection is closed when done
	defer func() {
		s.slogger.Debug("Closing connection")
		_ = netConn.Close() // Ignore error in defer cleanup
	}()

	// Handle the session with context - pass ctx to the session handler
	s.slogger.Debug("Calling handleAndCloseSession")
	s.handleAndCloseSession(ctx, netConn)
	s.slogger.Debug("handleAndCloseSession completed")
	return nil
}

// handleAndCloseSession processes a connection and ensures it's properly closed with guaranteed cleanup
func (s *Server) handleAndCloseSession(ctx context.Context, conn net.Conn) {
	clientIP := conn.RemoteAddr().String()
	s.slogger.Debug("handleAndCloseSession called", "client_ip", clientIP)
	var sessionID string
	var cleanupDone bool

	// Initialize logger if it's nil
	// Initialize logger if it's nil
	// if s.logger == nil { ... } - Removed

	// Guaranteed cleanup function that runs even on panic
	cleanup := func() {
		if cleanupDone {
			return
		}
		cleanupDone = true

		// Release connection from resource manager
		if sessionID != "" {
			s.resourceManager.ReleaseConnection(sessionID)
		}

		// Close the connection
		if err := conn.Close(); err != nil {
			s.slogger.Error("Failed to close connection during cleanup", "error", err, "client_ip", clientIP, "session_id", sessionID)
		}
	}

	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			s.slogger.Error("Panic in session handling", "panic", r, "client_ip", clientIP, "session_id", sessionID)
			cleanup()
			panic(r) // Re-panic to maintain panic behavior
		}
		cleanup()
	}()

	// Register connection with resource manager
	s.slogger.Debug("Registering connection with resource manager")
	sessionID = s.resourceManager.AcceptConnection(conn)
	s.slogger.Debug("Connection registered", "session_id", sessionID)
	s.slogger.Info("New connection", "client_ip", clientIP, "session_id", sessionID)

	// Set connection timeout
	s.slogger.Debug("Setting connection deadline")
	if err := conn.SetDeadline(time.Now().Add(s.resourceManager.GetConnectionTimeout())); err != nil {
		s.slogger.Debug("Failed to set connection deadline", "error", err)
		s.slogger.Error("Failed to set connection deadline", "error", err, "client_ip", clientIP, "session_id", sessionID)
	} else {
		s.slogger.Debug("Connection deadline set successfully")
	}

	// Create a new session with the current configuration and authentication
	// Use context.Background() to avoid inheriting the short-lived worker pool job context
	s.slogger.Debug("Creating new SMTP session", "client_ip", clientIP)
	session := NewSession(context.Background(), conn, s.config, s.authenticator)
	s.slogger.Debug("SMTP session created successfully")

	// Set the TLS manager from the server
	session.SetTLSManager(s.tlsManager)

	// Set the builtin plugins from the server
	session.SetBuiltinPlugins(s.builtinPlugins)

	// Set queue manager for message processing
	if s.queueManager != nil {
		session.SetQueueManager(s.queueManager)
	}

	// Set additional components
	session.SetResourceManager(s.resourceManager)
	// Note: Builtin plugins would be set through plugin manager if needed

	// Handle the SMTP session directly (circuit breaker disabled for now due to premature failures)
	s.slogger.Debug("Starting session.Handle()", "client_ip", clientIP)
	err := session.Handle()
	s.slogger.Debug("session.Handle() completed", "client_ip", clientIP)

	if err != nil {
		if err != io.EOF && err != context.DeadlineExceeded {
			s.slogger.Error("Session error", "error", err, "client_ip", clientIP, "session_id", sessionID)
		}
	}
}

// Close closes the server and all associated resources with graceful shutdown
func (s *Server) Close() error {
	var shutdownErr error

	s.shutdownOnce.Do(func() {
		s.slogger.Info("Initiating graceful server shutdown")
		s.running = false
		s.cancelRootContext()
		s.closeListener(&shutdownErr)
		s.stopWorkerPool(&shutdownErr)
		s.waitForGoroutines(&shutdownErr)
		s.closeResourceManagers(&shutdownErr)
		s.stopSubsystems(&shutdownErr)
		s.slogger.Info("Graceful server shutdown completed")
	})

	return shutdownErr
}

// cancelRootContext cancels the root context to propagate cancellation to all sessions.
func (s *Server) cancelRootContext() {
	if s.rootCancel != nil {
		s.slogger.Debug("Cancelling server root context to propagate shutdown signal")
		s.rootCancel()
	}
}

// closeListener stops accepting new connections.
func (s *Server) closeListener(shutdownErr *error) {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.slogger.Error("Error closing listener", "error", err)
			*shutdownErr = err
		}
	}
}

// stopWorkerPool gracefully stops the worker pool, ignoring context.Canceled.
func (s *Server) stopWorkerPool(shutdownErr *error) {
	if s.workerPool == nil {
		return
	}

	s.slogger.Info("Stopping worker pool")
	err := s.workerPool.Stop()
	if err == nil || err == context.Canceled {
		s.slogger.Info("Worker pool stopped successfully")
		return
	}

	s.slogger.Error("Error stopping worker pool", "error", err)
	if *shutdownErr == nil {
		*shutdownErr = err
	}
}

// waitForGoroutines waits for managed goroutines with the configured timeout.
func (s *Server) waitForGoroutines(shutdownErr *error) {
	timeout := s.config.Timeouts.ShutdownTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	s.slogger.Info("Waiting for goroutines to complete", "timeout", timeout)
	done := make(chan error, 1)
	go func() {
		done <- s.errGroup.Wait()
	}()

	select {
	case err := <-done:
		if err == nil || err == context.Canceled {
			s.slogger.Info("All goroutines stopped successfully")
		} else {
			s.slogger.Error("Error during goroutine shutdown", "error", err)
			if *shutdownErr == nil {
				*shutdownErr = err
			}
		}
	case <-time.After(timeout):
		s.slogger.Warn("Goroutine shutdown timeout after 30 seconds")
		if *shutdownErr == nil {
			*shutdownErr = fmt.Errorf("shutdown timeout")
		}
	}
}

// closeResourceManagers closes the resource manager.
func (s *Server) closeResourceManagers(shutdownErr *error) {
	if s.resourceManager != nil {
		s.resourceManager.Close()
	}
}

// stopSubsystems shuts down metrics, plugins, auth, TLS, and queue subsystems.
func (s *Server) stopSubsystems(shutdownErr *error) {
	// Close metrics server
	if s.metricsManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.metricsManager.Shutdown(ctx); err != nil {
			s.slogger.Error("Error shutting down metrics server", "error", err)
			if *shutdownErr == nil {
				*shutdownErr = err
			}
		}
	}

	// Close plugin manager
	if s.pluginManager != nil {
		if err := s.pluginManager.Close(); err != nil {
			s.slogger.Error("Error closing plugin manager", "error", err)
			if *shutdownErr == nil {
				*shutdownErr = err
			}
		}
	}

	// Close authenticator
	if s.authenticator != nil {
		if auth, ok := s.authenticator.(*SMTPAuthenticator); ok {
			if err := auth.Close(); err != nil {
				s.slogger.Error("Error closing authenticator", "error", err)
				if *shutdownErr == nil {
					*shutdownErr = err
				}
			}
		}
	}

	// Stop TLS manager
	if s.tlsManager != nil {
		if err := s.tlsManager.Stop(); err != nil {
			s.slogger.Error("Error stopping TLS manager", "error", err)
			if *shutdownErr == nil {
				*shutdownErr = err
			}
		}
	}

	// Stop queue processor
	if s.queueProcessor != nil {
		s.slogger.Info("Stopping queue processor")
		if err := s.queueProcessor.Stop(); err != nil {
			s.slogger.Error("Error stopping queue processor", "error", err)
			if *shutdownErr == nil {
				*shutdownErr = err
			}
		} else {
			s.slogger.Info("Queue processor stopped successfully")
		}
	}

	// Stop queue manager
	if s.queueManager != nil {
		s.slogger.Info("Stopping queue manager")
		s.queueManager.Stop()
	}
}

// Wait waits for all server goroutines to complete
func (s *Server) Wait() error {
	return s.errGroup.Wait()
}

// ... existing code ...
