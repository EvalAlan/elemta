package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/busybox42/elemta/internal/dkim"
	deliverymetrics "github.com/busybox42/elemta/internal/metrics"
	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/busybox42/elemta/internal/suppression"
	"github.com/google/uuid"
	"github.com/sony/gobreaker"
	"golang.org/x/sync/errgroup"
)

// Server represents an SMTP server
type Server struct {
	config          *Config
	listenerMu      sync.RWMutex
	listener        net.Listener
	running         atomic.Bool
	pluginManager   *plugin.Manager
	authenticator   Authenticator
	metricsManager  *MetricsManager    // Extracted metrics management
	queueManager    queue.QueueManager // Unified queue system
	queueProcessor  *queue.Processor   // Queue processor for message delivery
	tlsManager      TLSHandler
	resourceManager *ResourceManager // Resource management and rate limiting
	scannerManager  *ScannerManager  // Antivirus/antispam scanners used during DATA
	// scannerManager, accessControl and rblChecker are replaced by Reload while
	// the accept loop is reading them, so they are guarded. Everything else here
	// is fixed once startup finishes.
	pluginMu      sync.RWMutex
	accessControl *AccessControl // Allow/deny lists applied at connect and MAIL FROM
	rblChecker    *RBLChecker    // DNS blocklists consulted for the connecting address
	slogger       *slog.Logger   // Structured logger for resource management

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
// initPlugins initializes the plugin manager.
//
// This used to also construct plugin.BuiltinPlugins and hand it a hardcoded
// ClamAV and Rspamd address. Nothing ever asked it to scan a message — the
// SMTP session only checked it for nil, as a stand-in for "scanning is
// configured", and then ran a list of hardcoded substrings instead. Content
// scanning now goes through ScannerManager, which reads [antivirus] and
// [antispam] from the configuration rather than embedding infrastructure
// addresses in code.
func initPlugins(config *Config, slogger *slog.Logger) *plugin.Manager {
	var pluginManager *plugin.Manager

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
	} else {
		slogger.Info("Plugins disabled or not configured")
	}

	return pluginManager
}

type deliveryHandlerFactory func(host string, port int, maxPerDomain int, failedQueueRetentionHours int) queue.DeliveryHandler

type smtpDeliveryHandlerFactory func(failedQueueRetentionHours int) *queue.SMTPDeliveryHandler

type metricsStoreFactory func(addr string) (queue.MetricsRecorder, error)

var newDeliveryHandler deliveryHandlerFactory = func(host string, port int, maxPerDomain int, failedQueueRetentionHours int) queue.DeliveryHandler {
	return queue.NewLMTPDeliveryHandler(host, port, maxPerDomain, failedQueueRetentionHours)
}

var newSMTPDeliveryHandler smtpDeliveryHandlerFactory = func(failedQueueRetentionHours int) *queue.SMTPDeliveryHandler {
	return queue.NewSMTPDeliveryHandler(failedQueueRetentionHours)
}

var newQueueMetricsStore metricsStoreFactory = func(addr string) (queue.MetricsRecorder, error) {
	return deliverymetrics.NewValkeyStore(addr)
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
func initQueueSystem(config *Config, slogger *slog.Logger) (*queue.Manager, *queue.Processor, error) {
	// Validate and load DKIM before starting queue resources. This applies even
	// when queue processing is disabled and leaves no manager goroutine/backend
	// to clean up if DKIM configuration is invalid.
	dkimSigner, err := dkim.NewSigner(config.DKIM, slogger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize DKIM signer: %w", err)
	}

	queueManager, err := queue.NewManagerFromBackend(
		config.QueueDir,
		config.QueueBackend,
		queue.SQLiteConfig{
			Path:          config.QueueSQLite.Path,
			BusyTimeoutMS: config.QueueSQLite.BusyTimeoutMS,
			JournalMode:   config.QueueSQLite.JournalMode,
			Synchronous:   config.QueueSQLite.Synchronous,
		},
		queue.PostgresConfig{
			DSN:                    config.QueuePostgres.DSN,
			MaxOpenConns:           config.QueuePostgres.MaxOpenConns,
			MaxIdleConns:           config.QueuePostgres.MaxIdleConns,
			ConnMaxLifetimeSeconds: config.QueuePostgres.ConnMaxLifetimeSeconds,
		},
		queue.IndexedFSConfig{
			IndexPath:         config.QueueIndexedFS.IndexPath,
			ContentDir:        config.QueueIndexedFS.ContentDir,
			SyncMode:          config.QueueIndexedFS.SyncMode,
			RecoveryOnStartup: config.QueueIndexedFS.RecoveryOnStartup,
		},
		config.FailedQueueRetentionHours,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize queue backend: %w", err)
	}

	slogger.Info("Unified queue system initialized", "directory", config.QueueDir, "backend", queueManager.BackendType())

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

		deliveryMode := "lmtp"
		if config.Delivery != nil && strings.TrimSpace(config.Delivery.Mode) != "" {
			deliveryMode = strings.ToLower(strings.TrimSpace(config.Delivery.Mode))
		}

		var deliveryHandler queue.DeliveryHandler
		switch deliveryMode {
		case "lmtp":
			slogger.Info("Creating LMTP delivery handler", "host", deliveryHost, "port", deliveryPort, "max_per_domain", maxPerDomain)
			deliveryHandler = newDeliveryHandler(deliveryHost, deliveryPort, maxPerDomain, config.FailedQueueRetentionHours)
		case "smtp":
			slogger.Info("Creating SMTP delivery handler", "max_per_domain", maxPerDomain)
			deliveryHandler = newSMTPDeliveryHandler(config.FailedQueueRetentionHours)
		default:
			return nil, nil, fmt.Errorf("unsupported delivery mode %q (want smtp or lmtp)", deliveryMode)
		}

		// Attach the already-validated DKIM signer only to remote SMTP delivery.
		// Local LMTP delivery is intentionally not signed.
		if dkimSigner != nil {
			if smtpHandler, ok := deliveryHandler.(*queue.SMTPDeliveryHandler); ok {
				smtpHandler.SetDKIMSigner(dkimSigner)
				slogger.Info("DKIM outbound signing enabled")
			} else {
				slogger.Info("DKIM signing configured but active delivery handler is not the remote SMTP handler; signing will apply only on the remote SMTP path")
			}
		}

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

		queueProcessor = queue.NewProcessor(queueManager, processorConfig, deliveryHandler)

		// Set up bounce engine for DSN generation on permanent failures
		bounceEngine := NewBounceEngine(queueManager, config.Hostname, slogger)
		queueProcessor.SetBounceEngine(bounceEngine)

		slogger.Info("Queue processor initialized successfully")

		valkeyAddr := os.Getenv("VALKEY_ADDR")
		if valkeyAddr == "" {
			valkeyAddr = "elemta-valkey:6379"
		}
		metricsStore, err := newQueueMetricsStore(valkeyAddr)
		if err != nil {
			slogger.Warn("Failed to connect to Valkey for metrics", "error", err)
		} else {
			queueProcessor.SetMetricsRecorder(metricsStore)
			slogger.Info("Connected to Valkey for metrics", "address", valkeyAddr)
		}
	} else {
		slogger.Info("Queue processor disabled")
	}

	// The suppression list: addresses that permanently failed and must not be
	// mailed again. It lives beside the queue because both processes reach it
	// there — the SMTP node writes bounces, the web process reads them when a
	// campaign runs.
	//
	// A store that cannot be opened is a warning, not a failure. Delivery must
	// not depend on it; the cost is that bounces are not recorded until it is
	// fixed, which the log says plainly.
	if queueProcessor != nil && config.QueueDir != "" {
		suppressionPath := filepath.Join(config.QueueDir, "suppression.db")
		if store, err := suppression.Open(suppressionPath); err != nil {
			slogger.Warn("Suppression list unavailable; permanent failures will not be recorded",
				"path", suppressionPath, "error", err)
		} else {
			queueProcessor.SetSuppressionRecorder(suppression.NewRecorder(store, slogger))
			slogger.Info("Suppression list ready", "path", suppressionPath)
		}
	}

	return queueManager, queueProcessor, nil
}

// initResourceManager initializes resource limits and the resource manager.
func initResourceManager(config *Config, slogger *slog.Logger) (*ResourceManager, *ResourceLimits) {
	var resourceLimits *ResourceLimits
	var resourceManager *ResourceManager

	if config.Resources != nil {
		var memoryConfig *MemoryConfig
		if config.Memory != nil {
			memoryConfig = config.Memory
			// [memory] is operator-supplied and may be partially filled in.
			memoryConfig.ApplyDefaults()
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
		logMessageSizePolicy(config, memoryConfig, slogger)
		slogger.Info("Resource manager initialized with memory protection enabled")
	} else {
		resourceLimits = DefaultResourceLimits()
		resourceManager = NewResourceManager(resourceLimits, slogger)
		defaultMemory := DefaultMemoryConfig()
		memoryManager := NewMemoryManager(defaultMemory, slogger)
		resourceManager.SetMemoryManager(memoryManager)
		logMessageSizePolicy(config, defaultMemory, slogger)
		slogger.Info("Resource manager initialized with default memory protection")
	}

	return resourceManager, resourceLimits
}

// logMessageSizePolicy records the effective message size limit.
//
// This used to clamp max_size down to the per-connection memory limit, because
// DATA was accumulated on the heap and a session could not exceed it: the
// server would otherwise advertise a size in EHLO and then refuse the message
// part-way through, after the client had sent most of it.
//
// Message data is spooled to disk now, for both DATA and BDAT, so message size
// is bounded by max_size and by disk rather than by memory. The clamp is gone
// and max_size means what it says.
func logMessageSizePolicy(config *Config, memoryConfig *MemoryConfig, logger *slog.Logger) {
	logger.Info("Message size policy",
		"max_size", config.MaxSize,
		"per_connection_memory_limit", memoryConfig.PerConnectionMemoryLimit,
		"note", "message data is spooled to disk; max_size is not bounded by memory",
	)
}

// defaultConnectionWorkers is how many SMTP sessions run at once when
// [resources].max_concurrent is unset. Sessions are I/O bound — they spend
// their time waiting on the client and on content scanners — so this is sized
// well above the core count.
const defaultConnectionWorkers = 200

// initConcurrency initializes the context hierarchy and worker pool.
func initConcurrency(config *Config, slogger *slog.Logger, resourceLimits *ResourceLimits) (context.Context, context.CancelFunc, context.Context, context.CancelFunc, *errgroup.Group, context.Context, *WorkerPool) {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(rootCtx)
	errGroup, gctx := errgroup.WithContext(ctx)

	// Each accepted connection occupies a worker for the whole session, so this
	// is the cap on how many SMTP sessions can be in progress at once —
	// everything beyond it waits in the job queue. It was hardcoded to 20
	// while the shipped configuration allowed 1000 connections, so at any
	// meaningful concurrency most connections sat idle waiting for a worker
	// rather than being served.
	//
	// [resources].max_concurrent sizes it now. max_workers, which reads like
	// the right knob, has never been consumed by anything.
	poolSize := defaultConnectionWorkers
	if config != nil && config.Resources != nil && config.Resources.MaxConcurrent > 0 {
		poolSize = config.Resources.MaxConcurrent
	}
	slogger.Info("Connection worker pool sized",
		"workers", poolSize,
		"source", map[bool]string{true: "[resources].max_concurrent", false: "default"}[config != nil && config.Resources != nil && config.Resources.MaxConcurrent > 0],
	)

	workerPoolConfig := &WorkerPoolConfig{
		Size:               poolSize,
		JobBufferSize:      poolSize * 2,
		ResultBufferSize:   100,
		CircuitBreakerName: "smtp-connections",
		MaxRequests:        1000,
		Interval:           time.Minute,
		Timeout:            30 * time.Second,
		JobTimeout:         5 * time.Minute,
		ShutdownTimeout:    30 * time.Second,
		MaxGoroutines:      safeIntToInt32(resourceLimits.MaxGoroutines),
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

func prepareServerConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Refuse to start on a malformed trusted_networks entry rather than guess.
	// Dropping an entry would start refusing mail from a network the operator
	// meant to allow; falling back to the defaults would widen trust silently.
	if err := config.ValidateTrustedNetworks(); err != nil {
		return err
	}

	if config.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname not provided in config and could not be determined: %w", err)
		}
		config.Hostname = hostname
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":2525" // Default SMTP port (non-privileged)
	}

	return nil
}

func logServerConfigSummary(config *Config, slogger *slog.Logger) {
	slogger.Info("Initializing SMTP server",
		"event_type", "system",
		"hostname", config.Hostname)

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
}

// NewServer creates a new SMTP server
func NewServer(config *Config) (*Server, error) {
	if err := prepareServerConfig(config); err != nil {
		return nil, err
	}

	slogger := slog.Default().With(
		"component", "smtp-server",
		"hostname", config.Hostname,
	)
	logServerConfigSummary(config, slogger)

	pluginManager := initPlugins(config, slogger)
	authenticator, err := initAuthenticator(config, slogger)
	if err != nil {
		return nil, err
	}

	metrics := GetMetrics()
	slogger.Info("Metrics system initialized")
	metricsManager := NewMetricsManager(config, slogger, metrics)
	queueManager, queueProcessor, err := initQueueSystem(config, slogger)
	if err != nil {
		return nil, err
	}
	// Feed queue-size gauges from the queue manager's authoritative stats, and
	// fan delivery events out to Prometheus alongside any Valkey recorder.
	metricsManager.SetQueueManager(queueManager)
	if queueProcessor != nil {
		queueProcessor.AddMetricsRecorder(metrics)
	}
	resourceManager, resourceLimits := initResourceManager(config, slogger)
	rootCtx, rootCancel, _, cancel, errGroup, gctx, workerPool := initConcurrency(config, slogger, resourceLimits)

	server := &Server{
		config:          config,
		pluginManager:   pluginManager,
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

	// The scanner manager used to be initialised and then dropped: the local
	// variable went out of scope and nothing ever scanned a message with it.
	// ClamAV and Rspamd connected at startup and were never asked anything.
	scannerManager := NewScannerManager(config, server)
	if err := scannerManager.Initialize(context.Background()); err != nil {
		slogger.Warn("Error initializing scanner manager",
			"error", err,
			"component", "scanner-manager",
		)
	}
	server.scannerManager = scannerManager

	// Access control lists. A malformed entry stops startup rather than being
	// dropped: a deny rule that silently fails to load leaves the operator
	// believing a network is blocked when it is not.
	accessControl, err := NewAccessControl(config.AccessControl, slogger)
	if err != nil {
		return nil, fmt.Errorf("access control configuration: %w", err)
	}
	server.accessControl = accessControl
	if accessControl.Enabled() {
		slogger.Info("Access control enabled",
			"allow_ips", len(config.AccessControl.AllowIPs),
			"deny_ips", len(config.AccessControl.DenyIPs),
			"allow_domains", len(config.AccessControl.AllowDomains),
			"deny_domains", len(config.AccessControl.DenyDomains),
		)
	}

	// DNS blocklists, on the same terms: a zone that fails to load is a filter
	// the operator thinks is running.
	rblChecker, err := NewRBLChecker(config.RBL, slogger)
	if err != nil {
		return nil, fmt.Errorf("rbl configuration: %w", err)
	}
	server.rblChecker = rblChecker
	if rblChecker.Enabled() {
		slogger.Info("DNS blocklists enabled",
			"zones", config.RBL.Zones,
			"reject", rblChecker.Reject(),
		)
		if !rblChecker.Reject() {
			slogger.Info("Blocklist hits will be marked with an X-RBL-Listed header, not refused")
		}
	}

	// Say plainly when nothing will be scanned. Silence here previously looked
	// identical to working scanners.
	if !scannerManager.HasAntivirusScanners() {
		slogger.Warn("No antivirus scanner is available; messages will be delivered unscanned for viruses")
	}
	if !scannerManager.HasAntispamScanners() {
		slogger.Warn("No antispam scanner is available; messages will be delivered unscored for spam")
	}

	return server, nil
}

func (s *Server) setListener(listener net.Listener) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	s.listener = listener
}

func (s *Server) getListener() net.Listener {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()
	return s.listener
}

func (s *Server) isRunning() bool {
	return s.running.Load()
}

// Addr returns the server's listen address.
func (s *Server) Addr() net.Addr {
	listener := s.getListener()
	if listener != nil {
		return listener.Addr()
	}
	return nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	if s.isRunning() {
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
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.setListener(listener)
	s.running.Store(true)
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

	// Create subdirectories for different queue types with secure permissions.
	// "spool" holds in-flight DATA for messages larger than the spool
	// threshold, on the same filesystem as the queue.
	queueTypes := []string{"active", "deferred", "held", "failed", "data", "tmp", "quarantine", "spool"}

	for _, qType := range queueTypes {
		qDir := filepath.Join(s.config.QueueDir, qType)
		if err := os.MkdirAll(qDir, 0700); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %w", qType, err)
		}
		s.slogger.Info("Created secure queue directory", "path", qDir, "mode", "0700")
	}

	// Sessions remove their own spool files, but a crash or kill mid-DATA
	// leaves them behind. Without this sweep they accumulate across restarts
	// until they fill the queue filesystem.
	spoolDir := filepath.Join(s.config.QueueDir, "spool")
	if removed, err := SweepOrphanedSpools(spoolDir); err != nil {
		s.slogger.Warn("Failed to sweep orphaned message spools", "path", spoolDir, "error", err)
	} else if removed > 0 {
		s.slogger.Info("Removed orphaned message spools from a previous run",
			"path", spoolDir, "count", removed)
	}

	return nil
}

// updateQueueMetricsWithRetry periodically updates queue size metrics with retry on failure
func (s *Server) updateQueueMetricsWithRetry() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if !s.isRunning() {
				return
			}

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
		}
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

		listener := s.getListener()
		if listener == nil {
			if s.isRunning() {
				s.slogger.Warn("Listener is nil while server is marked running")
			}
			return nil
		}

		// Set a short timeout on accept to allow periodic context checking
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				s.slogger.Error("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := listener.Accept()
		if err != nil {
			// Check if it's a timeout error (expected)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			if s.isRunning() {
				s.slogger.Error("Failed to accept connection", "error", err)
			}
			continue
		}

		s.slogger.Debug("Connection accepted", "remote_addr", conn.RemoteAddr().String())

		// Reset deadline after successful accept
		if tcpListener, ok := listener.(*net.TCPListener); ok {
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

	// Denied peers are refused before a session exists. Answering 554 and
	// closing costs one round trip and no session state, which is the point of
	// blocking an address rather than filtering its mail later.
	if decision := s.currentAccessControl().CheckPeer(conn.RemoteAddr()); decision.Denied {
		s.slogger.WarnContext(ctx, "Connection refused by access control",
			"event_type", "rejection",
			"client_ip", clientIP,
			"rule", decision.Rule,
		)
		_, _ = conn.Write([]byte("554 5.7.1 " + decision.Reason + "\r\n"))
		_ = conn.Close()
		return
	}

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

	// Set the content scanners from the server
	// Read once, so a reload landing between these calls cannot give one
	// session a mixture of the old policy and the new one.
	s.pluginMu.RLock()
	scanners, accessControl, rblChecker := s.scannerManager, s.accessControl, s.rblChecker
	s.pluginMu.RUnlock()
	session.SetScannerManager(scanners)
	session.SetAccessControl(accessControl)
	session.SetRBLChecker(rblChecker)

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
		s.running.Store(false)
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
	listener := s.getListener()
	if listener == nil {
		return
	}

	if err := listener.Close(); err != nil {
		s.slogger.Error("Error closing listener", "error", err)
		*shutdownErr = err
	}
	s.setListener(nil)
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
