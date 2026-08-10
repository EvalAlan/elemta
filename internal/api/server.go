package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/busybox42/elemta/internal/auth"
	"github.com/busybox42/elemta/internal/campaign"
	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/metrics"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/busybox42/elemta/internal/runtimepaths"
	"github.com/gorilla/mux"
)

// MainConfig represents the configuration data needed by the API
type MainConfig struct {
	Hostname                  string      `json:"hostname"`
	ListenAddr                string      `json:"listen_addr"`
	QueueDir                  string      `json:"queue_dir"`
	QueueBackend              string      `json:"queue_backend"`
	QueueSQLitePath           string      `json:"queue_sqlite_path"`
	QueueSQLiteBusyTimeoutMS  int         `json:"queue_sqlite_busy_timeout_ms"`
	QueueSQLiteJournalMode    string      `json:"queue_sqlite_journal_mode"`
	QueueSQLiteSynchronous    string      `json:"queue_sqlite_synchronous"`
	QueuePostgresDSN          string      `json:"queue_postgres_dsn"`
	QueuePostgresMaxOpenConns int         `json:"queue_postgres_max_open_conns"`
	QueuePostgresMaxIdleConns int         `json:"queue_postgres_max_idle_conns"`
	QueuePostgresConnMaxLifeS int         `json:"queue_postgres_conn_max_lifetime_seconds"`
	QueueIndexedFSIndexPath   string      `json:"queue_indexedfs_index_path"`
	QueueIndexedFSContentDir  string      `json:"queue_indexedfs_content_dir"`
	QueueIndexedFSSyncMode    string      `json:"queue_indexedfs_sync_mode"`
	QueueIndexedFSRecovery    bool        `json:"queue_indexedfs_recovery_on_startup"`
	MaxSize                   int64       `json:"max_size"`
	MaxWorkers                int         `json:"max_workers"`
	MaxRetries                int         `json:"max_retries"`
	MaxQueueTime              int         `json:"max_queue_time"`
	RetrySchedule             []int       `json:"retry_schedule"`
	SessionTimeout            string      `json:"session_timeout"`
	LocalDomains              []string    `json:"local_domains"`
	FailedQueueRetentionHours int         `json:"failed_queue_retention_hours"`
	AuthAllowDeprecatedSHA1   *bool       `json:"auth_allow_deprecated_sha1,omitempty"`
	RateLimiterPluginConfig   interface{} `json:"rate_limiter"`
	TLS                       interface{} `json:"tls"`
	API                       interface{} `json:"api"`

	// Scanner configuration, mirrored here because internal/api cannot import
	// internal/smtp (smtp already imports api for the throughput counters).
	Antivirus *ScannerStatus `json:"antivirus,omitempty"`
	Antispam  *ScannerStatus `json:"antispam,omitempty"`

	// AccessControl is the allow/deny plugin's configuration, mirrored for the
	// same reason.
	AccessControl *AccessControlStatus `json:"access_control,omitempty"`

	// MassMailer configures the campaign sender.
	MassMailer *MassMailerStatus `json:"mass_mailer,omitempty"`

	// RBL is the DNS blocklist plugin's configuration.
	RBL *RBLStatus `json:"rbl,omitempty"`
}

// RBLStatus is the API's view of the DNS blocklists.
type RBLStatus struct {
	Enabled   bool     `json:"enabled"`
	Zones     []string `json:"zones"`
	Reject    bool     `json:"reject"`
	Timeout   int      `json:"timeout"`
	SkipIPs   []string `json:"skip_ips"`
	CacheTTL  int      `json:"cache_ttl"`
	CacheSize int      `json:"cache_size"`
}

// AccessControlStatus is the API's view of the allow/deny lists.
type AccessControlStatus struct {
	Enabled      bool     `json:"enabled"`
	AllowIPs     []string `json:"allow_ips"`
	DenyIPs      []string `json:"deny_ips"`
	AllowDomains []string `json:"allow_domains"`
	DenyDomains  []string `json:"deny_domains"`
}

// MassMailerStatus is the API's view of the mass mailer plugin.
type MassMailerStatus struct {
	Enabled              bool `json:"enabled"`
	DefaultRatePerMinute int  `json:"default_rate_per_minute"`
	MaxRecipients        int  `json:"max_recipients"`
}

// ScannerStatus is the API's view of a content scanner's configuration.
type ScannerStatus struct {
	Enabled         bool    `json:"enabled"`
	Address         string  `json:"address"`
	Timeout         int     `json:"timeout"`
	ScanLimit       int64   `json:"scan_limit"`
	Threshold       float64 `json:"threshold,omitempty"`
	RejectOnSpam    bool    `json:"reject_on_spam,omitempty"`
	RejectOnFailure bool    `json:"reject_on_failure,omitempty"`
}

// Server represents an API server for Elemta
type Server struct {
	config         *Config
	mainConfig     *MainConfig // Main application configuration
	configPath     string      // Path to config file for persistence
	httpServer     *http.Server
	listener       net.Listener
	restarting     atomic.Bool
	queueMgr       *queue.Manager
	listenAddr     string
	webRoot        string
	authSystem     *auth.Auth
	rbac           *auth.RBAC
	apiKeyManager  *auth.APIKeyManager
	sessionManager *auth.SessionManager
	authMiddleware *AuthMiddleware
	rateLimiter    *RateLimitMiddleware
	corsMiddleware *CORSMiddleware
	metricsStore   MetricsStore

	// Mass mailer. Guarded because the plugin toggle builds and tears these
	// down while requests are in flight, unlike the rest of the server's
	// components, which are fixed once startup finishes.
	massMailerMu   sync.RWMutex
	campaigns      *campaign.Store
	campaignRunner *campaign.Runner

	lifecycleMu     sync.Mutex
	lifecycleState  serverLifecycleState
	ready           chan struct{}
	stopDone        chan struct{}
	stopErr         error
	listenerFactory func() (net.Listener, error)
}

type serverLifecycleState uint8

const (
	serverStateNew serverLifecycleState = iota
	serverStateStarting
	serverStateRunning
	serverStateStopping
	serverStateStopped
)

var (
	ErrServerAlreadyStarted = errors.New("api server already started")
	ErrServerStopped        = errors.New("api server stopped during startup")
)

const inheritedHTTPFDEnv = "ELEMTA_INHERITED_HTTP_FD"

// MetricsStore interface for delivery metrics
type MetricsStore interface {
	GetMetrics(ctx context.Context) (*DeliveryMetricsData, error)
	GetHourlyStats(ctx context.Context) ([]HourlyStatsData, error)
	GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error)
}

// DeliveryMetricsData holds delivery statistics
type DeliveryMetricsData struct {
	TotalDelivered int64     `json:"total_delivered"`
	TotalFailed    int64     `json:"total_failed"`
	TotalDeferred  int64     `json:"total_deferred"`
	TotalReceived  int64     `json:"total_received"`
	LastUpdated    time.Time `json:"last_updated"`
}

// HourlyStatsData holds hourly delivery counts
type HourlyStatsData struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// Config represents API server configuration
type Config struct {
	Enabled     bool            `toml:"enabled" json:"enabled"`
	ListenAddr  string          `toml:"listen_addr" json:"listen_addr"`
	WebRoot     string          `toml:"web_root" json:"web_root"`
	AuthEnabled bool            `toml:"auth_enabled" json:"auth_enabled"`
	AuthFile    string          `toml:"auth_file" json:"auth_file"`
	ValkeyAddr  string          `toml:"valkey_addr" json:"valkey_addr"`
	RateLimit   RateLimitConfig `toml:"rate_limit" json:"rate_limit"`
	CORS        CORSConfig      `toml:"cors" json:"cors"`
}

// NewServer creates a new API server
func NewServer(config *Config, mainConfig *MainConfig, queueDir string, failedQueueRetentionHours int, configPath string) (*Server, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("API server disabled in configuration")
	}

	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8025"
	}

	webRoot := config.WebRoot
	if webRoot == "" {
		webRoot = "./web/static"
	}

	queueMgr, err := newQueueManagerForAPI(mainConfig, queueDir, failedQueueRetentionHours)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize queue manager: %w", err)
	}

	server := &Server{
		config:     config,
		mainConfig: mainConfig,
		configPath: configPath,
		queueMgr:   queueMgr,
		listenAddr: listenAddr,
		webRoot:    webRoot,
	}

	// Initialize metrics store (Valkey)
	valkeyAddr := config.ValkeyAddr
	if valkeyAddr == "" {
		// Try environment variable or default
		valkeyAddr = os.Getenv("VALKEY_ADDR")
		if valkeyAddr == "" {
			valkeyAddr = "elemta-valkey:6379"
		}
	}
	metricsStore, err := metrics.NewValkeyStore(valkeyAddr)
	if err != nil {
		log.Printf("Warning: Failed to connect to Valkey for metrics: %v", err)
		// Continue without metrics - not fatal
	} else {
		server.metricsStore = &valkeyMetricsAdapter{store: metricsStore}
		// #nosec G706 -- operational startup log; value is sanitized before logging
		log.Printf("Connected to Valkey for metrics at %s", sanitizeForLog(valkeyAddr))
	}

	// Initialize authentication if enabled
	if config.AuthEnabled {
		if err := server.initializeAuth(); err != nil {
			return nil, fmt.Errorf("failed to initialize authentication: %w", err)
		}
	}

	// Mass mailer. Only built when enabled: without a store and runner the
	// campaign endpoints report the feature as unavailable rather than half
	// working.
	if mainConfig != nil && mainConfig.MassMailer != nil && mainConfig.MassMailer.Enabled {
		if err := server.setMassMailerEnabled(true); err != nil {
			return nil, fmt.Errorf("failed to start the mass mailer: %w", err)
		}
	}

	// Initialize rate limiter
	server.rateLimiter = NewRateLimitMiddleware(config.RateLimit)

	// Initialize CORS middleware
	server.corsMiddleware = NewCORSMiddleware(config.CORS)

	return server, nil
}

func newQueueManagerForAPI(mainConfig *MainConfig, queueDir string, failedQueueRetentionHours int) (*queue.Manager, error) {
	backend := "file"
	sqliteCfg := queue.SQLiteConfig{BusyTimeoutMS: 5000, JournalMode: "WAL", Synchronous: "NORMAL"}
	postgresCfg := queue.PostgresConfig{MaxOpenConns: 20, MaxIdleConns: 10, ConnMaxLifetimeSeconds: 1800}
	indexedFSCfg := queue.IndexedFSConfig{SyncMode: "normal", RecoveryOnStartup: true}

	if mainConfig != nil {
		if b := strings.TrimSpace(strings.ToLower(mainConfig.QueueBackend)); b != "" {
			backend = b
		}
		sqliteCfg.Path = strings.TrimSpace(mainConfig.QueueSQLitePath)
		if mainConfig.QueueSQLiteBusyTimeoutMS > 0 {
			sqliteCfg.BusyTimeoutMS = mainConfig.QueueSQLiteBusyTimeoutMS
		}
		if v := strings.TrimSpace(mainConfig.QueueSQLiteJournalMode); v != "" {
			sqliteCfg.JournalMode = v
		}
		if v := strings.TrimSpace(mainConfig.QueueSQLiteSynchronous); v != "" {
			sqliteCfg.Synchronous = v
		}
		postgresCfg.DSN = strings.TrimSpace(mainConfig.QueuePostgresDSN)
		if mainConfig.QueuePostgresMaxOpenConns > 0 {
			postgresCfg.MaxOpenConns = mainConfig.QueuePostgresMaxOpenConns
		}
		if mainConfig.QueuePostgresMaxIdleConns > 0 {
			postgresCfg.MaxIdleConns = mainConfig.QueuePostgresMaxIdleConns
		}
		if mainConfig.QueuePostgresConnMaxLifeS > 0 {
			postgresCfg.ConnMaxLifetimeSeconds = mainConfig.QueuePostgresConnMaxLifeS
		}
		if v := strings.TrimSpace(mainConfig.QueueIndexedFSIndexPath); v != "" {
			indexedFSCfg.IndexPath = v
		}
		if v := strings.TrimSpace(mainConfig.QueueIndexedFSContentDir); v != "" {
			indexedFSCfg.ContentDir = v
		}
		if v := strings.TrimSpace(mainConfig.QueueIndexedFSSyncMode); v != "" {
			indexedFSCfg.SyncMode = v
		}
		indexedFSCfg.RecoveryOnStartup = mainConfig.QueueIndexedFSRecovery
	}

	return queue.NewManagerFromBackend(queueDir, backend, sqliteCfg, postgresCfg, indexedFSCfg, failedQueueRetentionHours)
}

// valkeyMetricsAdapter adapts ValkeyStore to MetricsStore interface
type valkeyMetricsAdapter struct {
	store *metrics.ValkeyStore
}

func (a *valkeyMetricsAdapter) GetMetrics(ctx context.Context) (*DeliveryMetricsData, error) {
	m, err := a.store.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	return &DeliveryMetricsData{
		TotalDelivered: m.TotalDelivered,
		TotalFailed:    m.TotalFailed,
		TotalDeferred:  m.TotalDeferred,
		TotalReceived:  m.TotalReceived,
		LastUpdated:    m.LastUpdated,
	}, nil
}

func (a *valkeyMetricsAdapter) GetHourlyStats(ctx context.Context) ([]HourlyStatsData, error) {
	stats, err := a.store.GetHourlyStats(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]HourlyStatsData, len(stats))
	for i, s := range stats {
		result[i] = HourlyStatsData{
			Hour:      s.Hour,
			Delivered: s.Delivered,
			Failed:    s.Failed,
			Deferred:  s.Deferred,
		}
	}
	return result, nil
}

func (a *valkeyMetricsAdapter) GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error) {
	return a.store.GetRecentErrors(ctx, limit)
}

// initializeAuth initializes the authentication system
func (s *Server) initializeAuth() error {
	// Create logger for auth initialization
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "api-auth",
	)

	// Use config auth file if specified, otherwise try environment, then fallback to default
	var authSystem *auth.Auth
	var err error

	authFile := s.config.AuthFile
	if authFile == "" {
		authFile = runtimepaths.Detect().AuthUsersFile
	}

	// If an explicit auth file was provided, honor it before consulting environment defaults.
	// This is especially important for container/web deployments that pass --auth-file
	// while building without CGO (where the default SQLite path is unusable).
	if authFile != "" {
		authSystem, err = auth.NewWithFile(authFile)
		if err != nil {
			return fmt.Errorf("failed to initialize file-based authentication from %s: %w", authFile, err)
		}
		logger.Info("Authentication initialized using explicit file-based datasource",
			"datasource", authFile,
		)
	} else {
		// Try environment first
		authSystem, err = auth.NewFromEnv()
		if err != nil {
			// Fallback to file-based authentication
			logger.Warn("Failed to initialize auth from environment, falling back to file-based auth",
				"error", err,
			)
			authSystem, err = auth.NewWithFile(authFile)
			if err != nil {
				return fmt.Errorf("failed to initialize file-based authentication from %s: %w", authFile, err)
			}
			logger.Info("Authentication initialized using file-based datasource",
				"datasource", authFile,
			)
		} else {
			logger.Info("Authentication initialized from environment configuration")
		}
	}

	if s.mainConfig != nil && s.mainConfig.AuthAllowDeprecatedSHA1 != nil {
		authSystem.SetAllowDeprecatedSHA1(*s.mainConfig.AuthAllowDeprecatedSHA1)
		logger.Info("Authentication legacy hash policy overridden by runtime config",
			"allow_deprecated_sha1", authSystem.AllowDeprecatedSHA1(),
		)
	}

	// Initialize RBAC
	rbac := auth.NewRBAC(authSystem)

	// Initialize API key manager
	apiKeyManager := auth.NewAPIKeyManager(rbac)

	// Initialize session manager
	sessionConfig := auth.SessionConfig{
		MaxAge:       24 * time.Hour,
		CookieName:   "elemta_session",
		SecureCookie: true, // Always require secure cookies
		HTTPOnly:     true,
		SameSite:     "lax",
	}
	sessionManager := auth.NewSessionManager(sessionConfig)

	// Create authentication middleware
	authMiddleware := NewAuthMiddleware(rbac, apiKeyManager, sessionManager)

	s.authSystem = authSystem
	s.rbac = rbac
	s.apiKeyManager = apiKeyManager
	s.sessionManager = sessionManager
	s.authMiddleware = authMiddleware

	return nil
}

// Start starts the API server
func (s *Server) Start() error {
	s.lifecycleMu.Lock()
	s.initLifecycleLocked()
	if s.lifecycleState != serverStateNew {
		err := ErrServerAlreadyStarted
		if s.lifecycleState == serverStateStopping || s.lifecycleState == serverStateStopped {
			err = ErrServerStopped
		}
		s.lifecycleMu.Unlock()
		return err
	}
	s.lifecycleState = serverStateStarting
	s.lifecycleMu.Unlock()

	r := mux.NewRouter()

	// Apply CORS middleware first - before any other middleware
	if s.corsMiddleware != nil {
		r.Use(s.corsMiddleware.Handler)
	}

	// Apply other middleware
	r.Use(LoggingMiddleware)

	// Apply rate limiting middleware
	if s.rateLimiter != nil {
		r.Use(s.rateLimiter.Limit)
	}

	if s.authMiddleware != nil {
		// Only apply auth-related middleware for protected routes
		log.Printf("API Server: Auth middleware available")
	}

	// Public routes (must be registered before protected routes)
	r.HandleFunc("/login", s.handleLoginPage).Methods("GET")
	r.HandleFunc("/logo.png", s.handleLogo).Methods("GET")

	// Serve static files for the web interface (protected)
	if s.authMiddleware != nil {
		// Protected routes
		r.PathPrefix("/static/").Handler(s.authMiddleware.RequireAuth(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot)))))
		// Serve the main dashboard at root (requires authentication)
		r.Handle("/", s.authMiddleware.RequireAuth(http.HandlerFunc(s.handleDashboard))).Methods("GET")
		r.Handle("/dashboard", s.authMiddleware.RequireAuth(http.HandlerFunc(s.handleDashboard))).Methods("GET")
	} else {
		// Fallback to no auth if auth system is not configured
		r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot))))
		r.HandleFunc("/", s.handleDashboard).Methods("GET")
		r.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
	}

	// pprof debugging routes (require auth when configured)
	if s.authMiddleware != nil {
		r.Handle("/debug/pprof/", s.authMiddleware.RequireAuth(http.HandlerFunc(pprof.Index)))
		r.Handle("/debug/pprof/cmdline", s.authMiddleware.RequireAuth(http.HandlerFunc(pprof.Cmdline)))
		r.Handle("/debug/pprof/profile", s.authMiddleware.RequireAuth(http.HandlerFunc(pprof.Profile)))
		r.Handle("/debug/pprof/symbol", s.authMiddleware.RequireAuth(http.HandlerFunc(pprof.Symbol)))
		r.Handle("/debug/pprof/trace", s.authMiddleware.RequireAuth(http.HandlerFunc(pprof.Trace)))
		r.Handle("/debug/pprof/goroutine", s.authMiddleware.RequireAuth(pprof.Handler("goroutine")))
		r.Handle("/debug/pprof/heap", s.authMiddleware.RequireAuth(pprof.Handler("heap")))
		r.Handle("/debug/pprof/threadcreate", s.authMiddleware.RequireAuth(pprof.Handler("threadcreate")))
		r.Handle("/debug/pprof/block", s.authMiddleware.RequireAuth(pprof.Handler("block")))
		r.Handle("/debug/pprof/mutex", s.authMiddleware.RequireAuth(pprof.Handler("mutex")))
	} else {
		r.HandleFunc("/debug/pprof/", pprof.Index)
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
		r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
		r.Handle("/debug/pprof/block", pprof.Handler("block"))
		r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	}

	// Authentication routes (if auth is enabled)
	if s.authMiddleware != nil {
		auth := r.PathPrefix("/auth").Subrouter()
		auth.HandleFunc("/login", s.handleLogin).Methods("POST")
		auth.HandleFunc("/logout", s.handleLogout).Methods("POST", "GET")
		auth.HandleFunc("/me", s.handleMe).Methods("GET")

		// API key management routes (require authentication)
		apiKeys := r.PathPrefix("/auth/apikeys").Subrouter()
		apiKeys.Use(s.authMiddleware.RequireAuth)
		apiKeys.HandleFunc("", s.handleListAPIKeys).Methods("GET")
		apiKeys.HandleFunc("", s.handleCreateAPIKey).Methods("POST")
		apiKeys.HandleFunc("/{id}", s.handleGetAPIKey).Methods("GET")
		apiKeys.HandleFunc("/{id}", s.handleUpdateAPIKey).Methods("PUT")
		apiKeys.HandleFunc("/{id}", s.handleDeleteAPIKey).Methods("DELETE")
		apiKeys.HandleFunc("/{id}/revoke", s.handleRevokeAPIKey).Methods("POST")
	}

	// API routes
	api := r.PathPrefix("/api").Subrouter()

	// Logging management endpoints (no auth required for GET, auth required for SET)
	api.HandleFunc("/logging/level", s.HandleGetLogLevel).Methods("GET")

	// Protected logging endpoints (require auth)
	if s.authMiddleware != nil {
		loggingProtected := api.PathPrefix("/logging").Subrouter()
		loggingProtected.Use(s.authMiddleware.RequireAuth)
		loggingProtected.HandleFunc("/level", s.HandleSetLogLevel).Methods("POST", "PUT")
	} else {
		// If no auth middleware, still allow setting log level (development mode)
		api.HandleFunc("/logging/level", s.HandleSetLogLevel).Methods("POST", "PUT")
	}

	// Read-only queue operations expose message metadata/content and require auth
	// whenever the web UI has authentication enabled.
	api.Handle("/queue/stats", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetQueueStats))).Methods("GET")
	api.Handle("/queue/observability", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetQueueObservability))).Methods("GET")
	api.Handle("/queue/storage", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetQueueStorage))).Methods("GET")
	api.Handle("/queue/message/{id}", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetMessage))).Methods("GET")
	api.Handle("/queue/{type}", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetQueue))).Methods("GET")
	api.Handle("/queue", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetAllQueues))).Methods("GET")

	// Logs can contain sender, recipient, hostname, and auth-adjacent context.
	api.Handle("/logs", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetLogs))).Methods("GET")
	api.Handle("/logs/messages", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetMessageLogs))).Methods("GET")

	// Health stays public for probes; detailed delivery stats follow dashboard auth.
	api.HandleFunc("/health", s.handleHealthStats).Methods("GET")
	api.Handle("/stats/delivery", s.requireAuthIfConfigured(http.HandlerFunc(s.handleDeliveryStats))).Methods("GET")

	// Configuration read endpoints expose operational topology.
	api.Handle("/config", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetConfig))).Methods("GET")
	// Mass mailer campaigns. Composing and sending are separate: a campaign is
	// created, checked, then started, so nothing goes out because a draft was
	// saved.
	if s.authMiddleware != nil {
		manage := s.authMiddleware.RequirePermission(auth.PermissionQueueManage)
		api.Handle("/campaigns", manage(http.HandlerFunc(s.handleListCampaigns))).Methods("GET")
		api.Handle("/campaigns", manage(http.HandlerFunc(s.handleCreateCampaign))).Methods("POST")
		api.Handle("/campaigns/{id}", manage(http.HandlerFunc(s.handleGetCampaign))).Methods("GET")
		api.Handle("/campaigns/{id}", manage(http.HandlerFunc(s.handleUpdateCampaign))).Methods("PUT")
		api.Handle("/campaigns/{id}", manage(http.HandlerFunc(s.handleDeleteCampaign))).Methods("DELETE")
		api.Handle("/campaigns/{id}/recipients", manage(http.HandlerFunc(s.handleGetCampaignRecipients))).Methods("GET")
		api.Handle("/campaigns/{id}/{action}", manage(http.HandlerFunc(s.handleCampaignAction))).Methods("POST")
	} else {
		api.HandleFunc("/campaigns", s.handleListCampaigns).Methods("GET")
		api.HandleFunc("/campaigns", s.handleCreateCampaign).Methods("POST")
		api.HandleFunc("/campaigns/{id}", s.handleGetCampaign).Methods("GET")
		api.HandleFunc("/campaigns/{id}", s.handleUpdateCampaign).Methods("PUT")
		api.HandleFunc("/campaigns/{id}", s.handleDeleteCampaign).Methods("DELETE")
		api.HandleFunc("/campaigns/{id}/recipients", s.handleGetCampaignRecipients).Methods("GET")
		api.HandleFunc("/campaigns/{id}/{action}", s.handleCampaignAction).Methods("POST")
	}

	// Message tracing. Read-only and derived from the logs, but a trace names
	// senders, recipients and subjects, so it follows the same auth as the rest
	// of the dashboard rather than being open.
	api.Handle("/messages/search", s.requireAuthIfConfigured(http.HandlerFunc(s.handleSearchMessages))).Methods("GET")
	api.Handle("/messages/{id}/trace", s.requireAuthIfConfigured(http.HandlerFunc(s.handleTraceMessage))).Methods("GET")

	api.Handle("/config/plugins", s.requireAuthIfConfigured(http.HandlerFunc(s.handleGetPlugins))).Methods("GET")

	// Configuration management endpoints (write operations require auth)
	if s.authMiddleware != nil {
		configHandler := s.authMiddleware.RequirePermission(auth.PermissionSystemConfig)(http.HandlerFunc(s.handleUpdateConfig))
		api.Handle("/config", configHandler).Methods("PUT")
		pluginHandler := s.authMiddleware.RequirePermission(auth.PermissionSystemConfig)(http.HandlerFunc(s.handleUpdatePlugin))
		api.Handle("/config/plugins/{plugin}", pluginHandler).Methods("PUT")
		restartHandler := s.authMiddleware.RequirePermission(auth.PermissionSystemAdmin)(http.HandlerFunc(s.handleServerRestart))
		api.Handle("/config/restart", restartHandler).Methods("POST")
	} else {
		// If auth is disabled, allow config operations without authentication (development mode)
		api.HandleFunc("/config", s.handleUpdateConfig).Methods("PUT")
		api.HandleFunc("/config/plugins/{plugin}", s.handleUpdatePlugin).Methods("PUT")
		api.HandleFunc("/config/restart", s.handleServerRestart).Methods("POST")
	}

	// Destructive operations require authentication (only if auth is enabled)
	if s.authMiddleware != nil {
		// Message deletion requires queue:delete permission
		deleteHandler := s.authMiddleware.RequirePermission(auth.PermissionQueueDelete)(http.HandlerFunc(s.handleDeleteMessage))
		api.Handle("/queue/message/{id}", deleteHandler).Methods("DELETE")
		// Queue management actions require queue:manage permission
		manageHandler := s.authMiddleware.RequirePermission(auth.PermissionQueueManage)
		api.Handle("/queue/message/{id}/requeue", manageHandler(http.HandlerFunc(s.handleRequeueMessage))).Methods("POST")
		api.Handle("/queue/message/{id}/hold", manageHandler(http.HandlerFunc(s.handleHoldMessage))).Methods("POST")
		api.Handle("/queue/message/{id}/release-claim", manageHandler(http.HandlerFunc(s.handleReleaseMessageClaim))).Methods("POST")
		// Bulk retry is a management action, not a destructive one.
		api.Handle("/queue/{type}/retry", manageHandler(http.HandlerFunc(s.handleRetryQueue))).Methods("POST")
		// Queue flushing deletes messages, so it requires queue:flush permission.
		flushHandler := s.authMiddleware.RequirePermission(auth.PermissionQueueFlush)(http.HandlerFunc(s.handleFlushQueue))
		api.Handle("/queue/{type}/flush", flushHandler).Methods("POST")
	} else {
		// If auth is disabled, allow destructive operations without authentication
		api.HandleFunc("/queue/message/{id}", s.handleDeleteMessage).Methods("DELETE")
		api.HandleFunc("/queue/message/{id}/requeue", s.handleRequeueMessage).Methods("POST")
		api.HandleFunc("/queue/message/{id}/hold", s.handleHoldMessage).Methods("POST")
		api.HandleFunc("/queue/message/{id}/release-claim", s.handleReleaseMessageClaim).Methods("POST")
		api.HandleFunc("/queue/{type}/retry", s.handleRetryQueue).Methods("POST")
		api.HandleFunc("/queue/{type}/flush", s.handleFlushQueue).Methods("POST")
	}

	// Create the HTTP server locally; lifecycle publication is atomic below.
	httpServer := &http.Server{
		Addr:              s.listenAddr,
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	listenerFactory := s.listenerFactory
	if listenerFactory == nil {
		listenerFactory = s.createListener
	}
	listener, err := listenerFactory()
	if err != nil {
		s.finishStop(nil)
		return fmt.Errorf("failed to create api listener: %w", err)
	}

	s.lifecycleMu.Lock()
	if s.lifecycleState == serverStateStopping {
		s.lifecycleMu.Unlock()
		_ = listener.Close()
		s.finishStop(nil)
		return ErrServerStopped
	}
	s.httpServer = httpServer
	s.listener = listener

	// Start Serve before publishing readiness, so Stop can always wait on Shutdown.
	go func(server *http.Server, ln net.Listener) {
		log.Printf("Starting API server on %s", s.listenAddr)
		if s.authMiddleware != nil {
			log.Printf("Authentication enabled")
		} else if warning := unauthenticatedExposureWarning(ln.Addr(), s.listenAddr); warning != "" {
			log.Print(warning)
		}
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}(httpServer, listener)
	s.lifecycleState = serverStateRunning
	close(s.ready)
	s.lifecycleMu.Unlock()

	return nil
}

func (s *Server) initLifecycleLocked() {
	if s.ready == nil {
		s.ready = make(chan struct{})
	}
	if s.stopDone == nil {
		s.stopDone = make(chan struct{})
	}
}

// Ready is closed once the listener and HTTP server are published for use. It
// signals publication readiness, not that Serve will remain healthy afterward.
func (s *Server) Ready() <-chan struct{} {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.initLifecycleLocked()
	return s.ready
}

func (s *Server) finishStop(err error) {
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	s.lifecycleMu.Lock()
	s.stopErr = err
	s.lifecycleState = serverStateStopped
	close(s.stopDone)
	s.lifecycleMu.Unlock()
}

func (s *Server) requireAuthIfConfigured(next http.Handler) http.Handler {
	if s.authMiddleware == nil {
		return next
	}
	return s.authMiddleware.RequireAuth(next)
}

// unauthenticatedExposureWarning returns a startup warning when the admin API
// is running without authentication on an address reachable from off-host, and
// "" otherwise.
//
// With auth disabled the API will read any queued message, flush queues, and
// rewrite configuration for anyone who can reach the port. That is a
// reasonable default only on loopback; the shipped container binds 0.0.0.0, so
// the exposure is otherwise silent.
func unauthenticatedExposureWarning(bound net.Addr, configured string) string {
	host := ""
	if tcp, ok := bound.(*net.TCPAddr); ok {
		host = tcp.IP.String()
	}
	if host == "" || host == "<nil>" {
		if h, _, err := net.SplitHostPort(configured); err == nil {
			host = h
		}
	}

	// A concrete loopback bind is the safe case. Everything else — an explicit
	// external IP, or an empty/unspecified host meaning all interfaces — is
	// reachable from off the host.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ""
	}

	return "SECURITY: the admin API is serving on " + configured +
		" with authentication DISABLED. Anyone who can reach this address can read queued mail, " +
		"flush queues, and change configuration. Bind it to 127.0.0.1, put it behind an " +
		"authenticating proxy, or set [api].auth_enabled = true."
}

// Stop stops the API server. It is idempotent and waits for an in-progress
// startup before returning.
func (s *Server) Stop() error {
	s.lifecycleMu.Lock()
	s.initLifecycleLocked()
	switch s.lifecycleState {
	case serverStateStopped:
		err := s.stopErr
		s.lifecycleMu.Unlock()
		return err
	case serverStateStopping:
		done := s.stopDone
		s.lifecycleMu.Unlock()
		<-done
		s.lifecycleMu.Lock()
		err := s.stopErr
		s.lifecycleMu.Unlock()
		return err
	case serverStateNew:
		s.lifecycleState = serverStateStopping
		s.lifecycleMu.Unlock()
		s.finishStop(nil)
		return nil
	case serverStateStarting:
		s.lifecycleState = serverStateStopping
		done := s.stopDone
		s.lifecycleMu.Unlock()
		<-done
		s.lifecycleMu.Lock()
		err := s.stopErr
		s.lifecycleMu.Unlock()
		return err
	}

	s.lifecycleState = serverStateStopping
	httpServer := s.httpServer
	listener := s.listener
	s.lifecycleMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := httpServer.Shutdown(ctx)

	// Shutdown only closes listeners that Serve has already registered with the
	// http.Server. Start hands the listener to Serve on a new goroutine, so a
	// Stop that arrives before that goroutine is scheduled finds nothing to
	// close and returns while the port is still accepting connections.
	// Closing the listener here makes "Stop returned" mean "the port is shut".
	// Serve's own deferred Close makes the second close a no-op.
	if listener != nil {
		if closeErr := listener.Close(); closeErr != nil && err == nil {
			if !errors.Is(closeErr, net.ErrClosed) {
				err = closeErr
			}
		}
	}

	s.lifecycleMu.Lock()
	s.httpServer = nil
	s.listener = nil
	s.lifecycleMu.Unlock()
	s.finishStop(err)
	return err
}

func (s *Server) createListener() (net.Listener, error) {
	if inheritedFD := os.Getenv(inheritedHTTPFDEnv); inheritedFD != "" {
		fd, err := strconv.Atoi(inheritedFD)
		if err != nil {
			return nil, fmt.Errorf("invalid inherited listener fd %q: %w", inheritedFD, err)
		}

		if fd < 0 {
			return nil, fmt.Errorf("invalid inherited listener fd %d", fd)
		}

		// #nosec G115 -- fd is validated as non-negative OS file descriptor before uintptr conversion
		f := os.NewFile(uintptr(fd), "inherited-api-listener")
		if f == nil {
			return nil, fmt.Errorf("failed to create file handle for inherited listener fd %d", fd)
		}
		defer f.Close()

		ln, err := net.FileListener(f)
		if err != nil {
			return nil, fmt.Errorf("failed to adopt inherited listener fd %d: %w", fd, err)
		}

		if err := os.Unsetenv(inheritedHTTPFDEnv); err != nil {
			log.Printf("warning: failed to unset %s: %v", inheritedHTTPFDEnv, err)
		}
		log.Printf("Adopted inherited API listener on fd %d", fd)
		return ln, nil
	}

	return net.Listen("tcp", s.listenAddr)
}

func (s *Server) startReplacementProcess() (*os.Process, error) {
	s.lifecycleMu.Lock()
	tcpListener, ok := s.listener.(*net.TCPListener)
	if !ok {
		s.lifecycleMu.Unlock()
		return nil, fmt.Errorf("listener does not support graceful restart handoff")
	}

	listenerFile, err := tcpListener.File()
	s.lifecycleMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to duplicate listener file descriptor: %w", err)
	}
	defer listenerFile.Close()

	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// #nosec G204 -- intentional self-reexec for graceful restart; executable path is resolved from current binary
	cmd := exec.Command(executablePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.ExtraFiles = []*os.File{listenerFile}
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", inheritedHTTPFDEnv, 3))

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start replacement process: %w", err)
	}

	return cmd.Process, nil
}

// API handlers

// handleGetAllQueues returns a page of messages across all queues
func (s *Server) handleGetAllQueues(w http.ResponseWriter, r *http.Request) {
	messages, err := s.queueMgr.GetAllMessages()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, listQueuePage(messages, parseQueueListQuery(r)))
}

// handleGetQueue returns a page of messages in a specific queue
func (s *Server) handleGetQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	queueType, err := parseQueueType(qType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	messages, err := s.queueMgr.ListMessages(queueType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, listQueuePage(messages, parseQueueListQuery(r)))
}

// handleFlushQueue flushes a specific queue
func (s *Server) handleFlushQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	var err error
	if qType == "all" {
		err = s.queueMgr.FlushAllQueues()
	} else {
		queueType, qErr := parseQueueType(qType)
		if qErr != nil {
			http.Error(w, fmt.Sprintf("Error: %v", qErr), http.StatusBadRequest)
			return
		}

		err = s.queueMgr.FlushQueue(queueType)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Queue %s flushed", qType)})
}

// handleRetryQueue requeues every message in a queue for immediate delivery.
//
// This is the non-destructive counterpart to flush. The dashboard's "process"
// and "retry" actions call it; flush deletes, so pointing those actions at
// flush meant a click labelled "Retry Deferred" silently discarded the queue.
func (s *Server) handleRetryQueue(w http.ResponseWriter, r *http.Request) {
	qType := mux.Vars(r)["type"]

	var req queueActionRequest
	if err := decodeOptionalQueueActionRequest(r, &req); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "bulk retry from dashboard"
	}

	var requeued int
	if qType == "all" {
		for _, qt := range []queue.QueueType{queue.Deferred, queue.Failed, queue.Hold, queue.Active} {
			n, err := s.queueMgr.RequeueQueue(qt, reason)
			requeued += n
			if err != nil {
				http.Error(w, fmt.Sprintf("Error retrying %s: %v", qt, err), http.StatusInternalServerError)
				return
			}
		}
	} else {
		queueType, qErr := parseQueueType(qType)
		if qErr != nil {
			http.Error(w, fmt.Sprintf("Error: %v", qErr), http.StatusBadRequest)
			return
		}
		n, err := s.queueMgr.RequeueQueue(queueType, reason)
		requeued = n
		if err != nil {
			http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]interface{}{
		"status":   "success",
		"action":   "requeued",
		"queue":    qType,
		"requeued": requeued,
		"message":  fmt.Sprintf("%d message(s) requeued for delivery", requeued),
	})
}

// handleGetMessage returns a specific message
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Get message metadata first
	msg, err := s.queueMgr.GetMessage(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Message not found: %v", err), http.StatusNotFound)
		return
	}

	content, err := s.queueMgr.GetMessageContent(id)
	if err != nil {
		// Log the error and return a more specific message to the user
		// #nosec G706 -- diagnostic logging only; message id is operational metadata
		log.Printf("Error getting content for message %s: %v", id, err)
		http.Error(w, fmt.Sprintf("Message metadata loaded, but content is missing or corrupt: %v", err), http.StatusNotFound)
		return
	}

	// If format=raw is specified, return raw message
	if r.URL.Query().Get("format") == "raw" {
		w.Header().Set("Content-Type", "text/plain")
		// #nosec G705 -- raw MIME output is intentional for queue message inspection endpoint
		if _, err := w.Write(content); err != nil {
			// #nosec G706 -- diagnostic logging only; message id is operational metadata
			log.Printf("Error writing raw response for message %s: %v", id, err)
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
		return
	}

	// Include the content with the message
	type MessageWithContent struct {
		queue.Message
		Content string `json:"content"`
	}

	msgWithContent := MessageWithContent{
		Message: msg,
		Content: string(content),
	}

	writeJSON(w, msgWithContent)
}

// handleDeleteMessage deletes a specific message
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.queueMgr.DeleteMessage(id); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Message %s deleted", id)})
}

// handleGetQueueStats returns queue statistics
func (s *Server) handleGetQueueStats(w http.ResponseWriter, r *http.Request) {
	if err := s.queueMgr.UpdateStats(); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	stats := s.queueMgr.GetStats()
	writeJSON(w, stats)
}

// handleGetQueueStorage returns storage usage details for the active queue backend.
func (s *Server) handleGetQueueStorage(w http.ResponseWriter, r *http.Request) {
	info, err := s.queueMgr.GetStorageInfo()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, info)
}

// handleLoginPage serves the public login page
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	setHTMLNoCache(w)
	http.ServeFile(w, r, "web/login.html")
}

// handleLogo serves the Elemta logo for the login page (public)
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	// #nosec G706 -- request path is logged for troubleshooting and sanitized
	log.Printf("Logo request received for path: %s", sanitizeForLog(r.URL.Path))

	// Try different possible paths
	paths := []string{
		"images/elemta.png",
		"./images/elemta.png",
		"web/../images/elemta.png",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			log.Printf("Serving logo from: %s", path)
			http.ServeFile(w, r, path)
			return
		}
	}

	log.Printf("Logo file not found in any expected path")
	http.NotFound(w, r)
}

// handleDashboard serves the main dashboard page
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	setHTMLNoCache(w)
	http.ServeFile(w, r, s.webRoot+"/index.html")
}

// setHTMLNoCache stops browsers reusing a stale application shell.
//
// The HTML references its CSS and JS with a version query string, so those can
// be cached hard. The document that carries those references cannot: it was
// served with only Last-Modified, which browsers are free to satisfy from cache
// without revalidating. A stale shell then keeps requesting the asset versions
// it was built with, so an updated UI simply never arrives — the symptom being
// a page that still shows old styling and duplicate controls long after the
// server was rebuilt.
//
// must-revalidate rather than no-store: the response may still be cached, the
// browser just has to ask whether it is current, which a Last-Modified check
// answers cheaply.
func setHTMLNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
}

// Authentication handlers

// handleLogin handles user login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("Login attempt received")

	if s.authSystem == nil {
		log.Printf("Auth system is nil - authentication not enabled")
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	if s.sessionManager == nil {
		log.Printf("Session manager is nil")
		http.Error(w, "Session management not available", http.StatusServiceUnavailable)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Authenticate user
	ctx := context.Background()
	authenticated, err := s.authSystem.Authenticate(ctx, loginReq.Username, loginReq.Password)
	if err != nil || !authenticated {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	log.Printf("Creating session for user: %s", loginReq.Username)
	session, err := s.sessionManager.CreateSession(loginReq.Username, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	log.Printf("Session created successfully for user: %s", loginReq.Username)

	// Set session cookie
	log.Printf("Setting session cookie")
	s.sessionManager.SetCookie(w, r, session.ID)
	log.Printf("Session cookie set")

	// Get user permissions
	permissions, _ := s.rbac.GetUserPermissions(ctx, loginReq.Username)

	writeJSON(w, map[string]interface{}{
		"status":      "success",
		"username":    loginReq.Username,
		"permissions": permissions,
	})
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Printf("Logout request received")

	if s.sessionManager == nil {
		log.Printf("Session manager is nil during logout")
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	sessionID := s.sessionManager.GetSessionFromRequest(r)
	// #nosec G706 -- session id logging is operational; value is sanitized
	log.Printf("Found session ID for logout: %s", sanitizeForLog(sessionID))

	if sessionID != "" {
		err := s.sessionManager.RevokeSession(sessionID)
		if err != nil {
			log.Printf("Error revoking session: %v", err)
		} else {
			log.Printf("Session revoked successfully")
		}
	}

	// Clear session cookie
	log.Printf("Clearing session cookie")
	s.sessionManager.ClearCookie(w, r)
	log.Printf("Session cookie cleared")

	// Redirect to login page instead of returning JSON
	log.Printf("Redirecting to login page")
	http.Redirect(w, r, "/login?logout=1", http.StatusFound)
}

// handleMe returns current user information
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.authMiddleware == nil {
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	// Authenticate using the same method as RequireAuth middleware
	authCtx, err := s.authMiddleware.authenticate(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Get user details
	ctx := context.Background()
	user, err := s.authSystem.GetUser(ctx, authCtx.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Don't return password
	user.Password = ""

	writeJSON(w, map[string]interface{}{
		"user":        user,
		"permissions": authCtx.Permissions,
		"is_api_key":  authCtx.IsAPIKey,
	})
}

// API Key management handlers

// handleListAPIKeys lists API keys for the current user
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	keys := s.apiKeyManager.ListAPIKeys(authCtx.Username)
	writeJSON(w, keys)
}

// handleCreateAPIKey creates a new API key
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Permissions []auth.Permission `json:"permissions"`
		ExpiryDays  *int              `json:"expiry_days,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var expiryDuration *time.Duration
	if req.ExpiryDays != nil && *req.ExpiryDays > 0 {
		duration := time.Duration(*req.ExpiryDays) * 24 * time.Hour
		expiryDuration = &duration
	}
	if err := s.validateRequestedAPIKeyPermissions(authCtx, req.Permissions); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	apiKey, keyString, err := s.apiKeyManager.CreateAPIKey(
		authCtx.Username,
		req.Name,
		req.Description,
		req.Permissions,
		expiryDuration,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create API key: %v", err), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]interface{}{
		"api_key": apiKey,
		"key":     keyString, // Only returned once
	})
}

// handleGetAPIKey gets a specific API key
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	// Users can only see their own keys (unless admin)
	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	writeJSON(w, apiKey)
}

// handleUpdateAPIKey updates an API key
func (s *Server) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Permissions []auth.Permission `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	if err := s.validateRequestedAPIKeyPermissions(authCtx, req.Permissions); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.UpdateAPIKey(keyID, req.Name, req.Description, req.Permissions); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update API key: %v", err), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key updated"})
}

// handleDeleteAPIKey deletes an API key
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.DeleteAPIKey(keyID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete API key: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key deleted"})
}

// handleRevokeAPIKey revokes an API key
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.RevokeAPIKey(keyID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke API key: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key revoked"})
}

// Debug handlers

// handleGetLogs fetches recent logs from log files
func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100" // Default to last 100 lines
	}

	// Try to read from various log file locations
	paths := runtimepaths.Detect()
	logFiles := []string{
		paths.LogFile,
		filepath.Join(paths.LogDir, "smtp.log"),
		filepath.Join(paths.LogDir, "queue.log"),
		filepath.Join(paths.LogDir, "application.log"),
	}
	if paths.LogDir != "/app/logs" {
		logFiles = append(logFiles,
			"/app/logs/elemta.log",
			"/app/logs/smtp.log",
			"/app/logs/queue.log",
			"/app/logs/application.log",
		)
	}

	var allLogs []string
	var source string

	// Read from available log files
	for _, logFile := range logFiles {
		if !isAllowedLogPath(logFile) {
			continue
		}
		if _, err := os.Stat(logFile); err == nil {
			// #nosec G304 -- path is constrained by isAllowedLogPath allowlist
			data, err := os.ReadFile(logFile)
			if err == nil {
				lines := strings.Split(string(data), "\n")
				// Filter out empty lines
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						allLogs = append(allLogs, line)
					}
				}
				source = filepath.Base(logFile)
				break // Use the first available log file
			}
		}
	}

	// If no log files found, provide a helpful message
	if len(allLogs) == 0 {
		response := map[string]interface{}{
			"logs":    []string{"No log files found. Logs may be written to stdout/stderr."},
			"count":   1,
			"tail":    tail,
			"source":  "none",
			"time":    time.Now().Format(time.RFC3339),
			"message": "Configure Elemta to write logs to /var/log/elemta/ or use container-specific /app/logs/ paths",
		}
		writeJSON(w, response)
		return
	}

	// If we have more logs than requested, return only the tail
	tailInt, err := strconv.Atoi(tail)
	if err != nil {
		tailInt = 100
	}

	if len(allLogs) > tailInt {
		allLogs = allLogs[len(allLogs)-tailInt:]
	}

	// Create response
	response := map[string]interface{}{
		"logs":   allLogs,
		"count":  len(allLogs),
		"tail":   tail,
		"source": source,
		"time":   time.Now().Format(time.RFC3339),
	}

	writeJSON(w, response)
}

// MessageLog represents a structured message lifecycle log entry
type MessageLog struct {
	Time      string                 `json:"time"`
	Level     string                 `json:"level"`
	Message   string                 `json:"msg"`
	EventType string                 `json:"event_type,omitempty"`
	Component string                 `json:"component,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// handleGetMessageLogs fetches structured message lifecycle logs
func (s *Server) handleGetMessageLogs(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limitStr = "50" // Reduced default from 100 to 50
	}
	limit, parseErr := strconv.Atoi(limitStr)
	if parseErr != nil || limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500 // Reduced max from 1000 to 500
	}

	eventTypeFilter := r.URL.Query().Get("event_type")
	levelFilter := r.URL.Query().Get("level")

	// Read log file using tail approach for better performance
	paths := runtimepaths.Detect()
	logCandidates := []string{paths.LogFile}
	if paths.LogFile != "/app/logs/elemta.log" {
		logCandidates = append(logCandidates, "/app/logs/elemta.log")
	}
	logCandidates = append(logCandidates, "./logs/elemta.log")

	var messageLogs []MessageLog
	var err error
	logFile := ""
	for _, candidate := range logCandidates {
		messageLogs, err = s.tailLogFile(candidate, limit, eventTypeFilter, levelFilter)
		if err == nil {
			logFile = candidate
			break
		}
		logFile = candidate
	}
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"logs":    []MessageLog{},
			"count":   0,
			"message": "No log file found",
			"source":  logFile,
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"logs":   messageLogs,
		"count":  len(messageLogs),
		"source": logFile,
		"limit":  limit,
	})
}

// maxLogScanBytes bounds how much of the log file a single request may scan.
// A filtered query that matches nothing used to walk the whole file backwards,
// JSON-parsing every line — 20+ seconds against the multi-gigabyte log a busy
// server accumulates, per click, in the request path.
const maxLogScanBytes = 32 * 1024 * 1024

// tailLogFile reads the log file from the end and returns matching entries.
//
// The scan stops at limit*3 matches or after maxLogScanBytes, whichever comes
// first. A filter with no matches therefore returns empty quickly instead of
// scanning to the beginning of time.
func (s *Server) tailLogFile(filename string, limit int, eventTypeFilter, levelFilter string) ([]MessageLog, error) {
	if !isAllowedLogPath(filename) {
		return nil, fmt.Errorf("log file path not allowed: %s", filename)
	}

	// #nosec G304 -- path is constrained by isAllowedLogPath allowlist
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	var messageLogs []MessageLog
	const maxLineSize = 8192
	buffer := make([]byte, maxLineSize)

	// Lowercased needles for the cheap pre-filter below.
	levelNeedle := strings.ToLower(levelFilter)
	typeNeedle := strings.ToLower(eventTypeFilter)

	offset := stat.Size()
	scanFloor := int64(0)
	if offset > maxLogScanBytes {
		scanFloor = offset - maxLogScanBytes
	}
	linesFound := 0
	maxLinesToRead := limit * 3 // Read more lines than needed to survive filtering

	for offset > scanFloor && linesFound < maxLinesToRead {
		chunkSize := int64(len(buffer))
		if offset-scanFloor < chunkSize {
			chunkSize = offset - scanFloor
		}
		offset -= chunkSize

		if _, err := file.ReadAt(buffer[:chunkSize], offset); err != nil {
			break
		}

		chunk := string(buffer[:chunkSize])
		chunkLines := strings.Split(chunk, "\n")

		// If we're not at the start of the scan window, the first line of the
		// chunk is partial; it will be read whole in the next iteration.
		if offset > scanFloor && len(chunkLines) > 1 {
			chunkLines = chunkLines[1:]
		}

		// Process lines in reverse order, since the file is walked backwards.
		for i := len(chunkLines) - 1; i >= 0 && linesFound < maxLinesToRead; i-- {
			line := strings.TrimSpace(chunkLines[i])
			if line == "" {
				continue
			}

			// Cheap pre-filter: a line that does not even contain the filter
			// text cannot match it, and skipping the JSON parse is what makes
			// scanning a large window affordable. False positives fall
			// through to the real checks below.
			if levelNeedle != "" || typeNeedle != "" {
				lower := strings.ToLower(line)
				if levelNeedle != "" && !strings.Contains(lower, levelNeedle) {
					continue
				}
				if typeNeedle != "" && typeNeedle != "system" && !strings.Contains(lower, typeNeedle) {
					continue
				}
			}

			var logEntry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
				continue // skip non-JSON lines
			}

			timeStr, _ := logEntry["time"].(string)
			level, _ := logEntry["level"].(string)
			msg, _ := logEntry["msg"].(string)
			eventType, _ := logEntry["event_type"].(string)
			component, _ := logEntry["component"].(string)

			// Enforce strict categorization for 4xx/5xx errors if event_type is missing or system
			if eventType == "" || eventType == "system" {
				eventType = categorizeLogEntry(logEntry, msg)
			}

			// Apply filters
			if eventTypeFilter != "" {
				if eventTypeFilter == "system" {
					// System filter matches explicit "system" events or events with no type
					// It excludes known lifecycle events
					isKnownCategory := false
					knownCategories := []string{"reception", "delivery", "rejection", "deferral", "bounce", "tempfail", "authentication"}
					for _, t := range knownCategories {
						if eventType == t {
							isKnownCategory = true
							break
						}
					}
					if isKnownCategory {
						continue
					}
				} else if eventType != eventTypeFilter {
					continue
				}
			}
			if levelFilter != "" && !strings.EqualFold(level, levelFilter) {
				continue
			}

			// Only include message lifecycle events or interesting logs
			includeLog := false
			messageLifecycleTypes := []string{
				"reception", "delivery", "rejection", "deferral", "bounce", "tempfail", "authentication",
			}
			for _, t := range messageLifecycleTypes {
				if eventType == t {
					includeLog = true
					break
				}
			}
			// Always include system events, errors, and warnings
			if !includeLog && (eventType == "system" || strings.EqualFold(level, "error") || strings.EqualFold(level, "warn")) {
				includeLog = true
			}

			if includeLog {
				messageLogs = append(messageLogs, MessageLog{
					Time:      timeStr,
					Level:     level,
					Message:   msg,
					EventType: eventType,
					Component: component,
					Fields:    logEntry,
				})
				linesFound++
			}
		}
	}

	// The walk collected newest-first; flip to chronological order.
	for i, j := 0, len(messageLogs)-1; i < j; i, j = i+1, j-1 {
		messageLogs[i], messageLogs[j] = messageLogs[j], messageLogs[i]
	}

	// Trim to the requested limit, keeping the newest entries.
	if len(messageLogs) > limit {
		messageLogs = messageLogs[len(messageLogs)-limit:]
	}

	return messageLogs, nil
}

// Configuration management handlers

// handleGetConfig returns the current configuration (read-only)
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.mainConfig == nil {
		http.Error(w, "Configuration not available", http.StatusServiceUnavailable)
		return
	}

	// Create a safe configuration response (exclude sensitive data)
	configResponse := map[string]interface{}{
		"hostname":                     s.mainConfig.Hostname,
		"listen_addr":                  s.mainConfig.ListenAddr,
		"queue_dir":                    s.mainConfig.QueueDir,
		"max_size":                     s.mainConfig.MaxSize,
		"max_workers":                  s.mainConfig.MaxWorkers,
		"max_retries":                  s.mainConfig.MaxRetries,
		"max_queue_time":               s.mainConfig.MaxQueueTime,
		"retry_schedule":               s.mainConfig.RetrySchedule,
		"session_timeout":              s.mainConfig.SessionTimeout,
		"local_domains":                s.mainConfig.LocalDomains,
		"failed_queue_retention_hours": s.mainConfig.FailedQueueRetentionHours,
		"rate_limiter":                 s.mainConfig.RateLimiterPluginConfig,
		"tls":                          s.mainConfig.TLS,
		"api":                          s.mainConfig.API,
	}

	writeJSON(w, configResponse)
}

// handleGetPlugins returns the status of all plugins
func (s *Server) handleGetPlugins(w http.ResponseWriter, r *http.Request) {
	if s.mainConfig == nil {
		http.Error(w, "Configuration not available", http.StatusServiceUnavailable)
		return
	}

	// Rate limiter plugin - we have direct config access
	rateLimiterEnabled := false
	if s.mainConfig.RateLimiterPluginConfig != nil {
		if rateLimiterConfig, ok := s.mainConfig.RateLimiterPluginConfig.(*config.RateLimiterPluginConfig); ok {
			rateLimiterEnabled = rateLimiterConfig.Enabled
		}
	}

	// Scanner state comes from configuration. This process does not run the
	// scanners — the SMTP node does — so what is reported here is what the
	// shipped config asks for, which is also what the UI can meaningfully
	// edit. This used to be hardcoded nil, which the UI dressed up as
	// "Disabled (managed via docker-compose)" regardless of reality.
	clamavEnabled, clamavConfig := false, map[string]interface{}(nil)
	if av := s.mainConfig.Antivirus; av != nil {
		clamavEnabled = av.Enabled
		clamavConfig = map[string]interface{}{
			"address":           av.Address,
			"timeout":           av.Timeout,
			"scan_limit":        av.ScanLimit,
			"reject_on_failure": av.RejectOnFailure,
		}
	}
	rspamdEnabled, rspamdConfig := false, map[string]interface{}(nil)
	if as := s.mainConfig.Antispam; as != nil {
		rspamdEnabled = as.Enabled
		rspamdConfig = map[string]interface{}{
			"address":        as.Address,
			"timeout":        as.Timeout,
			"scan_limit":     as.ScanLimit,
			"threshold":      as.Threshold,
			"reject_on_spam": as.RejectOnSpam,
		}
	}

	// configurable drives the per-plugin settings tab in the UI: a plugin with
	// settings worth editing gets its own tab while it is enabled, and loses it
	// when it is turned off. requires_restart says whether toggling takes effect
	// in this process or needs the SMTP server restarted, so the UI can tell the
	// operator the truth instead of implying the change is already live.
	acEnabled, acConfig := false, map[string]interface{}(nil)
	if ac := s.mainConfig.AccessControl; ac != nil {
		acEnabled = ac.Enabled
		acConfig = map[string]interface{}{
			"allow_ips":     ac.AllowIPs,
			"deny_ips":      ac.DenyIPs,
			"allow_domains": ac.AllowDomains,
			"deny_domains":  ac.DenyDomains,
		}
	}
	accessControlEnabled, accessControlConfig := acEnabled, acConfig

	mmEnabled, mmConfig := false, map[string]interface{}(nil)
	if mm := s.mainConfig.MassMailer; mm != nil {
		mmEnabled = mm.Enabled
		mmConfig = map[string]interface{}{
			"default_rate_per_minute": mm.DefaultRatePerMinute,
			"max_recipients":          mm.MaxRecipients,
		}
	}

	// needsConfig is a plugin that has a prerequisite before it can be turned
	// on at all. The UI uses it to show the settings form for a plugin that is
	// still off, which is the only way out of "the toggle refuses until you
	// configure it, and the form is only shown once it is enabled".
	rblEnabled, rblConfig, rblNeedsConfig := false, map[string]interface{}(nil), true
	if r := s.mainConfig.RBL; r != nil {
		rblEnabled = r.Enabled
		rblNeedsConfig = len(r.Zones) == 0
		rblConfig = map[string]interface{}{
			"zones":      r.Zones,
			"reject":     r.Reject,
			"timeout":    r.Timeout,
			"skip_ips":   r.SkipIPs,
			"cache_ttl":  r.CacheTTL,
			"cache_size": r.CacheSize,
		}
	}

	plugins := []map[string]interface{}{
		{
			"name":             "rate_limiter",
			"title":            "Rate Limiting",
			"enabled":          rateLimiterEnabled,
			"description":      "Rate limiting and connection management",
			"config":           s.mainConfig.RateLimiterPluginConfig,
			"configurable":     true,
			"requires_restart": false,
		},
		{
			"name":              "clamav",
			"title":             "Antivirus",
			"enabled":           clamavEnabled,
			"description":       "Antivirus and malware scanning",
			"config":            clamavConfig,
			"configurable":      true,
			"requires_restart":  false,
			"applies_on_reload": true,
		},
		{
			"name":              "access_control",
			"title":             "Allow / Deny",
			"enabled":           accessControlEnabled,
			"description":       "Allow and deny lists for peer addresses and sender domains",
			"config":            accessControlConfig,
			"configurable":      true,
			"requires_restart":  false,
			"applies_on_reload": true,
		},
		{
			"name":              "rspamd",
			"title":             "Antispam",
			"enabled":           rspamdEnabled,
			"description":       "Spam filtering and content analysis",
			"config":            rspamdConfig,
			"configurable":      true,
			"requires_restart":  false,
			"applies_on_reload": true,
		},
		{
			"name":              "rbl",
			"title":             "DNS Blocklists",
			"enabled":           rblEnabled,
			"description":       "Check the connecting address against DNS blocklists (RBL/DNSBL)",
			"config":            rblConfig,
			"configurable":      true,
			"requires_restart":  false,
			"applies_on_reload": true,
			// This plugin cannot be switched on until it has something to
			// query. Saying so here is what lets the UI offer its settings
			// before it is enabled; without it the toggle refuses and the form
			// that would fix the refusal is nowhere to be found.
			"needs_config": rblNeedsConfig,
		},
		{
			"name":        "mass_mailer",
			"title":       "Mass Mailer",
			"enabled":     mmEnabled,
			"description": "Bulk campaigns with a throttled background sender",
			"config":      mmConfig,
			// The campaign store and runner live in this process, so unlike the
			// scanners this one is live the moment it is switched on.
			"configurable":     true,
			"requires_restart": false,
		},
	}

	writeJSON(w, map[string]interface{}{
		"plugins": plugins,
	})
}

// handleUpdateConfig updates configuration and persists to disk
func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if s.mainConfig == nil {
		http.Error(w, "Configuration not available", http.StatusServiceUnavailable)
		return
	}

	var configUpdate map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	requiresRestart := false

	// Apply server config fields
	if v, ok := configUpdate["hostname"].(string); ok && v != s.mainConfig.Hostname {
		s.mainConfig.Hostname = v
		requiresRestart = true
	}
	if v, ok := configUpdate["listen_addr"].(string); ok && v != s.mainConfig.ListenAddr {
		s.mainConfig.ListenAddr = v
		requiresRestart = true
	}
	if v, ok := configUpdate["queue_dir"].(string); ok && v != s.mainConfig.QueueDir {
		s.mainConfig.QueueDir = v
		requiresRestart = true
	}
	if v, ok := configUpdate["max_size"].(float64); ok {
		s.mainConfig.MaxSize = int64(v)
	}
	if v, ok := configUpdate["max_workers"].(float64); ok {
		s.mainConfig.MaxWorkers = int(v)
	}
	if v, ok := configUpdate["failed_queue_retention_hours"].(float64); ok {
		s.mainConfig.FailedQueueRetentionHours = int(v)
	}

	// Apply rate limiter config if present
	if rl, ok := configUpdate["rate_limiter"].(map[string]interface{}); ok {
		s.applyRateLimiterUpdate(rl)
	}

	// Persist to disk
	if s.configPath != "" {
		if err := s.persistConfig(); err != nil {
			slog.Error("Failed to persist configuration", "error", err)
			http.Error(w, fmt.Sprintf("Failed to save configuration: %v", err), http.StatusInternalServerError)
			return
		}
	}

	msg := "Configuration saved"
	if requiresRestart {
		msg = "Configuration saved (restart required for some changes to take effect)"
	}

	writeJSON(w, map[string]interface{}{
		"status":           "success",
		"message":          msg,
		"requires_restart": requiresRestart,
	})
}

// applyRateLimiterUpdate applies rate limiter fields from a map to the in-memory config
func (s *Server) applyRateLimiterUpdate(rl map[string]interface{}) {
	var rateCfg *config.RateLimiterPluginConfig
	if s.mainConfig.RateLimiterPluginConfig != nil {
		if rc, ok := s.mainConfig.RateLimiterPluginConfig.(*config.RateLimiterPluginConfig); ok {
			rateCfg = rc
		}
	}
	if rateCfg == nil {
		rateCfg = config.DefaultRateLimiterPluginConfig()
		s.mainConfig.RateLimiterPluginConfig = rateCfg
	}

	if v, ok := rl["enabled"].(bool); ok {
		rateCfg.Enabled = v
	}
	if v, ok := rl["max_connections_per_ip"].(float64); ok {
		rateCfg.MaxConnectionsPerIP = int(v)
	}
	if v, ok := rl["connection_rate_per_minute"].(float64); ok {
		rateCfg.ConnectionRatePerMinute = int(v)
	}
	if v, ok := rl["connection_burst_size"].(float64); ok {
		rateCfg.ConnectionBurstSize = int(v)
	}
	if v, ok := rl["connection_timeout"].(string); ok {
		rateCfg.ConnectionTimeout = v
	}
	if v, ok := rl["max_messages_per_minute"].(float64); ok {
		rateCfg.MaxMessagesPerMinute = int(v)
	}
	if v, ok := rl["max_messages_per_hour"].(float64); ok {
		rateCfg.MaxMessagesPerHour = int(v)
	}
	if v, ok := rl["max_recipients_per_message"].(float64); ok {
		rateCfg.MaxRecipientsPerMessage = int(v)
	}
	if v, ok := rl["max_message_size"].(string); ok {
		rateCfg.MaxMessageSize = v
	}
}

// persistConfig writes the settings the API manages back to the config file,
// changing only those keys.
//
// It used to rebuild a config.Config from DefaultConfig(), copy a dozen fields
// across and re-serialise the whole file with SaveConfig — which emits only the
// sections it knows about. Everything else was destroyed: toggling the rate
// limiter in the web UI deleted [antivirus] and [antispam] outright, turning
// off virus and spam scanning, and reset queue.backend from sqlite to file,
// pointing the server at a different queue and orphaning the mail already in
// it. None of that was reported; the toggle returned success.
//
// Editing the keys in place cannot do that. A setting this code has never heard
// of survives, as do comments and ordering.
func (s *Server) persistConfig() error {
	if s.configPath == "" {
		return fmt.Errorf("no config file path is known")
	}

	doc, err := os.ReadFile(s.configPath) // #nosec G304 -- operator-configured path
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	type edit struct {
		section string
		key     string
		value   interface{}
	}
	edits := []edit{
		{"", "hostname", s.mainConfig.Hostname},
		{"", "listen_addr", s.mainConfig.ListenAddr},
		{"", "max_size", s.mainConfig.MaxSize},
		{"", "failed_queue_retention_hours", s.mainConfig.FailedQueueRetentionHours},
	}
	if len(s.mainConfig.LocalDomains) > 0 {
		edits = append(edits, edit{"", "local_domains", s.mainConfig.LocalDomains})
	}

	// Rate limiter, if the API is holding one.
	if rc, ok := s.mainConfig.RateLimiterPluginConfig.(*config.RateLimiterPluginConfig); ok && rc != nil {
		edits = append(edits,
			edit{"rate_limiter", "enabled", rc.Enabled},
			edit{"rate_limiter", "max_connections_per_ip", rc.MaxConnectionsPerIP},
			edit{"rate_limiter", "max_messages_per_minute", rc.MaxMessagesPerMinute},
			edit{"rate_limiter", "max_messages_per_hour", rc.MaxMessagesPerHour},
			edit{"rate_limiter", "max_recipients_per_message", rc.MaxRecipientsPerMessage},
		)
	}

	// Scanners. The endpoint settings live in the [antivirus.clamav] and
	// [antispam.rspamd] subsections, while the rejection policy is a property of
	// the stage as a whole and sits in the parent — writing either to the wrong
	// place produces a file that loads cleanly and ignores the setting.
	//
	// An unset endpoint setting is left out rather than written as a zero. A
	// scanner section can be absent from the file entirely, in which case the
	// toggle creates one from an empty struct — writing that out would replace a
	// working address with "" and a timeout with 0, which is not "the default"
	// but "no timeout".
	if av := s.mainConfig.Antivirus; av != nil {
		edits = append(edits,
			edit{"antivirus", "enabled", av.Enabled},
			edit{"antivirus", "reject_on_failure", av.RejectOnFailure},
			edit{"antivirus.clamav", "enabled", av.Enabled},
		)
		if av.Address != "" {
			edits = append(edits, edit{"antivirus.clamav", "address", av.Address})
		}
		if av.Timeout > 0 {
			edits = append(edits, edit{"antivirus.clamav", "timeout", av.Timeout})
		}
		if av.ScanLimit > 0 {
			edits = append(edits, edit{"antivirus.clamav", "scan_limit", av.ScanLimit})
		}
	}
	if as := s.mainConfig.Antispam; as != nil {
		edits = append(edits,
			edit{"antispam", "enabled", as.Enabled},
			edit{"antispam", "reject_on_spam", as.RejectOnSpam},
			edit{"antispam.rspamd", "enabled", as.Enabled},
		)
		if as.Address != "" {
			edits = append(edits, edit{"antispam.rspamd", "address", as.Address})
		}
		if as.Timeout > 0 {
			edits = append(edits, edit{"antispam.rspamd", "timeout", as.Timeout})
		}
		if as.ScanLimit > 0 {
			edits = append(edits, edit{"antispam.rspamd", "scan_limit", as.ScanLimit})
		}
		if as.Threshold > 0 {
			edits = append(edits, edit{"antispam.rspamd", "threshold", as.Threshold})
		}
	}
	if r := s.mainConfig.RBL; r != nil {
		edits = append(edits,
			edit{"rbl", "enabled", r.Enabled},
			edit{"rbl", "zones", r.Zones},
			edit{"rbl", "reject", r.Reject},
			edit{"rbl", "skip_ips", r.SkipIPs},
		)
		// Same rule as the scanners: an unset bound is left out rather than
		// written as a zero, which here would mean no timeout and no cache.
		if r.Timeout > 0 {
			edits = append(edits, edit{"rbl", "timeout", r.Timeout})
		}
		if r.CacheTTL > 0 {
			edits = append(edits, edit{"rbl", "cache_ttl", r.CacheTTL})
		}
		if r.CacheSize > 0 {
			edits = append(edits, edit{"rbl", "cache_size", r.CacheSize})
		}
	}
	if mm := s.mainConfig.MassMailer; mm != nil {
		edits = append(edits,
			edit{"mass_mailer", "enabled", mm.Enabled},
			edit{"mass_mailer", "default_rate_per_minute", mm.DefaultRatePerMinute},
			edit{"mass_mailer", "max_recipients", mm.MaxRecipients},
		)
	}
	if ac := s.mainConfig.AccessControl; ac != nil {
		edits = append(edits,
			edit{"access_control", "enabled", ac.Enabled},
			edit{"access_control", "allow_ips", ac.AllowIPs},
			edit{"access_control", "deny_ips", ac.DenyIPs},
			edit{"access_control", "allow_domains", ac.AllowDomains},
			edit{"access_control", "deny_domains", ac.DenyDomains},
		)
	}

	for _, e := range edits {
		doc, err = config.SetTOMLValue(doc, e.section, e.key, e.value)
		if err != nil {
			return fmt.Errorf("update %s.%s: %w", e.section, e.key, err)
		}
	}

	// Write via a temp file in the same directory so a failure part-way through
	// cannot leave a half-written config behind.
	//
	// #nosec G703 -- configPath is resolved once at startup from --config or
	// config discovery and is never derived from a request. No handler writes
	// it, so there is no request-controlled component in this path; the taint
	// analysis is flagging the absence of a string literal, not a reachable
	// traversal.
	tmp := s.configPath + ".tmp"
	// #nosec G703 -- see above: configPath is startup-resolved, not request-derived.
	if err := os.WriteFile(tmp, doc, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	// #nosec G703 -- same path, same provenance.
	if err := os.Rename(tmp, s.configPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", s.configPath, err)
	}
	return nil
}

// handleUpdatePlugin enables or disables a plugin and persists the change.
//
// Whether the change takes effect immediately depends on the plugin. The rate
// limiter is read by this process. The scanners are used by the SMTP server,
// which reads its configuration at startup, so those need a restart — reported
// as requires_restart so the UI can say so rather than implying the toggle took
// effect.
func (s *Server) handleUpdatePlugin(w http.ResponseWriter, r *http.Request) {
	if s.mainConfig == nil {
		http.Error(w, "Configuration not available", http.StatusServiceUnavailable)
		return
	}

	pluginName := mux.Vars(r)["plugin"]
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	var pluginUpdate struct {
		Enabled *bool                  `json:"enabled"`
		Config  map[string]interface{} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&pluginUpdate); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if pluginUpdate.Enabled == nil && pluginUpdate.Config == nil {
		http.Error(w, "Send 'enabled' (boolean), 'config' (object), or both", http.StatusBadRequest)
		return
	}

	// Settings first: a payload that turns a plugin on with settings it will
	// refuse to start with should not leave the toggle flipped.
	if pluginUpdate.Config != nil {
		if err := s.applyPluginConfig(pluginName, pluginUpdate.Config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// An update that only changes settings leaves enablement alone.
	enabled := s.pluginEnabled(pluginName)
	if pluginUpdate.Enabled != nil {
		enabled = *pluginUpdate.Enabled
	}

	// requiresRestart means the operator has to take the server down to apply
	// this. appliesOnReload means the SMTP server picks it up on its own,
	// shortly, without dropping connections — a distinction worth keeping,
	// because telling someone to restart when they need not is how a restart
	// becomes a reflex.
	requiresRestart := false
	appliesOnReload := false
	switch pluginName {
	case "rate_limiter":
		if rc, ok := s.mainConfig.RateLimiterPluginConfig.(*config.RateLimiterPluginConfig); ok && rc != nil {
			rc.Enabled = enabled
		} else {
			s.mainConfig.RateLimiterPluginConfig = &config.RateLimiterPluginConfig{Enabled: enabled}
		}

	case "clamav":
		if s.mainConfig.Antivirus == nil {
			s.mainConfig.Antivirus = &ScannerStatus{}
		}
		s.mainConfig.Antivirus.Enabled = enabled
		appliesOnReload = true

	case "rspamd":
		if s.mainConfig.Antispam == nil {
			s.mainConfig.Antispam = &ScannerStatus{}
		}
		s.mainConfig.Antispam.Enabled = enabled
		appliesOnReload = true

	case "access_control":
		if s.mainConfig.AccessControl == nil {
			s.mainConfig.AccessControl = &AccessControlStatus{}
		}
		s.mainConfig.AccessControl.Enabled = enabled
		appliesOnReload = true

	case "rbl":
		if s.mainConfig.RBL == nil {
			s.mainConfig.RBL = &RBLStatus{}
		}
		// Enabled with nothing to query is a filter the operator believes is
		// protecting them — and it is what the SMTP server refuses to start
		// with, so accepting it here would turn a form error into a server that
		// does not come back up.
		if enabled && len(s.mainConfig.RBL.Zones) == 0 {
			http.Error(w, "Add at least one blocklist zone before enabling this plugin", http.StatusBadRequest)
			return
		}
		s.mainConfig.RBL.Enabled = enabled
		appliesOnReload = true

	case "mass_mailer":
		if s.mainConfig.MassMailer == nil {
			s.mainConfig.MassMailer = &MassMailerStatus{}
		}
		// The campaign store and runner live in this process, so this toggle
		// can take effect now. Turning it off with a send in flight would
		// abandon a partly-delivered campaign, so that is refused rather than
		// done quietly.
		if err := s.setMassMailerEnabled(enabled); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		s.mainConfig.MassMailer.Enabled = enabled

	default:
		http.Error(w, fmt.Sprintf("Unknown plugin %q", pluginName), http.StatusBadRequest)
		return
	}

	// A toggle that cannot be written down is not a toggle: report the failure
	// rather than returning success for a change that will not survive.
	if err := s.persistConfig(); err != nil {
		slog.Error("Failed to persist plugin change", "plugin", pluginName, "error", err)
		http.Error(w, fmt.Sprintf("Failed to save configuration: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"plugin":  pluginName,
		"enabled": enabled,
		// requires_restart is the operator taking the server down.
		// applies_on_reload is the SMTP server picking the change up on its
		// own, without dropping connections.
		"requires_restart":  requiresRestart,
		"applies_on_reload": appliesOnReload,
		"message": fmt.Sprintf("%s %s", pluginName,
			map[bool]string{true: "enabled", false: "disabled"}[enabled]),
	}
	// Saying "saved" about a file that will not be read again is worse than
	// saying nothing. Deployments that stage the config into a private copy —
	// which the containers do, because the server refuses a world-readable
	// config — write to that copy, and the change is gone at the next start.
	if warning := nonDurableConfigWarning(s.configPath); warning != "" {
		response["persistent"] = false
		response["warning"] = warning
	} else {
		response["persistent"] = true
	}
	writeJSON(w, response)
}

// nonDurableConfigWarning reports that the config being written is a staging
// copy rather than the file the server will read next time, and returns "" when
// the write is durable.
func nonDurableConfigWarning(path string) string {
	if path == "" {
		return "No configuration file is known, so this change exists only in memory."
	}
	dir := filepath.Dir(path)
	if dir == os.TempDir() || strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") {
		return fmt.Sprintf("Saved to %s, which is a temporary copy of the configuration. "+
			"The change will be lost when the service restarts — edit the real config file, "+
			"or give the service write access to it.", path)
	}
	return ""
}

// handleServerRestart initiates a graceful zero-downtime restart using listener handoff.
func (s *Server) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	if !s.restarting.CompareAndSwap(false, true) {
		http.Error(w, "Restart already in progress", http.StatusConflict)
		return
	}

	process, err := s.startReplacementProcess()
	if err != nil {
		s.restarting.Store(false)
		http.Error(w, fmt.Sprintf("Failed to start replacement process: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":       "success",
		"message":      "Graceful restart initiated",
		"new_pid":      process.Pid,
		"drain_period": "existing requests will drain before shutdown",
	})

	// Flush response before shutting down
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Shutdown current process after response is delivered.
	go func() {
		time.Sleep(500 * time.Millisecond)
		slog.Info("Restart requested via web UI, draining old API process", "new_pid", process.Pid)
		if err := s.Stop(); err != nil {
			slog.Error("Failed to gracefully stop old API process", "error", err)
			if killErr := syscall.Kill(os.Getpid(), syscall.SIGTERM); killErr != nil {
				slog.Error("Failed to forcefully terminate old API process", "error", killErr)
			}
			return
		}

		os.Exit(0)
	}()
}

// Helper functions

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
	}
}

// parseQueueType converts a string to a QueueType
func parseQueueType(qType string) (queue.QueueType, error) {
	qType = strings.ToLower(qType)

	switch qType {
	case "active":
		return queue.Active, nil
	case "deferred":
		return queue.Deferred, nil
	case "hold":
		return queue.Hold, nil
	case "failed":
		return queue.Failed, nil
	default:
		return "", fmt.Errorf("invalid queue type: %s", qType)
	}
}

// isAdmin checks if the user has admin permissions
func (s *Server) isAdmin(authCtx *AuthContext) bool {
	for _, perm := range authCtx.Permissions {
		if perm == auth.PermissionSystemAdmin {
			return true
		}
	}
	return false
}

func (s *Server) validateRequestedAPIKeyPermissions(authCtx *AuthContext, requested []auth.Permission) error {
	if authCtx == nil {
		return fmt.Errorf("not authenticated")
	}
	if s.isAdmin(authCtx) {
		return nil
	}

	allowed := make(map[auth.Permission]struct{}, len(authCtx.Permissions))
	for _, permission := range authCtx.Permissions {
		allowed[permission] = struct{}{}
	}
	for _, permission := range requested {
		if _, ok := allowed[permission]; !ok {
			return fmt.Errorf("cannot grant API key permission %q", permission)
		}
	}
	return nil
}

func isAllowedLogPath(path string) bool {
	allowedFiles := map[string]struct{}{
		"elemta.log":      {},
		"smtp.log":        {},
		"queue.log":       {},
		"application.log": {},
	}

	base := filepath.Base(path)
	if _, ok := allowedFiles[base]; !ok {
		return false
	}

	cleanPath := filepath.Clean(path)
	allowedDirs := []string{
		"/app/logs",
		"./logs",
		"logs",
		filepath.Clean(runtimepaths.Detect().LogDir),
	}

	for _, dir := range allowedDirs {
		cleanDir := filepath.Clean(dir)
		if cleanPath == filepath.Join(cleanDir, base) {
			return true
		}
	}

	return false
}

func sanitizeForLog(value string) string {
	replacer := strings.NewReplacer("\n", "", "\r", "", "\t", " ")
	return replacer.Replace(value)
}

// Regex patterns for SMTP code detection
var (
	smtp5xxPattern = regexp.MustCompile(`\b5[0-9]{2}\b`)
	smtp4xxPattern = regexp.MustCompile(`\b4[0-9]{2}\b`)
)

// categorizeLogEntry determines the event_type for a log entry based on its content
// This ensures 5xx errors are categorized as rejection and 4xx as tempfail/deferral
func categorizeLogEntry(logEntry map[string]interface{}, msg string) string {
	msgLower := strings.ToLower(msg)

	// Check log level first - INFO level messages should not be categorized as rejection/tempfail
	if level, ok := logEntry["level"].(string); ok {
		if level == "INFO" || level == "DEBUG" {
			// INFO and DEBUG messages are system events unless they contain explicit rejection keywords
			systemKeywords := []string{
				"plugin", "enabled", "initialized", "started", "stopped",
				"configuration", "loading", "loaded", "shutdown",
			}
			for _, keyword := range systemKeywords {
				if strings.Contains(msgLower, keyword) {
					return "system"
				}
			}
			// Default INFO/DEBUG to system unless clearly a rejection
			return "system"
		}
	}

	// 1. Check for spam_score field (content-based rejection)
	if spamScore, ok := logEntry["spam_score"].(float64); ok && spamScore > 0 {
		return "rejection"
	}

	// 2. Check for threats field (virus/content rejection)
	if _, ok := logEntry["threats"]; ok {
		return "rejection"
	}

	// 3. Check for virus_found field
	if virusFound, ok := logEntry["virus_found"].(bool); ok && virusFound {
		return "rejection"
	}

	// 4. Scan ALL string fields for SMTP 5xx codes (permanent failures)
	for _, v := range logEntry {
		if str, ok := v.(string); ok {
			if smtp5xxPattern.MatchString(str) {
				return "rejection"
			}
		}
	}

	// 5. Scan ALL string fields for SMTP 4xx codes (temporary failures)
	for _, v := range logEntry {
		if str, ok := v.(string); ok {
			if smtp4xxPattern.MatchString(str) {
				return "tempfail"
			}
		}
	}

	// 6. Check for rejection keywords in message (fallback after SMTP codes)
	rejectionKeywords := []string{
		"rejected", "virus", "spam", "blocked", "denied", "refused",
		"malware", "threat", "infected", "banned", "blacklist",
	}
	for _, keyword := range rejectionKeywords {
		if strings.Contains(msgLower, keyword) {
			return "rejection"
		}
	}

	// 7. Check for tempfail/deferral keywords in message (fallback after SMTP codes)
	tempfailKeywords := []string{
		"deferred", "retry", "temporary", "tempfail", "greylisted",
		"try again", "later", "busy", "throttled", "rate limit",
	}
	for _, keyword := range tempfailKeywords {
		if strings.Contains(msgLower, keyword) {
			return "tempfail"
		}
	}

	// 8. Check for delivery/bounce status fields
	if status, ok := logEntry["status"].(string); ok {
		statusLower := strings.ToLower(status)
		if statusLower == "rejected" || statusLower == "bounced" {
			return "rejection"
		}
		if statusLower == "deferred" || statusLower == "temporary_failure" {
			return "tempfail"
		}
	}

	// Default: remain as system/empty (will be filtered appropriately)
	return ""
}
