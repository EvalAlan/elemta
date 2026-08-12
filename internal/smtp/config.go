package smtp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/busybox42/elemta/internal/dkim"
)

// Config represents the main configuration for the SMTP server
type Config struct {
	ListenAddr    string   `toml:"listen_addr" json:"listen_addr"`
	QueueDir      string   `toml:"queue_dir" json:"queue_dir"`
	QueueBackend  string   `toml:"queue_backend" json:"queue_backend"` // file|sqlite|postgres|indexedfs
	MaxSize       int64    `toml:"max_size" json:"max_size"`
	DevMode       bool     `toml:"dev_mode" json:"dev_mode"`
	AllowedRelays []string `toml:"allowed_relays" json:"allowed_relays"`
	LocalDomains  []string `toml:"local_domains" json:"local_domains"`
	Hostname      string   `toml:"hostname" json:"hostname"`
	MaxWorkers    int      `toml:"max_workers" json:"max_workers"`
	MaxRetries    int      `toml:"max_retries" json:"max_retries"`
	MaxQueueTime  int      `toml:"max_queue_time" json:"max_queue_time"`
	RetrySchedule []int    `toml:"retry_schedule" json:"retry_schedule"`

	// SQLite queue backend configuration (used when QueueBackend=sqlite)
	QueueSQLite QueueSQLiteConfig `toml:"queue_sqlite" json:"queue_sqlite"`

	// PostgreSQL queue backend configuration (used when QueueBackend=postgres)
	QueuePostgres QueuePostgresConfig `toml:"queue_postgres" json:"queue_postgres"`

	// Indexed filesystem queue backend configuration (used when QueueBackend=indexedfs)
	QueueIndexedFS QueueIndexedFSConfig `toml:"queue_indexedfs" json:"queue_indexedfs"`

	// Queue management options
	KeepDeliveredMessages     bool `toml:"keep_delivered_messages" json:"keep_delivered_messages"`           // Whether to keep delivered messages for archiving
	KeepMessageData           bool `toml:"keep_message_data" json:"keep_message_data"`                       // Whether to keep message data after delivery
	FailedQueueRetentionHours int  `toml:"failed_queue_retention_hours" json:"failed_queue_retention_hours"` // 0 = immediate deletion
	QueuePriorityEnabled      bool `toml:"queue_priority_enabled" json:"queue_priority_enabled"`             // Whether to enable queue prioritization
	QueueWorkers              int  `toml:"queue_workers" json:"queue_workers"`                               // Number of queue worker goroutines
	MessageRetentionHours     int  `toml:"message_retention_hours" json:"message_retention_hours"`           // How long to keep messages before expiry
	ConnectTimeout            int  `toml:"connect_timeout" json:"connect_timeout"`                           // Timeout for connecting to remote servers
	SMTPTimeout               int  `toml:"smtp_timeout" json:"smtp_timeout"`                                 // Timeout for SMTP operations
	MaxConnectionsPerDomain   int  `toml:"max_connections_per_domain" json:"max_connections_per_domain"`     // Maximum concurrent connections per domain

	// Queue processor options
	QueueProcessorEnabled bool `toml:"queue_processor_enabled" json:"queue_processor_enabled"` // Whether queue processing is enabled
	QueueProcessInterval  int  `toml:"queue_process_interval" json:"queue_process_interval"`   // How often to process the queue in seconds

	// Authentication configuration
	Auth *AuthConfig `toml:"auth" json:"auth"`

	// TLS configuration
	TLS *TLSConfig `toml:"tls" json:"tls"`

	// Resource limits
	Resources *ResourceConfig `toml:"resources" json:"resources"`

	// Caching configuration
	Cache *CacheConfig `toml:"cache" json:"cache"`

	// Antivirus configuration
	Antivirus *AntivirusConfig `toml:"antivirus" json:"antivirus"`

	// AccessControl holds the allow/deny lists applied at connect and MAIL FROM.
	AccessControl *AccessControlConfig `toml:"access_control" json:"access_control"`

	// RBL holds the DNS blocklists consulted for the connecting address.
	RBL *RBLConfig `toml:"rbl" json:"rbl"`

	// InboundAuth holds SPF/DKIM/DMARC verification of arriving mail.
	InboundAuth *InboundAuthConfig `toml:"inbound_auth" json:"inbound_auth"`

	// Rules configuration
	Rules *RulesConfig `toml:"rules" json:"rules"`

	// Antispam configuration
	Antispam *AntispamConfig `toml:"antispam" json:"antispam"`

	// Plugin configuration
	Plugins *PluginConfig `toml:"plugins" json:"plugins"`

	// Metrics configuration
	Metrics *MetricsConfig `toml:"metrics" json:"metrics"`

	// API server configuration
	API *APIConfig `toml:"api" json:"api"`

	// Delivery configuration
	Delivery *DeliveryConfig `toml:"delivery" json:"delivery"`

	// DKIM outbound signing configuration
	DKIM *dkim.Config `toml:"dkim" json:"dkim"`

	// Memory management configuration
	Memory *MemoryConfig `toml:"memory" json:"memory"`

	// Timeout configuration for context propagation
	Timeouts TimeoutConfig `toml:"timeouts" json:"timeouts"`

	SessionTimeout time.Duration `yaml:"session_timeout" toml:"session_timeout"` // Deprecated: Use Timeouts.SessionTimeout

	// TrustedNetworks lists the CIDRs whose peers are treated as internal and
	// given the permissive content-validation path. Unset uses the built-in
	// private ranges; an explicitly empty list trusts nothing, which is how a
	// test exercises the external path from loopback.
	TrustedNetworks []string `toml:"trusted_networks" json:"trusted_networks"`

	// trustedNets is TrustedNetworks resolved by ApplyDefaults.
	trustedNets []*net.IPNet

	// SpoolThresholdBytes is the size above which message data is written to a
	// spool file instead of being held in memory. Unset means
	// DefaultSpoolThreshold; a negative value keeps every message in memory,
	// which is the behaviour that predates spooling.
	SpoolThresholdBytes *int64 `toml:"spool_threshold_bytes" json:"spool_threshold_bytes"`

	// RFC 5321 compliance settings
	// StrictLineEndings enforces RFC 5321 CRLF requirements. It is a pointer so
	// that "unset" is distinguishable from an explicit false; ApplyDefaults
	// resolves nil to true. Read it through StrictLineEndingsEnabled().
	StrictLineEndings *bool `toml:"strict_line_endings" json:"strict_line_endings"`
}

// TimeoutConfig contains hierarchical timeout settings for context propagation
type TimeoutConfig struct {
	// Session timeout for SMTP sessions
	SessionTimeout time.Duration `toml:"session_timeout" json:"session_timeout"`

	// Command timeout for individual SMTP commands
	CommandTimeout time.Duration `toml:"command_timeout" json:"command_timeout"`

	// Data timeout for DATA command (longer due to message content)
	DataTimeout time.Duration `toml:"data_timeout" json:"data_timeout"`

	// Shutdown timeout for graceful server shutdown
	ShutdownTimeout time.Duration `toml:"shutdown_timeout" json:"shutdown_timeout"`

	// Connection timeout for establishing connections
	ConnectionTimeout time.Duration `toml:"connection_timeout" json:"connection_timeout"`

	// Authentication timeout for auth processes
	AuthTimeout time.Duration `toml:"auth_timeout" json:"auth_timeout"`
}

// QueueSQLiteConfig represents sqlite queue backend configuration.
type QueueSQLiteConfig struct {
	Path          string `toml:"path" json:"path"`
	BusyTimeoutMS int    `toml:"busy_timeout_ms" json:"busy_timeout_ms"`
	JournalMode   string `toml:"journal_mode" json:"journal_mode"`
	Synchronous   string `toml:"synchronous" json:"synchronous"`
}

// QueuePostgresConfig represents postgres queue backend configuration.
type QueuePostgresConfig struct {
	DSN                    string `toml:"dsn" json:"dsn"`
	MaxOpenConns           int    `toml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns           int    `toml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetimeSeconds int    `toml:"conn_max_lifetime_seconds" json:"conn_max_lifetime_seconds"`
}

// QueueIndexedFSConfig represents indexedfs queue backend configuration.
type QueueIndexedFSConfig struct {
	IndexPath         string `toml:"index_path" json:"index_path"`
	ContentDir        string `toml:"content_dir" json:"content_dir"`
	SyncMode          string `toml:"sync_mode" json:"sync_mode"`
	RecoveryOnStartup bool   `toml:"recovery_on_startup" json:"recovery_on_startup"`
}

// DeliveryConfig represents configuration for message delivery
type DeliveryConfig struct {
	// MaxMessagesPerMinutePerDomain caps the send rate to a single destination.
	// Zero means no limit, which is right for most deployments: the backoff
	// below reacts to what a destination actually asks for, whereas a rate
	// invented in advance slows everyone including receivers happy to take more.
	MaxMessagesPerMinutePerDomain int `toml:"max_messages_per_minute_per_domain" json:"max_messages_per_minute_per_domain"`

	Mode          string `toml:"mode" json:"mode"`                     // Delivery mode (smtp, lmtp, etc.)
	Host          string `toml:"host" json:"host"`                     // Host to deliver to
	Port          int    `toml:"port" json:"port"`                     // Port to deliver to
	Timeout       int    `toml:"timeout" json:"timeout"`               // Timeout for delivery operations
	MaxRetries    int    `toml:"max_retries" json:"max_retries"`       // Maximum number of delivery retries
	RetryDelay    int    `toml:"retry_delay" json:"retry_delay"`       // Delay between retries in seconds
	TestMode      bool   `toml:"test_mode" json:"test_mode"`           // Whether to use test mode delivery
	DefaultDomain string `toml:"default_domain" json:"default_domain"` // Default domain for local delivery
	Debug         bool   `toml:"debug" json:"debug"`                   // Enable debug logging for delivery
}

// MetricsConfig represents the configuration for metrics collection
type MetricsConfig struct {
	Enabled    bool   `toml:"enabled" json:"enabled"`         // Whether metrics collection is enabled
	ListenAddr string `toml:"listen_addr" json:"listen_addr"` // Address to listen on for metrics HTTP server
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled             bool   `json:"enabled" toml:"enabled"`
	Required            bool   `json:"required" toml:"required"`
	AllowDeprecatedSHA1 *bool  `json:"allow_deprecated_sha1,omitempty" toml:"allow_deprecated_sha1"`
	DataSourceType      string `json:"datasource_type" toml:"datasource_type"`
	DataSourceName      string `json:"datasource_name" toml:"datasource_name"`
	DataSourcePath      string `json:"datasource_path" toml:"datasource_path"`
	DataSourceHost      string `json:"datasource_host" toml:"datasource_host"`
	DataSourcePort      int    `json:"datasource_port" toml:"datasource_port"`
	DataSourceUser      string `json:"datasource_user" toml:"datasource_user"`
	DataSourcePass      string `json:"datasource_pass" toml:"datasource_pass"`
	DataSourceDB        string `json:"datasource_db" toml:"datasource_db"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled        bool               `yaml:"enabled" toml:"enabled"`
	ListenAddr     string             `yaml:"listen_addr" toml:"listen_addr"`
	CertFile       string             `yaml:"cert_file" toml:"cert_file"`
	KeyFile        string             `yaml:"key_file" toml:"key_file"`
	LetsEncrypt    *LetsEncryptConfig `yaml:"letsencrypt" toml:"letsencrypt"`
	MinVersion     string             `yaml:"min_version" toml:"min_version"`
	MaxVersion     string             `yaml:"max_version" toml:"max_version"`
	Ciphers        []string           `yaml:"ciphers" toml:"ciphers"`
	Curves         []string           `yaml:"curves" toml:"curves"`
	ClientAuth     string             `yaml:"client_auth" toml:"client_auth"`
	RenewalConfig  *CertRenewalConfig `yaml:"renewal" toml:"renewal"`
	EnableStartTLS bool               `yaml:"enable_starttls" toml:"enable_starttls"` // Enable STARTTLS on standard ports
}

// LetsEncryptConfig represents Let's Encrypt configuration
type LetsEncryptConfig struct {
	Enabled  bool   `yaml:"enabled" toml:"enabled"`
	Domain   string `yaml:"domain" toml:"domain"`
	Email    string `yaml:"email" toml:"email"`
	CacheDir string `yaml:"cache_dir" toml:"cache_dir"`
	Staging  bool   `yaml:"staging" toml:"staging"`
}

// CertRenewalConfig represents certificate renewal configuration
type CertRenewalConfig struct {
	AutoRenew    bool `yaml:"auto_renew" toml:"auto_renew"`
	RenewalDays  int  `yaml:"renewal_days" toml:"renewal_days"` // Renew this many days before expiration
	ForceRenewal bool `yaml:"force_renewal" toml:"force_renewal"`

	// Seconds-valued TOML forms. These are ints rather than time.Duration
	// because pelletier/go-toml (used by internal/config, the path the server
	// takes) cannot decode a duration string, and decodes a bare integer as
	// nanoseconds. See MemoryConfig.MonitoringIntervalSeconds.
	CheckIntervalSeconds  int `yaml:"check_interval_seconds" toml:"check_interval"`
	RenewalTimeoutSeconds int `yaml:"renewal_timeout_seconds" toml:"renewal_timeout"`

	// Resolved runtime values, derived by ApplyDefaults.
	CheckInterval  time.Duration `yaml:"-" toml:"-"`
	RenewalTimeout time.Duration `yaml:"-" toml:"-"`
}

// ApplyDefaults resolves the seconds-valued TOML fields into durations and
// fills in defaults for anything unset.
func (c *CertRenewalConfig) ApplyDefaults() {
	if c.CheckIntervalSeconds > 0 {
		c.CheckInterval = time.Duration(c.CheckIntervalSeconds) * time.Second
	}
	if c.CheckInterval <= 0 {
		c.CheckInterval = 24 * time.Hour
	}
	c.CheckIntervalSeconds = int(c.CheckInterval / time.Second)

	if c.RenewalTimeoutSeconds > 0 {
		c.RenewalTimeout = time.Duration(c.RenewalTimeoutSeconds) * time.Second
	}
	if c.RenewalTimeout <= 0 {
		c.RenewalTimeout = 5 * time.Minute
	}
	c.RenewalTimeoutSeconds = int(c.RenewalTimeout / time.Second)

	if c.RenewalDays <= 0 {
		c.RenewalDays = 30
	}
}

// ResourceConfig represents resource limits
type ResourceConfig struct {
	MaxCPU               int    `json:"max_cpu" toml:"max_cpu"`
	MaxMemory            int64  `json:"max_memory" toml:"max_memory"`
	MaxConnections       int    `json:"max_connections" toml:"max_connections"`
	MaxConnectionsPerIP  int    `json:"max_connections_per_ip" toml:"max_connections_per_ip"`
	MaxConcurrent        int    `json:"max_concurrent" toml:"max_concurrent"`
	ConnectionTimeout    int    `json:"connection_timeout" toml:"connection_timeout"`
	ReadTimeout          int    `json:"read_timeout" toml:"read_timeout"`
	WriteTimeout         int    `json:"write_timeout" toml:"write_timeout"`
	ValkeyURL            string `json:"valkey_url" toml:"valkey_url"`
	ValkeyKeyPrefix      string `json:"valkey_key_prefix" toml:"valkey_key_prefix"`
	SessionTimeout       int    `json:"session_timeout" toml:"session_timeout"`
	IdleTimeout          int    `json:"idle_timeout" toml:"idle_timeout"`
	GoroutinePoolSize    int    `json:"goroutine_pool_size" toml:"goroutine_pool_size"`
	MaxMemoryUsage       int64  `json:"max_memory_usage" toml:"max_memory_usage"`
	RateLimitWindow      int    `json:"rate_limit_window" toml:"rate_limit_window"`
	MaxRequestsPerWindow int    `json:"max_requests_per_window" toml:"max_requests_per_window"`
}

// CacheConfig represents caching configuration
type CacheConfig struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Password string `json:"password"`
	Database int    `json:"database"`
	MaxItems int    `json:"max_items"`
	MaxSize  int64  `json:"max_size"`
	TTL      int    `json:"ttl"`
}

// AccessControlConfig holds operator-maintained allow and deny lists.
//
// Separate from trusted_networks on purpose: that decides how strictly a peer's
// content is validated, this decides whether the peer may connect at all.
//
// Allow beats deny, so a known-good host inside a denied range can be permitted
// without restating the range.
type AccessControlConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// AllowIPs and DenyIPs accept CIDR ranges and bare addresses.
	AllowIPs []string `toml:"allow_ips" json:"allow_ips"`
	DenyIPs  []string `toml:"deny_ips" json:"deny_ips"`
	// AllowDomains and DenyDomains match the MAIL FROM domain and its
	// subdomains, so "example.com" also covers "mail.example.com".
	AllowDomains []string `toml:"allow_domains" json:"allow_domains"`
	DenyDomains  []string `toml:"deny_domains" json:"deny_domains"`
}

// InboundAuthConfig configures verification of who a message claims to be from.
type InboundAuthConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// EnforceDMARC honours a sending domain's published policy. Off by default:
	// the first thing enforcement does on a real server is reject mail from
	// forwarders and mailing lists, which break SPF alignment by design, so the
	// results should be watched before they are acted on.
	EnforceDMARC bool `toml:"enforce_dmarc" json:"enforce_dmarc"`
	// Timeout bounds the DNS work for one message, in seconds. Verification
	// happens while a client waits at end-of-DATA.
	Timeout int `toml:"timeout" json:"timeout"`
}

// RBLConfig configures DNS blocklist checks on the connecting address.
type RBLConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// Zones are the blocklists to query, e.g. "zen.spamhaus.org". They are
	// queried concurrently and one listing is enough.
	Zones []string `toml:"zones" json:"zones"`
	// Reject decides whether a listing refuses the message or only adds a
	// header. Tagging first is what makes a new blocklist safe to try: the
	// operator can see what it would have refused before letting it.
	Reject bool `toml:"reject" json:"reject"`
	// Timeout bounds the whole check in seconds, not each zone.
	Timeout int `toml:"timeout" json:"timeout"`
	// SkipIPs are addresses and ranges never looked up: relays, monitoring,
	// the operator's own networks.
	SkipIPs []string `toml:"skip_ips" json:"skip_ips"`
	// CacheTTL and CacheSize bound the answer cache. It has to be bounded:
	// keyed by peer address and left to grow, it is a memory exhaustion vector.
	CacheTTL  int `toml:"cache_ttl" json:"cache_ttl"`
	CacheSize int `toml:"cache_size" json:"cache_size"`
}

// AntivirusConfig represents antivirus configuration
type AntivirusConfig struct {
	Enabled         bool          `toml:"enabled" json:"enabled"`
	RejectOnFailure bool          `toml:"reject_on_failure" json:"reject_on_failure"`
	ClamAV          *ClamAVConfig `toml:"clamav" json:"clamav"`
}

// ClamAVConfig represents ClamAV configuration
//
// The toml tags are load-bearing. Without them neither decoder matches
// `scan_limit` to ScanLimit — single-word keys resolve case-insensitively
// against the field name, but underscored ones do not — so the setting was
// accepted and silently ignored.
type ClamAVConfig struct {
	Enabled   bool   `toml:"enabled" json:"enabled"`
	Address   string `toml:"address" json:"address"`
	Timeout   int    `toml:"timeout" json:"timeout"`
	ScanLimit int64  `toml:"scan_limit" json:"scan_limit"`
}

// AntispamConfig represents antispam configuration
type AntispamConfig struct {
	Enabled      bool                `toml:"enabled" json:"enabled"`
	RejectOnSpam bool                `toml:"reject_on_spam" json:"reject_on_spam"`
	SpamAssassin *SpamAssassinConfig `toml:"spamassassin" json:"spamassassin"`
	Rspamd       *RspamdConfig       `toml:"rspamd" json:"rspamd"`
}

// SpamAssassinConfig represents SpamAssassin configuration
type SpamAssassinConfig struct {
	Enabled   bool    `toml:"enabled" json:"enabled"`
	Address   string  `toml:"address" json:"address"`
	Timeout   int     `toml:"timeout" json:"timeout"`
	ScanLimit int64   `toml:"scan_limit" json:"scan_limit"`
	Threshold float64 `toml:"threshold" json:"threshold"`
}

// RspamdConfig represents Rspamd configuration
type RspamdConfig struct {
	Enabled   bool    `toml:"enabled" json:"enabled"`
	Address   string  `toml:"address" json:"address"`
	Timeout   int     `toml:"timeout" json:"timeout"`
	ScanLimit int64   `toml:"scan_limit" json:"scan_limit"`
	Threshold float64 `toml:"threshold" json:"threshold"`
	APIKey    string  `toml:"api_key" json:"api_key"`
}

// RulesConfig represents rules configuration
type RulesConfig struct {
	Enabled       bool   `json:"enabled"`
	Path          string `json:"path"`
	DefaultAction string `json:"default_action"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled    bool     `toml:"enabled" json:"enabled"`
	PluginPath string   `toml:"directory" json:"plugin_path"`
	Plugins    []string `toml:"enabled_plugins" json:"plugins"`

	// Mail authentication is implemented by built-in plugins. Keeping these
	// typed here, beside the external-plugin loader settings, lets the SMTP and
	// web processes decode exactly the same [plugins.*] tables without relying
	// on map[string]interface{} or silently losing underscored TOML keys.
	SPF   *SPFPluginConfig   `toml:"spf" json:"spf,omitempty"`
	DKIM  *DKIMPluginConfig  `toml:"dkim" json:"dkim,omitempty"`
	DMARC *DMARCPluginConfig `toml:"dmarc" json:"dmarc,omitempty"`
	ARC   *ARCPluginConfig   `toml:"arc" json:"arc,omitempty"`
}

// SPFPluginConfig controls envelope-sender SPF verification.
type SPFPluginConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	Timeout int  `toml:"timeout" json:"timeout"`
}

// DKIMPluginConfig controls inbound verification and outbound signing. Signing
// domains deliberately reuse the proven outbound DKIM configuration shape.
type DKIMPluginConfig struct {
	Enabled                bool                `toml:"enabled" json:"enabled"`
	Verify                 bool                `toml:"verify" json:"verify"`
	Sign                   bool                `toml:"sign" json:"sign"`
	HeaderCanonicalization string              `toml:"header_canonicalization" json:"header_canonicalization"`
	BodyCanonicalization   string              `toml:"body_canonicalization" json:"body_canonicalization"`
	Domains                []dkim.DomainConfig `toml:"domains" json:"domains"`
}

// SigningConfig returns the outbound signer's existing configuration format.
func (c *DKIMPluginConfig) SigningConfig() *dkim.Config {
	if c == nil || !c.Enabled || !c.Sign {
		return nil
	}
	return &dkim.Config{
		Enabled:                true,
		HeaderCanonicalization: c.HeaderCanonicalization,
		BodyCanonicalization:   c.BodyCanonicalization,
		Domains:                append([]dkim.DomainConfig(nil), c.Domains...),
	}
}

// DMARCPluginConfig controls alignment evaluation and optional policy action.
type DMARCPluginConfig struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	Enforce bool `toml:"enforce" json:"enforce"`
	Timeout int  `toml:"timeout" json:"timeout"`
}

// ARCPluginConfig controls RFC 8617 chain verification and outbound sealing.
// Sealing is RSA-only because ARC-Seal is defined only for rsa-sha256.
type ARCPluginConfig struct {
	Enabled                bool     `toml:"enabled" json:"enabled"`
	Verify                 bool     `toml:"verify" json:"verify"`
	Seal                   bool     `toml:"seal" json:"seal"`
	Domain                 string   `toml:"domain" json:"domain"`
	Selector               string   `toml:"selector" json:"selector"`
	PrivateKeyPath         string   `toml:"private_key_path" json:"private_key_path,omitempty"`
	HeaderCanonicalization string   `toml:"header_canonicalization" json:"header_canonicalization"`
	BodyCanonicalization   string   `toml:"body_canonicalization" json:"body_canonicalization"`
	HeadersToSign          []string `toml:"headers_to_sign" json:"headers_to_sign"`
	Timeout                int      `toml:"timeout" json:"timeout"`
}

// DeliveryModes are the delivery modes the server can actually run.
//
// One list, because there used to be two. The runtime switch in initQueueSystem
// accepted smtp and lmtp while the config validator accepted smtp, lmtp and
// local, so "local" passed validation and then failed at startup with a
// different error, and a mode added to the runtime was rejected before it ever
// got there. A mode belongs here and nowhere else; the validator reads it.
var DeliveryModes = []string{"lmtp", "smtp", "split"}

// APIConfig represents the configuration for the API server
type APIConfig struct {
	Enabled    bool   `toml:"enabled" json:"enabled"`         // Whether API server is enabled
	ListenAddr string `toml:"listen_addr" json:"listen_addr"` // Address to listen on for API server
}

func findConfigFile(configPath string) (string, error) {
	if configPath != "" {
		// #nosec G703 -- explicit config path is operator-provided CLI/env input
		if _, err := os.Stat(configPath); err == nil {
			// Informational: config file found at explicit path
			return configPath, nil
		}
		return "", fmt.Errorf("config file not found at %s", configPath)
	}

	searchPaths := []string{
		"./elemta.conf",
		"./config/elemta.conf",
		"../config/elemta.conf",
		os.ExpandEnv("$HOME/.elemta.conf"),
		"/etc/elemta/elemta.conf",
	}

	for _, path := range searchPaths {
		// Checking for config file in search paths
		if _, err := os.Stat(path); err == nil {
			// Config file found in search path
			return path, nil
		}
	}

	fmt.Println("No config file found, using defaults")
	return "", fmt.Errorf("no config file found in search paths")
}

func LoadConfig(configPath string) (*Config, error) {
	// Check for environment variable if configPath is empty
	if configPath == "" {
		envPath := os.Getenv("ELEMTA_CONFIG_PATH")
		if envPath != "" {
			configPath = envPath
		}
	}

	path, err := findConfigFile(configPath)
	if err != nil {
		return DefaultConfig(), nil
	}

	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid config file path: path traversal attempt detected")
	}

	// Path was normalized/checked before use.
	data, err := os.ReadFile(path) // #nosec G304,G703 -- operator-provided config path, validated for traversal
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if _, err := toml.Decode(string(data), &config); err != nil {
		// Try JSON as fallback
		if jsonErr := json.Unmarshal(data, &config); jsonErr != nil {
			return nil, fmt.Errorf("error parsing config (tried TOML and JSON): %w", err)
		}
	}

	config.ApplyDefaults()

	if err := os.MkdirAll(config.QueueDir, 0750); err != nil {
		return nil, err
	}

	return &config, nil
}

// ApplyDefaults fills in default values for any unset configuration fields.
// It is shared by LoadConfig and by callers that construct a Config from the
// top-level elemta configuration, so both paths get identical defaults.
func (c *Config) ApplyDefaults() {
	if c.Hostname == "" {
		hostname, err := os.Hostname()
		if err == nil {
			c.Hostname = hostname
		} else {
			c.Hostname = "localhost.localdomain"
		}
	}

	if c.ListenAddr == "" {
		c.ListenAddr = ":2525"
	}
	if c.QueueDir == "" {
		c.QueueDir = "./queue"
	}
	if c.MaxSize == 0 {
		c.MaxSize = 50 * 1024 * 1024 // 50MB - increased default
	}
	if c.MaxWorkers == 0 {
		c.MaxWorkers = 10
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 10
	}
	if c.MaxQueueTime == 0 {
		c.MaxQueueTime = 172800
	}
	if len(c.RetrySchedule) == 0 {
		c.RetrySchedule = []int{60, 300, 900, 3600, 10800, 21600, 43200}
	}

	// Set default TLS configuration if not provided
	if c.TLS == nil {
		c.TLS = &TLSConfig{
			Enabled:       false,
			ListenAddr:    ":2465",
			MinVersion:    "tls1.2",
			RenewalConfig: &CertRenewalConfig{AutoRenew: true},
		}
	}
	if c.TLS.RenewalConfig == nil {
		c.TLS.RenewalConfig = &CertRenewalConfig{AutoRenew: true}
	}
	// Resolves the seconds-valued TOML fields into durations.
	c.TLS.RenewalConfig.ApplyDefaults()

	// Set default authentication configuration if not provided
	if c.Auth == nil {
		c.Auth = &AuthConfig{
			Enabled:        false,
			Required:       false,
			DataSourceType: "sqlite",
			DataSourcePath: "./elemta.db",
		}
	}

	// Set default resource configuration if not provided
	if c.Resources == nil {
		c.Resources = &ResourceConfig{
			MaxCPU:            0, // Use all available CPUs
			MaxMemory:         0, // No memory limit
			MaxConnections:    1000,
			MaxConcurrent:     100,
			ConnectionTimeout: 60,
			ReadTimeout:       60,
			WriteTimeout:      60,
		}
	}

	// Set default cache configuration if not provided
	if c.Cache == nil {
		c.Cache = &CacheConfig{
			Enabled:  false,
			Type:     "memory",
			MaxItems: 10000,
			MaxSize:  100 * 1024 * 1024, // 100 MB
			TTL:      3600,              // 1 hour
		}
	}

	// Set default antivirus configuration if not provided
	if c.Antivirus == nil {
		enabled := true
		if os.Getenv("ELEMTA_DISABLE_CLAMAV") == "true" {
			enabled = false
		}
		c.Antivirus = &AntivirusConfig{
			Enabled:         enabled,
			RejectOnFailure: false,
			ClamAV: &ClamAVConfig{
				Enabled:   enabled,
				Address:   "localhost:3310",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
			},
		}
	}

	// Set default antispam configuration if not provided
	if c.Antispam == nil {
		c.Antispam = &AntispamConfig{
			Enabled:      true,
			RejectOnSpam: false,
			SpamAssassin: &SpamAssassinConfig{
				Enabled:   false,
				Address:   "localhost:783",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 5.0,
			},
			Rspamd: &RspamdConfig{
				Enabled:   true,
				Address:   "http://localhost:11333",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 6.0,
				APIKey:    "",
			},
		}
	}

	// Set default rules configuration if not provided
	if c.Rules == nil {
		c.Rules = &RulesConfig{
			Enabled:       false,
			Path:          "./rules",
			DefaultAction: "accept",
		}
	}

	// Set default plugin configuration if not provided
	if c.Plugins == nil {
		c.Plugins = &PluginConfig{
			Enabled:    false,
			PluginPath: "./plugins",
			Plugins:    []string{},
		}
	}

	// Set default metrics configuration if not provided
	if c.Metrics == nil {
		c.Metrics = &MetricsConfig{
			Enabled:    true,
			ListenAddr: ":8080",
		}
	}

	// Set default API configuration if not provided
	if c.API == nil {
		c.API = &APIConfig{
			Enabled:    false,
			ListenAddr: ":8081",
		}
	}

	if c.SessionTimeout == 0 {
		c.SessionTimeout = 5 * time.Minute
	}

	// RFC 5321 compliance is strict unless the operator explicitly opts out.
	if c.StrictLineEndings == nil {
		c.StrictLineEndings = BoolPtr(true)
	}

	// Resolve trusted networks once. A malformed CIDR is left unresolved so
	// ValidateTrustedNetworks can report it rather than silently widening or
	// narrowing trust.
	if nets, err := ParseTrustedNetworks(c.TrustedNetworks); err == nil {
		c.trustedNets = nets
	}
}

// ValidateTrustedNetworks reports a malformed trusted_networks entry.
//
// This is checked at startup rather than tolerated, because either failure
// mode is bad: silently dropping an entry narrows trust and starts refusing
// mail from a network the operator meant to allow, while silently falling back
// to the defaults widens it.
func (c *Config) ValidateTrustedNetworks() error {
	if _, err := ParseTrustedNetworks(c.TrustedNetworks); err != nil {
		return fmt.Errorf("invalid trusted_networks: %w", err)
	}
	return nil
}

// TrustedNetworkList returns the resolved trusted networks. It falls back to
// parsing on demand for configs built directly in tests without ApplyDefaults.
func (c *Config) TrustedNetworkList() []*net.IPNet {
	if c.trustedNets != nil {
		return c.trustedNets
	}
	if c.TrustedNetworks == nil {
		return DefaultTrustedNetworks()
	}
	nets, err := ParseTrustedNetworks(c.TrustedNetworks)
	if err != nil {
		// ApplyDefaults rejects bad CIDRs at startup; anything reaching here is
		// a config built in code, so fail closed rather than widen trust.
		return nil
	}
	return nets
}

// BoolPtr returns a pointer to b. It exists so callers can set tri-state
// configuration fields such as StrictLineEndings from a struct literal.
func BoolPtr(b bool) *bool { return &b }

// StrictLineEndingsEnabled reports whether RFC 5321 CRLF enforcement is active.
// An unset value defaults to true (strict).
func (c *Config) StrictLineEndingsEnabled() bool {
	return c.StrictLineEndings == nil || *c.StrictLineEndings
}

// DefaultConfig returns a default configuration with sane defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:            ":2525",
		Hostname:              "localhost",
		MaxSize:               50 * 1024 * 1024, // 50MB
		QueueDir:              "./queue",
		QueueBackend:          "file",
		QueueProcessorEnabled: true,
		QueueProcessInterval:  30, // 30 seconds
		MaxRetries:            10,
		MaxQueueTime:          86400,                             // 24 hours
		RetrySchedule:         []int{300, 600, 1200, 1800, 3600}, // 5m, 10m, 20m, 30m, 1h
		MaxWorkers:            5,
		QueueSQLite: QueueSQLiteConfig{
			Path:          "./queue/queue.db",
			BusyTimeoutMS: 5000,
			JournalMode:   "WAL",
			Synchronous:   "NORMAL",
		},
		QueuePostgres: QueuePostgresConfig{
			MaxOpenConns:           20,
			MaxIdleConns:           10,
			ConnMaxLifetimeSeconds: 1800,
		},
		QueueIndexedFS: QueueIndexedFSConfig{
			IndexPath:         "./queue/index",
			ContentDir:        "./queue/data",
			SyncMode:          "normal",
			RecoveryOnStartup: true,
		},

		// TLS configuration with enhanced certificate management
		TLS: &TLSConfig{
			Enabled:        false,
			ListenAddr:     ":2465",
			MinVersion:     "tls1.2",
			EnableStartTLS: true, // Enable STARTTLS by default when TLS is enabled
			RenewalConfig: &CertRenewalConfig{
				AutoRenew:             true,
				RenewalDays:           30,
				ForceRenewal:          false,
				CheckIntervalSeconds:  int(24 * time.Hour / time.Second),
				RenewalTimeoutSeconds: int(5 * time.Minute / time.Second),
				CheckInterval:         24 * time.Hour,
				RenewalTimeout:        5 * time.Minute,
			},
		},

		Auth: &AuthConfig{
			Enabled:  false,
			Required: false,
		},

		Delivery: &DeliveryConfig{
			Mode:       "smtp",
			Timeout:    30,
			MaxRetries: 5,
			RetryDelay: 300, // 5 minutes
		},

		Plugins: &PluginConfig{
			Enabled:    false,
			PluginPath: "./plugins",
		},

		Metrics: &MetricsConfig{
			Enabled:    true,
			ListenAddr: ":8080",
		},

		API: &APIConfig{
			Enabled:    false,
			ListenAddr: ":8081",
		},

		Resources: &ResourceConfig{
			MaxConnections:    100,
			MaxConcurrent:     20,
			ConnectionTimeout: 60,
			ReadTimeout:       30,
			WriteTimeout:      30,
		},

		SessionTimeout: 5 * time.Minute,

		// RFC 5321 compliance - strict by default for security
		StrictLineEndings: BoolPtr(true),
	}
}
