package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/busybox42/elemta/internal/datasource"
)

// AuthMethod represents the SMTP authentication method
type AuthMethod string

const (
	// AuthMethodPlain represents PLAIN authentication
	AuthMethodPlain AuthMethod = "PLAIN"
	// AuthMethodLogin represents LOGIN authentication
	AuthMethodLogin AuthMethod = "LOGIN"
	// AuthMethodCramMD5 represents CRAM-MD5 authentication
	AuthMethodCramMD5 AuthMethod = "CRAM-MD5"
)

// Authenticator is the interface for SMTP authentication
type Authenticator interface {
	// Authenticate authenticates a user with the given credentials
	Authenticate(ctx context.Context, username, password string) (bool, error)
	// IsEnabled returns true if authentication is enabled
	IsEnabled() bool
	// IsRequired returns true if authentication is required
	IsRequired() bool
	// GetSupportedMethods returns the supported authentication methods
	GetSupportedMethods() []AuthMethod
}

// SMTPAuthenticator implements the Authenticator interface
type SMTPAuthenticator struct {
	config     *AuthConfig
	dataSource datasource.DataSource
	logger     *slog.Logger
	mu         sync.RWMutex
}

type authDataSourceFactory func(config datasource.Config) (datasource.DataSource, error)

var newAuthDataSource authDataSourceFactory = datasource.Factory

// AuthDataSourceConfig turns the SMTP auth settings into a datasource config.
//
// Exported so anything else that needs to read the same accounts — the
// dashboard's campaign recipient import, for one — builds an identical
// datasource rather than its own approximation. Two copies of this mapping
// would let the dashboard list one directory while the server authenticates
// against another, and the difference would only show up as a campaign
// addressed to the wrong people.
//
// Note that Type comes from DataSourceName rather than DataSourceType. That is
// how deployments in the field are configured, so it stays; changing it would
// break every existing config file.
func AuthDataSourceConfig(config *AuthConfig) datasource.Config {
	dsConfig := datasource.Config{
		Type:     config.DataSourceName,
		Name:     config.DataSourceName,
		Host:     config.DataSourceHost,
		Port:     config.DataSourcePort,
		Database: config.DataSourceDB,
		Username: config.DataSourceUser,
		Password: config.DataSourcePass,
		Options:  make(map[string]interface{}),
	}

	// Both file and db_path are set for backward compatibility.
	if config.DataSourcePath != "" {
		dsConfig.Options["file"] = config.DataSourcePath
		dsConfig.Options["db_path"] = config.DataSourcePath
	}

	if config.DataSourceName == "ldap" {
		if config.DataSourceDB != "" {
			dsConfig.Options["base_dn"] = config.DataSourceDB
		}
		dsConfig.Options["user_dn"] = "ou=people"
		dsConfig.Options["group_dn"] = "ou=groups"
	}

	return dsConfig
}

// NewAuthenticator creates a new SMTP authenticator
func NewAuthenticator(config *AuthConfig) (*SMTPAuthenticator, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	auth := &SMTPAuthenticator{
		config: config,
		logger: logger,
	}

	// If authentication is not enabled, return early
	if !config.Enabled {
		return auth, nil
	}

	ds, err := newAuthDataSource(AuthDataSourceConfig(config))
	if err != nil {
		return nil, fmt.Errorf("failed to create datasource: %w", err)
	}

	if err := ds.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to datasource: %w", err)
	}

	auth.dataSource = ds
	return auth, nil
}

// Authenticate authenticates a user with the given credentials
func (a *SMTPAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// If authentication is not enabled, return success
	if !a.config.Enabled {
		return true, nil
	}

	// If no datasource is configured, return error
	if a.dataSource == nil {
		return false, fmt.Errorf("no datasource configured for authentication")
	}

	// Authenticate against the datasource
	authenticated, err := a.dataSource.Authenticate(ctx, username, password)
	if err != nil {
		a.logger.Error("authentication failed", "username", username, "error", err)
		return false, err
	}

	if authenticated {
		a.logger.Info("authentication successful", "username", username)
	} else {
		a.logger.Warn("authentication failed", "username", username)
	}

	return authenticated, nil
}

// IsEnabled returns true if authentication is enabled
func (a *SMTPAuthenticator) IsEnabled() bool {
	return a.config != nil && a.config.Enabled
}

// IsRequired returns true if authentication is required
func (a *SMTPAuthenticator) IsRequired() bool {
	return a.config != nil && a.config.Enabled && a.config.Required
}

// GetSupportedMethods returns the supported authentication methods
func (a *SMTPAuthenticator) GetSupportedMethods() []AuthMethod {
	// CRAM-MD5 is disabled for security reasons:
	// 1. Requires plaintext password storage (major security risk)
	// 2. Uses MD5 which is cryptographically broken
	// 3. Vulnerable to offline dictionary attacks
	// 4. Modern security standards recommend PLAIN/LOGIN over TLS instead
	return []AuthMethod{AuthMethodPlain, AuthMethodLogin}
}

// Close closes the authenticator and releases resources
func (a *SMTPAuthenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dataSource != nil && a.dataSource.IsConnected() {
		return a.dataSource.Close()
	}
	return nil
}
