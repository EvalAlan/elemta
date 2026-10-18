// Package mailbox implements Elemta's durable mailbox service. Protocol
// sessions keep only their view; Postgres owns all shared mailbox state.
package mailbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Server      ServerConfig      `toml:"server"`
	Metadata    MetadataConfig    `toml:"metadata"`
	Bodies      BodyConfig        `toml:"bodies"`
	Auth        AuthConfig        `toml:"auth"`
	Limits      LimitsConfig      `toml:"limits"`
	Maintenance MaintenanceConfig `toml:"maintenance"`
	Sieve       SieveConfig       `toml:"sieve"`
}

// SieveConfig controls filtering at delivery and the ManageSieve service.
type SieveConfig struct {
	// Listen is the ManageSieve address (RFC 5804); empty disables it.
	Listen string `toml:"listen"`
	// SubmitAddr is the SMTP submission server redirects and automatic
	// replies are sent through; empty disables both.
	SubmitAddr               string `toml:"submit_addr"`
	SubmitTLS                string `toml:"submit_tls"` // none or starttls
	SubmitInsecureSkipVerify bool   `toml:"submit_insecure_skip_verify"`
	SubmitUserEnv            string `toml:"submit_user_env"`
	SubmitPasswordEnv        string `toml:"submit_password_env"`
	Hostname                 string `toml:"hostname"`
	MaxScriptBytes           int    `toml:"max_script_bytes"`
	MaxScripts               int    `toml:"max_scripts"`
	MaxRedirects             int    `toml:"max_redirects"`
	VacationMaxDays          int    `toml:"vacation_max_days"`
}
type MaintenanceConfig struct {
	GarbageCollection bool `toml:"garbage_collection"`
	// JournalRetentionHours is how long change records are kept for
	// sessions to catch up from; older ones are removed and such sessions
	// reload their folder instead. Zero means 168 (a week); negative keeps
	// the journal forever.
	JournalRetentionHours int `toml:"journal_retention_hours"`
	// BackfillBatch is how many missing message summaries the service
	// computes per minute in the background. Zero means 200; negative
	// disables it.
	BackfillBatch int `toml:"backfill_batch"`
	// BodyGraceHours keeps a message body this long after its last message
	// is gone, so a restored metadata backup still finds it. Set it above
	// your backup retention. Zero means 168 (a week).
	BodyGraceHours int `toml:"body_grace_hours"`
}
type ServerConfig struct {
	IMAPListen string `toml:"imap_listen"`
	// IMAPSListen is an implicit-TLS IMAP listener (usually :993). It
	// needs tls_cert and tls_key.
	IMAPSListen         string   `toml:"imaps_listen"`
	LMTPListen          string   `toml:"lmtp_listen"`
	HTTPListen          string   `toml:"http_listen"`
	AllowPlaintextAuth  bool     `toml:"allow_plaintext_auth"`
	TLSCert             string   `toml:"tls_cert"`
	TLSKey              string   `toml:"tls_key"`
	LMTPAllowedNetworks []string `toml:"lmtp_allowed_networks"`
}
type MetadataConfig struct {
	DSNEnv                        string `toml:"dsn_env"`
	MaxConnections                int    `toml:"max_connections"`
	RequireSynchronousReplication bool   `toml:"require_synchronous_replication"`
}
type BodyConfig struct {
	Driver       string `toml:"driver"`
	DriverEnv    string `toml:"driver_env"`
	Root         string `toml:"root"`
	Endpoint     string `toml:"endpoint"`
	Bucket       string `toml:"bucket"`
	Region       string `toml:"region"`
	Secure       bool   `toml:"secure"`
	AccessKeyEnv string `toml:"access_key_env"`
	SecretKeyEnv string `toml:"secret_key_env"`
}
type AuthConfig struct {
	LDAPURL         string `toml:"ldap_url"`
	LDAPBase        string `toml:"ldap_base"`
	LDAPFilter      string `toml:"ldap_user_filter"`
	BindDNEnv       string `toml:"ldap_bind_dn_env"`
	BindPasswordEnv string `toml:"ldap_bind_password_env"`
	DefaultDomain   string `toml:"default_domain"`
}
type LimitsConfig struct {
	MaxConnections      int `toml:"max_connections"`
	MaxMessageMB        int `toml:"max_message_mb"`
	MaxConcurrentBodies int `toml:"max_concurrent_bodies"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	// The operator explicitly chooses this local configuration path; no
	// protocol client can supply it or cause a configuration read.
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return c, err
	}
	defer f.Close()
	if err := toml.NewDecoder(f).DisallowUnknownFields().Decode(&c); err != nil {
		return c, fmt.Errorf("mailbox configuration: %w", err)
	}
	c = c.WithDefaults()
	return c, c.Validate()
}
func (c Config) WithDefaults() Config {
	if c.Bodies.DriverEnv != "" {
		if driver := os.Getenv(c.Bodies.DriverEnv); driver != "" {
			c.Bodies.Driver = driver
		}
	}
	if c.Sieve.MaxScriptBytes == 0 {
		c.Sieve.MaxScriptBytes = 64 << 10
	}
	if c.Sieve.MaxScripts == 0 {
		c.Sieve.MaxScripts = 20
	}
	if c.Sieve.MaxRedirects == 0 {
		c.Sieve.MaxRedirects = 4
	}
	if c.Sieve.VacationMaxDays == 0 {
		c.Sieve.VacationMaxDays = 30
	}
	if c.Sieve.Hostname == "" {
		c.Sieve.Hostname = "mailbox.elemta"
	}
	if c.Sieve.SubmitUserEnv == "" {
		c.Sieve.SubmitUserEnv = "ELEMTA_MAILBOX_SUBMIT_USER"
	}
	if c.Sieve.SubmitPasswordEnv == "" {
		c.Sieve.SubmitPasswordEnv = "ELEMTA_MAILBOX_SUBMIT_PASSWORD"
	}
	if c.Maintenance.JournalRetentionHours == 0 {
		c.Maintenance.JournalRetentionHours = 168
	}
	if c.Maintenance.BodyGraceHours == 0 {
		c.Maintenance.BodyGraceHours = 168
	}
	if c.Maintenance.BackfillBatch == 0 {
		c.Maintenance.BackfillBatch = 200
	}
	if c.Server.IMAPListen == "" {
		c.Server.IMAPListen = ":1143"
	}
	if c.Server.LMTPListen == "" {
		c.Server.LMTPListen = ":2424"
	}
	if c.Server.HTTPListen == "" {
		c.Server.HTTPListen = ":8080"
	}
	if c.Metadata.MaxConnections == 0 {
		c.Metadata.MaxConnections = 8
	}
	if c.Metadata.DSNEnv == "" {
		c.Metadata.DSNEnv = "ELEMTA_MAILBOX_DATABASE_DSN"
	}
	if c.Bodies.Driver == "" {
		c.Bodies.Driver = "file"
	}
	if c.Bodies.AccessKeyEnv == "" {
		c.Bodies.AccessKeyEnv = "ELEMTA_MAILBOX_S3_ACCESS_KEY"
	}
	if c.Bodies.SecretKeyEnv == "" {
		c.Bodies.SecretKeyEnv = "ELEMTA_MAILBOX_S3_SECRET_KEY"
	}
	if c.Auth.LDAPFilter == "" {
		c.Auth.LDAPFilter = "(&(objectClass=posixAccount)(mail=%s))"
	}
	if c.Auth.BindDNEnv == "" {
		c.Auth.BindDNEnv = "ELEMTA_MAILBOX_LDAP_DN"
	}
	if c.Auth.BindPasswordEnv == "" {
		c.Auth.BindPasswordEnv = "ELEMTA_MAILBOX_LDAP_PASSWORD"
	}
	if c.Limits.MaxConnections == 0 {
		c.Limits.MaxConnections = 256
	}
	if c.Limits.MaxMessageMB == 0 {
		c.Limits.MaxMessageMB = 50
	}
	if c.Limits.MaxConcurrentBodies == 0 {
		c.Limits.MaxConcurrentBodies = 4
	}
	return c
}
func (c Config) Validate() error {
	if !c.Server.AllowPlaintextAuth && !strings.HasPrefix(c.Auth.LDAPURL, "ldaps://") {
		return errors.New("verified LDAPS required unless plaintext development authentication is explicitly allowed")
	}
	for _, addr := range []string{c.Server.IMAPListen, c.Server.LMTPListen, c.Server.HTTPListen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("mailbox listen address: %w", err)
		}
	}
	if c.Metadata.MaxConnections < 2 || c.Metadata.MaxConnections > 100 {
		return errors.New("metadata max_connections must be between 2 and 100")
	}
	if c.Limits.MaxConnections < 1 || c.Limits.MaxMessageMB < 1 || c.Limits.MaxMessageMB > 100 || c.Limits.MaxConcurrentBodies < 1 {
		return errors.New("invalid mailbox limits (message size must be 1..100 MB)")
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return errors.New("both tls_cert and tls_key are required")
	}
	if c.Server.IMAPSListen != "" && c.Server.TLSCert == "" {
		return errors.New("imaps_listen needs tls_cert and tls_key")
	}
	if !c.Server.AllowPlaintextAuth && c.Server.TLSCert == "" {
		return errors.New("TLS certificates required unless allow_plaintext_auth is explicitly enabled")
	}
	if len(c.Server.LMTPAllowedNetworks) == 0 {
		return errors.New("lmtp_allowed_networks must explicitly restrict trusted delivery peers")
	}
	for _, cidr := range c.Server.LMTPAllowedNetworks {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("LMTP network: %w", err)
		}
	}
	switch c.Bodies.Driver {
	case "file":
		if c.Bodies.Root == "" {
			return errors.New("file body root is required")
		}
	case "s3":
		if c.Bodies.Bucket == "" || c.Bodies.Endpoint == "" {
			return errors.New("S3 endpoint and bucket are required")
		}
	default:
		return errors.New("body driver must be file or s3")
	}
	if c.Auth.LDAPURL == "" || c.Auth.LDAPBase == "" || strings.Count(c.Auth.LDAPFilter, "%s") != 1 {
		return errors.New("LDAP URL, base and a filter with one %s are required")
	}
	return nil
}
