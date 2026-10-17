// Package webmail is Elemta's first-party webmail: a server-rendered Go web
// application that reads mail from an IMAP store (Dovecot) and sends through
// Elemta's own submission listener.
//
// The package deliberately owns no mail storage. Everything a user sees comes
// from IMAP on every request, and the only state it keeps is the login
// session. That keeps webmail pods stateless, so they can be scaled and
// replaced freely behind a load balancer.
package webmail

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLS modes accepted for the IMAP and submission connections.
const (
	TLSModeStartTLS = "starttls"
	TLSModeImplicit = "tls"
	TLSModeNone     = "none"
)

// Config is the [webmail] table of the main configuration file.
//
// Every field carries an explicit toml tag: the config decoders do not map
// underscored keys onto field names implicitly, and an untagged field would
// load silently and do nothing.
type Config struct {
	Enabled bool `toml:"enabled"`

	// Listen is the HTTP listen address, for example ":8027".
	Listen string `toml:"listen"`

	// IMAPAddr is host:port of the IMAP server holding the mailboxes.
	IMAPAddr string `toml:"imap_addr"`
	// IMAPTLS is "starttls" (default), "tls" or "none".
	IMAPTLS string `toml:"imap_tls"`

	// SubmissionAddr is host:port of the Elemta submission listener that
	// outgoing mail is handed to, authenticated as the logged-in user.
	SubmissionAddr string `toml:"submission_addr"`
	// SubmissionTLS is "starttls" (default), "tls" or "none".
	SubmissionTLS string `toml:"submission_tls"`

	// InsecureSkipVerify disables certificate verification on the IMAP and
	// submission connections. It exists for the dev stack's self-signed
	// certificates and must stay off in production.
	InsecureSkipVerify bool `toml:"insecure_skip_verify"`

	// DefaultDomain is appended to a login name without an @, so "dana"
	// signs in, and sends, as dana@<default_domain>.
	DefaultDomain string `toml:"default_domain"`

	// SessionTTL is how long an idle session stays valid ("8h" by default).
	SessionTTL string `toml:"session_ttl"`

	// SecureCookies marks session cookies Secure. Unset means true; set it
	// to false only when the webmail is served over plain HTTP in dev.
	SecureCookies *bool `toml:"secure_cookies"`

	// MaxUploadMB caps the total size of a composed message's attachments.
	MaxUploadMB int `toml:"max_upload_mb"`

	// PageSize is the number of messages per page in a folder listing.
	PageSize int `toml:"page_size"`

	// MaxMessageMB caps the size of a message the webmail will download from
	// IMAP to display. Larger messages show their headers and a download link.
	MaxMessageMB int `toml:"max_message_mb"`

	// DefaultTimezone is the IANA zone dates are shown in until a user's
	// browser reports theirs or they pick one in Settings ("UTC" by default).
	DefaultTimezone string `toml:"default_timezone"`

	// SieveAddr is host:port of the ManageSieve server (RFC 5804) that
	// mail filters and the out-of-office reply are stored on. Empty turns
	// those features off.
	SieveAddr string `toml:"sieve_addr"`
	// SieveTLS is "starttls" (default), "tls" or "none".
	SieveTLS string `toml:"sieve_tls"`

	// SessionStore is "memory" (the default: sessions live in one process
	// and end when it restarts) or "valkey" (shared by every webmail pod,
	// surviving restarts).
	SessionStore string `toml:"session_store"`
	// ValkeyAddr is host:port of Valkey for session_store = "valkey".
	// Empty uses the VALKEY_ADDR environment variable.
	ValkeyAddr string `toml:"valkey_addr"`
	// SessionKeyFile holds the key that seals passwords in shared sessions,
	// base64 encoded. It is created if missing. Every pod must read the
	// same file, and it must not be stored in Valkey.
	SessionKeyFile string `toml:"session_key_file"`
}

// Defaults applied by WithDefaults.
const (
	defaultListen       = ":8027"
	defaultSessionTTL   = 8 * time.Hour
	defaultMaxUploadMB  = 25
	defaultPageSize     = 50
	defaultMaxMessageMB = 50
)

// WithDefaults returns a copy of c with every unset field filled in.
func (c Config) WithDefaults() Config {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.IMAPTLS == "" {
		c.IMAPTLS = TLSModeStartTLS
	}
	if c.SubmissionTLS == "" {
		c.SubmissionTLS = TLSModeStartTLS
	}
	if c.SieveTLS == "" {
		c.SieveTLS = TLSModeStartTLS
	}
	if c.DefaultTimezone == "" {
		c.DefaultTimezone = "UTC"
	}
	if c.SessionStore == "" {
		c.SessionStore = "memory"
	}
	if c.SessionTTL == "" {
		c.SessionTTL = defaultSessionTTL.String()
	}
	if c.SecureCookies == nil {
		secure := true
		c.SecureCookies = &secure
	}
	if c.MaxUploadMB <= 0 {
		c.MaxUploadMB = defaultMaxUploadMB
	}
	if c.PageSize <= 0 {
		c.PageSize = defaultPageSize
	}
	if c.MaxMessageMB <= 0 {
		c.MaxMessageMB = defaultMaxMessageMB
	}
	c.IMAPTLS = strings.ToLower(c.IMAPTLS)
	c.SubmissionTLS = strings.ToLower(c.SubmissionTLS)
	c.SieveTLS = strings.ToLower(c.SieveTLS)
	return c
}

// Validate reports the first problem that would stop the webmail working.
// Call it on the result of WithDefaults.
func (c Config) Validate() error {
	var errs []error
	if c.IMAPAddr == "" {
		errs = append(errs, errors.New("webmail: imap_addr is required"))
	} else if _, _, err := net.SplitHostPort(c.IMAPAddr); err != nil {
		errs = append(errs, fmt.Errorf("webmail: imap_addr %q: %w", c.IMAPAddr, err))
	}
	if c.SubmissionAddr == "" {
		errs = append(errs, errors.New("webmail: submission_addr is required"))
	} else if _, _, err := net.SplitHostPort(c.SubmissionAddr); err != nil {
		errs = append(errs, fmt.Errorf("webmail: submission_addr %q: %w", c.SubmissionAddr, err))
	}
	if c.SieveAddr != "" {
		if _, _, err := net.SplitHostPort(c.SieveAddr); err != nil {
			errs = append(errs, fmt.Errorf("webmail: sieve_addr %q: %w", c.SieveAddr, err))
		}
	}
	switch c.SessionStore {
	case "memory":
	case "valkey":
		if c.SessionKeyFile == "" {
			errs = append(errs, errors.New("webmail: session_store = \"valkey\" needs session_key_file"))
		}
	default:
		errs = append(errs, fmt.Errorf("webmail: session_store must be memory or valkey, not %q", c.SessionStore))
	}
	if _, err := time.LoadLocation(c.DefaultTimezone); err != nil {
		errs = append(errs, fmt.Errorf("webmail: default_timezone %q: %w", c.DefaultTimezone, err))
	}
	for name, mode := range map[string]string{"imap_tls": c.IMAPTLS, "submission_tls": c.SubmissionTLS, "sieve_tls": c.SieveTLS} {
		switch mode {
		case TLSModeStartTLS, TLSModeImplicit, TLSModeNone:
		default:
			errs = append(errs, fmt.Errorf("webmail: %s must be starttls, tls or none, not %q", name, mode))
		}
	}
	if _, err := time.ParseDuration(c.SessionTTL); err != nil {
		errs = append(errs, fmt.Errorf("webmail: session_ttl %q: %w", c.SessionTTL, err))
	}
	return errors.Join(errs...)
}

// sessionTTL returns the parsed session lifetime; Validate guarantees it parses.
func (c Config) sessionTTL() time.Duration {
	d, err := time.ParseDuration(c.SessionTTL)
	if err != nil || d <= 0 {
		return defaultSessionTTL
	}
	return d
}

// location is the default time zone; Validate guarantees it loads.
func (c Config) location() *time.Location {
	if l, err := time.LoadLocation(c.DefaultTimezone); err == nil {
		return l
	}
	return time.UTC
}

// address turns a login name into the mailbox address it sends as.
func (c Config) address(login string) string {
	if strings.Contains(login, "@") || c.DefaultDomain == "" {
		return login
	}
	return login + "@" + c.DefaultDomain
}
