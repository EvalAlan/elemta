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
	"net/url"
	"os"
	"path/filepath"
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
	// SecurityURL is the mailbox service's internal account-security API
	// (two-step verification and app passwords), for example
	// http://elemta-mailbox:8080. Empty hides those settings and skips the
	// second sign-in step. ELEMTA_WEBMAIL_SECURITY_URL overrides it.
	SecurityURL string `toml:"security_url"`
	// ObjectStore selects imap (default) or postgres for non-mail objects.
	ObjectStore string `toml:"object_store"`
	// ObjectPostgresDSN may instead be supplied through
	// ELEMTA_WEBMAIL_OBJECT_POSTGRES_DSN to keep credentials out of config.
	ObjectPostgresDSN string `toml:"object_postgres_dsn"`

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

	// SessionTTL is how long an idle session stays valid ("8h" by default)
	// when StaySignedIn is off.
	SessionTTL string `toml:"session_ttl"`

	// StaySignedIn keeps people signed in, through closing the browser, for
	// this long after they last used the webmail ("720h", 30 days, by
	// default). "0" turns it off: the cookie then lasts only until the
	// browser closes and a session ends after SessionTTL idle.
	StaySignedIn string `toml:"stay_signed_in"`

	// SessionMaxAge ends a sign-in this long after it started, however often
	// it is used ("2160h", 90 days, by default; "0" for no limit). Without
	// it, a remembered sign-in used now and then, or a stolen session cookie
	// kept warm, would last for ever.
	SessionMaxAge string `toml:"session_max_age"`

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
	// LDAPURL turns on self-service password changes: the directory the
	// mailbox passwords live in (ldap:// or ldaps://). Empty hides the
	// feature.
	LDAPURL string `toml:"ldap_url"`
	// LDAPBase and LDAPUserFilter find a user's entry; %s in the filter is
	// replaced by the (escaped) sign-in name.
	LDAPBase       string `toml:"ldap_base"`
	LDAPUserFilter string `toml:"ldap_user_filter"`
	// LDAPSearchDN and LDAPSearchPassword are an account that may look up
	// user entries. It needs read access to DNs only; the change itself is
	// made bound as the user. The password can also come from the
	// ELEMTA_WEBMAIL_LDAP_SEARCH_PASSWORD environment variable.
	LDAPSearchDN       string `toml:"ldap_search_dn"`
	LDAPSearchPassword string `toml:"ldap_search_password"`
	// MinPasswordLength is the shortest new password accepted (10).
	MinPasswordLength int `toml:"min_password_length"`

	// RecoveryURL is the public origin used in emailed links. Enabling recovery
	// requires shared Valkey sessions and a separate privileged directory bind.
	RecoveryURL string `toml:"recovery_url"`
	// LDAPProvisionDN is the account mail administration (the console and
	// `elemta provision`) binds as, with write access to mailbox entries
	// and address claims only. Its password is ldap_provision_password or
	// ELEMTA_LDAP_PROVISION_PASSWORD. Unset, administration falls back to
	// the reset account, as before.
	LDAPProvisionDN       string `toml:"ldap_provision_dn"`
	LDAPProvisionPassword string `toml:"ldap_provision_password"`
	LDAPResetDN           string `toml:"ldap_reset_dn"`
	LDAPResetPassword     string `toml:"ldap_reset_password"`
	RecoverySender        string `toml:"recovery_sender"`
	RecoverySMTPUser      string `toml:"recovery_smtp_user"`
	RecoverySMTPPassword  string `toml:"recovery_smtp_password"`

	// TrustedProxies are the addresses (CIDRs) of reverse proxies in front
	// of the webmail. A request from one of them is attributed to the client
	// named in X-Forwarded-For, so sign-in and recovery limits apply per
	// person rather than to everyone behind the proxy. Never list addresses
	// that clients can connect from directly.
	TrustedProxies []string `toml:"trusted_proxies"`

	// OriginatingIPHeader adds X-Originating-IP, the sender's address, to
	// every message sent from the webmail. Off by default because it shows
	// each recipient where the user was; the sender's address is always
	// logged with the Message-ID instead, for abuse reports.
	OriginatingIPHeader bool `toml:"originating_ip_header"`

	// SessionKeyFile holds the key that seals passwords in shared sessions,
	// base64 encoded. It is created if missing. Every pod must read the
	// same file, and it must not be stored in Valkey.
	SessionKeyFile string `toml:"session_key_file"`

	// ImageProxy fetches remote images in mail on the server and serves them
	// from the webmail's origin (imageproxy.go), so senders don't see the
	// reader's address and tracker blockers don't break mail. On by default;
	// false sends the browser straight to the sender's servers, as before.
	ImageProxy *bool `toml:"image_proxy"`
	// ImageCacheDir holds proxied images; it is created if missing. The
	// default is under the system temporary directory, which is enough: a
	// lost cache only means images are fetched again.
	ImageCacheDir string `toml:"image_cache_dir"`
	// ImageCacheMB caps the cache's size on disk.
	ImageCacheMB int `toml:"image_cache_mb"`
	// ImageMaxMB is the largest single image the proxy will pass on.
	ImageMaxMB int `toml:"image_max_mb"`
}

// Defaults applied by WithDefaults.
const (
	defaultListen       = ":8027"
	defaultSessionTTL   = 8 * time.Hour
	defaultStaySignedIn = 30 * 24 * time.Hour
	defaultMaxAge       = 90 * 24 * time.Hour
	defaultMaxUploadMB  = 25
	defaultPageSize     = 50
	defaultMaxMessageMB = 50
	defaultImageCacheMB = 512
	defaultImageMaxMB   = 5
)

// WithDefaults returns a copy of c with every unset field filled in.
func (c Config) WithDefaults() Config {
	if c.ObjectStore == "" {
		c.ObjectStore = "imap"
	}
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
	if c.LDAPUserFilter == "" {
		c.LDAPUserFilter = "(mail=%s)"
	}
	if c.MinPasswordLength <= 0 {
		c.MinPasswordLength = 10
	}
	if c.SessionTTL == "" {
		c.SessionTTL = defaultSessionTTL.String()
	}
	if c.StaySignedIn == "" {
		c.StaySignedIn = defaultStaySignedIn.String()
	}
	if c.SessionMaxAge == "" {
		c.SessionMaxAge = defaultMaxAge.String()
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
	if c.ImageProxy == nil {
		on := true
		c.ImageProxy = &on
	}
	if c.ImageCacheDir == "" {
		c.ImageCacheDir = filepath.Join(os.TempDir(), "elemta-webmail-images")
	}
	if c.ImageCacheMB <= 0 {
		c.ImageCacheMB = defaultImageCacheMB
	}
	if c.ImageMaxMB <= 0 {
		c.ImageMaxMB = defaultImageMaxMB
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
	if c.ObjectStore != "imap" && c.ObjectStore != "postgres" {
		errs = append(errs, errors.New("webmail: object_store must be imap or postgres"))
	}
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
	for _, p := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			errs = append(errs, fmt.Errorf("webmail: trusted_proxies entry %q is not an address or CIDR", p))
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
	if c.RecoveryURL != "" {
		u, err := url.Parse(c.RecoveryURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && !*c.SecureCookies)) {
			errs = append(errs, errors.New("webmail: recovery_url must be an HTTPS origin (HTTP allowed with secure_cookies=false)"))
		}
		if c.SessionStore != "valkey" || c.LDAPURL == "" || c.LDAPResetDN == "" || c.RecoverySender == "" || c.RecoverySMTPUser == "" {
			errs = append(errs, errors.New("webmail: recovery needs Valkey sessions, ldap_url, ldap_reset_dn, recovery_sender and recovery_smtp_user"))
		}
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
	if d, err := time.ParseDuration(c.StaySignedIn); err != nil || d < 0 {
		errs = append(errs, fmt.Errorf("webmail: stay_signed_in %q must be a duration such as \"720h\", or \"0\" for off", c.StaySignedIn))
	}
	if c.SessionMaxAge != "" {
		if d, err := time.ParseDuration(c.SessionMaxAge); err != nil || d < 0 {
			errs = append(errs, fmt.Errorf("webmail: session_max_age %q must be a duration such as \"2160h\", or \"0\" for no limit", c.SessionMaxAge))
		}
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

// staySignedIn is how long a remembered sign-in lasts after its last use,
// or zero when the sign-in ends with the browser.
func (c Config) staySignedIn() time.Duration {
	d, err := time.ParseDuration(c.StaySignedIn)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// idleTTL is how long a session lasts unused: long enough for a remembered
// sign-in when that's on, so the session outlives the cookie never.
func (c Config) idleTTL() time.Duration {
	return max(c.sessionTTL(), c.staySignedIn())
}

// maxAge is how long a sign-in may last from its start, or zero for no limit.
func (c Config) maxAge() time.Duration {
	d, err := time.ParseDuration(c.SessionMaxAge)
	if err != nil || d < 0 {
		return 0
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
