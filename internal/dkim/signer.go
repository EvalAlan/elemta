// Package dkim implements outbound DKIM signing for elemta.
//
// It reuses github.com/emersion/go-msgauth/dkim (the same library referenced by
// the verification path in the plugin package) so that a message signed here can
// be verified with the exact same code on the receiving side. RSA and Ed25519
// keys are both supported because dkim.Sign accepts any crypto.Signer.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/emersion/go-msgauth/dkim"
)

// DefaultHeadersToSign is the set of headers signed when a signing domain does
// not override HeadersToSign. It intentionally includes the headers Gmail,
// Yahoo and Outlook expect for good deliverability.
var DefaultHeadersToSign = []string{
	"From",
	"To",
	"Cc",
	"Subject",
	"Date",
	"Message-ID",
	"MIME-Version",
	"Content-Type",
	"Reply-To",
	"In-Reply-To",
	"References",
}

// DomainConfig is the per-domain signing configuration.
type DomainConfig struct {
	// Domain is the signing domain (the d= tag). Matched against the
	// envelope-from / From header domain to select a key.
	Domain string `toml:"domain"`
	// Selector is the DKIM selector (the s= tag).
	Selector string `toml:"selector"`
	// PrivateKeyPath is the path to a PEM-encoded RSA or Ed25519 private key.
	PrivateKeyPath string `toml:"private_key_path"`
	// HeadersToSign optionally overrides the default header set for this domain.
	HeadersToSign []string `toml:"headers_to_sign"`
}

// Config is the top-level [dkim] configuration section.
type Config struct {
	Enabled bool `toml:"enabled"`
	// HeaderCanonicalization and BodyCanonicalization default to "relaxed".
	HeaderCanonicalization string `toml:"header_canonicalization"`
	BodyCanonicalization   string `toml:"body_canonicalization"`
	// Domains is the list of signing domains.
	Domains []DomainConfig `toml:"domains"`
}

// domainKey holds a loaded, validated signer for a single domain.
type domainKey struct {
	selector    string
	signer      crypto.Signer
	hash        crypto.Hash
	headerKeys  []string
	headerCanon dkim.Canonicalization
	bodyCanon   dkim.Canonicalization
}

// Signer signs outbound messages. It is safe for concurrent use.
type Signer struct {
	logger *slog.Logger
	// keys maps a lower-cased signing domain to its loaded key material.
	keys map[string]domainKey

	mu sync.RWMutex
}

// NewSigner builds a Signer from configuration. It loads and validates every
// configured key up-front (including file-permission checks) so that a
// misconfiguration fails fast at start-up rather than silently at delivery
// time. If cfg is nil or disabled, NewSigner returns (nil, nil) and callers
// should treat a nil *Signer as "signing disabled".
func NewSigner(cfg *Config, logger *slog.Logger) (*Signer, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "dkim-signer")

	headerCanon, err := parseCanonicalization(cfg.HeaderCanonicalization)
	if err != nil {
		return nil, fmt.Errorf("dkim: header_canonicalization: %w", err)
	}
	bodyCanon, err := parseCanonicalization(cfg.BodyCanonicalization)
	if err != nil {
		return nil, fmt.Errorf("dkim: body_canonicalization: %w", err)
	}

	s := &Signer{logger: logger, keys: make(map[string]domainKey)}

	for _, dc := range cfg.Domains {
		domain := strings.ToLower(strings.TrimSpace(dc.Domain))
		if domain == "" {
			return nil, fmt.Errorf("dkim: domain entry with empty domain")
		}
		if dc.Selector == "" {
			return nil, fmt.Errorf("dkim: domain %q has empty selector", domain)
		}
		if dc.PrivateKeyPath == "" {
			return nil, fmt.Errorf("dkim: domain %q has empty private_key_path", domain)
		}
		if _, exists := s.keys[domain]; exists {
			return nil, fmt.Errorf("dkim: domain %q configured more than once", domain)
		}

		signer, hash, err := loadPrivateKey(dc.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("dkim: domain %q: %w", domain, err)
		}

		configuredHeaders := dc.HeadersToSign
		if len(configuredHeaders) == 0 {
			configuredHeaders = DefaultHeadersToSign
		}
		headerKeys := make([]string, len(configuredHeaders))
		hasFrom := false
		for i, header := range configuredHeaders {
			headerKeys[i] = strings.TrimSpace(header)
			if !validHeaderFieldName(headerKeys[i]) {
				return nil, fmt.Errorf("dkim: domain %q headers_to_sign contains invalid header name %q", domain, header)
			}
			if strings.EqualFold(headerKeys[i], "From") {
				hasFrom = true
			}
		}
		if !hasFrom {
			return nil, fmt.Errorf("dkim: domain %q headers_to_sign must include From", domain)
		}

		s.keys[domain] = domainKey{
			selector:    dc.Selector,
			signer:      signer,
			hash:        hash,
			headerKeys:  headerKeys,
			headerCanon: headerCanon,
			bodyCanon:   bodyCanon,
		}
		logger.Info("Loaded DKIM signing key", "domain", domain, "selector", dc.Selector)
	}

	if len(s.keys) == 0 {
		return nil, fmt.Errorf("dkim: enabled but no signing domains configured")
	}

	return s, nil
}

// Sign returns a DKIM-signed copy of content. The signing domain is selected by
// matching signingDomain (typically the envelope-from domain, falling back to
// the From header domain) against the configured domains.
//
// Behaviour:
//   - If no key is configured for the domain, content is returned unchanged and
//     a debug line is logged (not an error — the message is still deliverable).
//   - A signing failure returns the original content and an error. Elemta's SMTP
//     delivery path treats that error as a failed attempt rather than sending
//     unsigned mail for a configured signing domain.
func (s *Signer) Sign(content []byte, signingDomain string) ([]byte, error) {
	if s == nil {
		return content, nil
	}

	domain := strings.ToLower(strings.TrimSpace(signingDomain))
	s.mu.RLock()
	key, ok := s.keys[domain]
	s.mu.RUnlock()
	if !ok {
		s.logger.Debug("No DKIM key configured for domain, skipping signing", "domain", domain)
		return content, nil
	}

	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               key.selector,
		Signer:                 key.signer,
		Hash:                   key.hash,
		HeaderCanonicalization: key.headerCanon,
		BodyCanonicalization:   key.bodyCanon,
		HeaderKeys:             key.headerKeys,
	}

	var buf bytes.Buffer
	if err := dkim.Sign(&buf, bytes.NewReader(content), opts); err != nil {
		return content, fmt.Errorf("dkim: signing for domain %q failed: %w", domain, err)
	}

	s.logger.Debug("Signed message with DKIM", "domain", domain, "selector", key.selector)
	return buf.Bytes(), nil
}

// HasKeyFor reports whether a signing key is configured for the given domain.
func (s *Signer) HasKeyFor(domain string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.keys[strings.ToLower(strings.TrimSpace(domain))]
	return ok
}

// loadPrivateKey reads, permission-checks and parses a PEM private key. It
// returns a crypto.Signer and the hash to use (SHA-256 for RSA; Ed25519
// signs without a separate hash so crypto.Hash(0) is returned and go-msgauth
// handles the ed25519 special case internally).
func loadPrivateKey(path string) (crypto.Signer, crypto.Hash, error) {
	if err := validateKeyPermissions(path); err != nil {
		return nil, 0, err
	}

	// #nosec G304 -- private-key path is explicit, trusted operator configuration;
	// permissions and key format are validated immediately before this read.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("reading key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, 0, fmt.Errorf("no PEM block found in key file %s", path)
	}

	signer, hash, err := parsePrivateKeyBlock(block)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing key %s: %w", path, err)
	}
	return signer, hash, nil
}

// parsePrivateKeyBlock parses a decoded PEM block into a crypto.Signer.
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, crypto.Hash, error) {
	// PKCS#1 (RSA-only).
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, crypto.SHA256, nil
	}

	// PKCS#8 (RSA or Ed25519). go-msgauth does not support ECDSA DKIM keys.
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := parsed.(type) {
		case *rsa.PrivateKey:
			return key, crypto.SHA256, nil
		case ed25519.PrivateKey:
			// dkim.Sign special-cases ed25519; the hash value is ignored for it.
			return key, crypto.Hash(0), nil
		case *ecdsa.PrivateKey:
			return nil, 0, fmt.Errorf("ECDSA DKIM keys are not supported")
		default:
			return nil, 0, fmt.Errorf("unsupported PKCS#8 key type %T", parsed)
		}
	}

	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil, 0, fmt.Errorf("ECDSA DKIM keys are not supported")
	}

	return nil, 0, fmt.Errorf("unrecognised private key format")
}

// validateKeyPermissions rejects private keys that are readable or writable by
// group or other, matching elemta's file-security posture for sensitive files.
func validateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat key %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("key path %s is a directory", path)
	}
	// 0077 = any group/other read/write/execute bit set.
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key %s has insecure permissions %s (must not be readable/writable by group or other)",
			path, info.Mode().Perm())
	}
	return nil
}

// validHeaderFieldName reports whether name is an RFC 5322 field-name: one or
// more printable US-ASCII characters except colon. Names are trimmed before
// validation so accepted configuration is exactly what reaches go-msgauth.
func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 33 || name[i] > 126 || name[i] == ':' {
			return false
		}
	}
	return true
}

// parseCanonicalization maps a config string to a dkim.Canonicalization,
// defaulting to relaxed when empty (per requirements).
func parseCanonicalization(v string) (dkim.Canonicalization, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "relaxed":
		return dkim.CanonicalizationRelaxed, nil
	case "simple":
		return dkim.CanonicalizationSimple, nil
	default:
		return "", fmt.Errorf("unknown canonicalization %q (want \"relaxed\" or \"simple\")", v)
	}
}

// FromHeaderDomain extracts the domain from the message's From header. It reads
// only the header block and returns "" when no usable From domain is found. This
// is used as a fallback when the envelope-from is empty (e.g. bounce messages).
func FromHeaderDomain(content []byte) string {
	headerEnd := bytes.Index(content, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		if idx := bytes.Index(content, []byte("\n\n")); idx != -1 {
			headerEnd = idx
		} else {
			headerEnd = len(content)
		}
	}
	lines := strings.Split(strings.ReplaceAll(string(content[:headerEnd]), "\r\n", "\n"), "\n")
	for _, line := range lines {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			value := strings.TrimSpace(line[len("from:"):])
			// Prefer an address inside angle brackets when present.
			if lt := strings.LastIndex(value, "<"); lt != -1 {
				if gt := strings.Index(value[lt:], ">"); gt != -1 {
					value = value[lt+1 : lt+gt]
				}
			}
			return DomainFromAddress(value)
		}
	}
	return ""
}

// DomainFromAddress extracts the lower-cased domain from an email address such
// as "user@example.com" or "<user@example.com>". It returns "" when no domain
// can be determined.
func DomainFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "<>")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}
