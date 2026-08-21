// Package arc implements Elemta's built-in RFC 8617 ARC plugin.
//
// ARC exists because DKIM and SPF break when mail is forwarded. A mailing list
// that rewrites a subject invalidates the DKIM signature; a forwarder that
// relays a message sends it from an address the sender's SPF record has never
// heard of. The mail is legitimate and the authentication fails anyway, so a
// receiver enforcing DMARC rejects it. ARC lets each hop record what it saw,
// signed, so a later receiver can see that authentication passed earlier even
// though it no longer does.
//
// That makes the chain a trust-conveying mechanism, which is why everything
// here fails closed. A chain that cannot be fully verified is reported as
// broken rather than as unknown: an unverifiable chain is either damaged or
// forged, and the entire value of ARC is lost if a forged one is honoured.
//
// This is a first-party implementation rather than a dependency. The only Go
// ARC libraries available had effectively no adoption, and code that decides
// whether a message is authentic is not somewhere to accept an unvetted
// dependency. It is cross-checked against dkimpy — see
// scripts/dev/arc_crossvalidate.py — so that a mistake in our canonicalization
// cannot hide behind our own tests agreeing with themselves.
package arc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/dkim"
)

// Config controls ARC verification and sealing.
type Config struct {
	Enabled                bool
	Verify                 bool
	Seal                   bool
	Domain                 string
	Selector               string
	PrivateKeyPath         string
	HeaderCanonicalization string
	BodyCanonicalization   string
	HeadersToSign          []string
	Timeout                time.Duration
}

// Result is the RFC 8617 chain-validation result.
type Result struct {
	Value  string `json:"value"`
	Reason string `json:"reason,omitempty"`
}

// Plugin is a concurrency-safe built-in ARC verifier/sealer.
//
// Nothing here mutates after New returns, so it is safe to share across
// sessions and to swap wholesale on a config reload.
type Plugin struct {
	config      Config
	key         *rsa.PrivateKey
	headerCanon Canonicalization
	bodyCanon   Canonicalization
	resolver    TXTResolver
}

// New validates configuration and loads sealing material up front.
//
// Loading the key here means a misconfigured sealer fails at startup rather
// than on the first message, when the failure would be a delivery error.
func New(config Config) (*Plugin, error) {
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	p := &Plugin{
		config:      config,
		headerCanon: CanonRelaxed,
		bodyCanon:   CanonRelaxed,
		resolver:    net.DefaultResolver.LookupTXT,
	}
	if c := Canonicalization(strings.ToLower(strings.TrimSpace(config.HeaderCanonicalization))); c != "" {
		if !c.valid() {
			return nil, fmt.Errorf("arc: header canonicalization %q must be simple or relaxed", c)
		}
		p.headerCanon = c
	}
	if c := Canonicalization(strings.ToLower(strings.TrimSpace(config.BodyCanonicalization))); c != "" {
		if !c.valid() {
			return nil, fmt.Errorf("arc: body canonicalization %q must be simple or relaxed", c)
		}
		p.bodyCanon = c
	}

	if !config.Enabled || !config.Seal {
		return p, nil
	}
	if strings.TrimSpace(config.Domain) == "" {
		return nil, fmt.Errorf("arc: domain is required when sealing is enabled")
	}
	if strings.TrimSpace(config.Selector) == "" {
		return nil, fmt.Errorf("arc: selector is required when sealing is enabled")
	}
	if strings.TrimSpace(config.PrivateKeyPath) == "" {
		return nil, fmt.Errorf("arc: private_key_path is required when sealing is enabled")
	}
	key, err := dkim.LoadRSAPrivateKey(config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("arc: load signing key: %w", err)
	}
	if bits := key.N.BitLen(); bits < minKeyBits {
		return nil, fmt.Errorf("arc: signing key is %d bits; %d is the minimum", bits, minKeyBits)
	}
	p.key = key
	return p, nil
}

// Enabled reports whether either ARC operation is active.
func (p *Plugin) Enabled() bool {
	return p != nil && p.config.Enabled && (p.config.Verify || p.config.Seal)
}

// Verify checks the chain cryptographically.
//
// The result is advisory. It records what this server established, and never
// rejects a message on its own — a broken chain means the chain cannot vouch
// for anything, not that the message is necessarily hostile.
func (p *Plugin) Verify(ctx context.Context, message []byte) Result {
	if p == nil || !p.config.Enabled || !p.config.Verify {
		return Result{Value: ChainNone, Reason: "ARC verification disabled"}
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	value, reason := verifyChain(ctx, message, p.resolver)
	return Result{Value: value, Reason: reason}
}

// Seal adds an ARC set. A sealing failure is returned to the delivery path;
// sending an unsealed message after the operator asked for a seal would make
// the dashboard claim a protection that was not applied.
func (p *Plugin) Seal(ctx context.Context, message []byte, authResults string) ([]byte, error) {
	if p == nil || !p.config.Enabled || !p.config.Seal {
		return message, nil
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	sealed, err := sealMessage(ctx, message, sealOptions{
		domain:        p.config.Domain,
		selector:      p.config.Selector,
		key:           p.key,
		headerCanon:   p.headerCanon,
		bodyCanon:     p.bodyCanon,
		headersToSign: append([]string(nil), p.config.HeadersToSign...),
		authResults:   authResults,
	}, p.resolver)
	if err != nil {
		return message, fmt.Errorf("ARC sealing failed: %w", err)
	}
	return sealed, nil
}

// SetResolver replaces the DNS resolver.
//
// Production uses the system resolver. This exists so tests and the offline
// cross-validation tool can supply a fixed zone instead of depending on the
// network, which would make a correctness check depend on the weather.
func (p *Plugin) SetResolver(resolver TXTResolver) {
	if p != nil && resolver != nil {
		p.resolver = resolver
	}
}

// DNSName is the TXT record name operators must publish for this sealer.
func (p *Plugin) DNSName() string {
	if p == nil || p.config.Selector == "" || p.config.Domain == "" {
		return ""
	}
	return p.config.Selector + "._domainkey." + p.config.Domain
}
