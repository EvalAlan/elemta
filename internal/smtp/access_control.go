package smtp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// Access control: operator-maintained allow and deny lists for peer addresses
// and sender domains.
//
// This is deliberately separate from trusted_networks, which decides how
// strictly a peer's *content* is validated. This decides whether the peer is
// allowed to talk to the server at all, and whether a sender domain may be
// used. Conflating the two would mean an operator could not block a network
// without also changing how mail from everywhere else is inspected.
//
// Allow beats deny. An address that matches both lists is allowed, so a broad
// deny range can be punched through for a known-good host without having to
// restate the range. Getting this the other way round makes the lists unusable:
// the only way to permit one host inside a denied /8 would be to enumerate the
// rest of it.

// AccessDecision is why a connection or sender was refused, for logging.
type AccessDecision struct {
	Denied bool
	Reason string
	Rule   string
}

// AccessControl evaluates the configured allow and deny lists.
//
// A zero value is safe: with no lists configured nothing is denied, so a
// misconfigured or absent section cannot silently start refusing mail.
type AccessControl struct {
	enabled bool

	allowNets []*net.IPNet
	denyNets  []*net.IPNet

	// Domains are held lowercased for case-insensitive comparison, which is
	// what RFC 5321 requires of the domain part.
	allowDomains map[string]struct{}
	denyDomains  map[string]struct{}

	logger *slog.Logger
}

// NewAccessControl builds the matcher from configuration. A malformed entry is
// an error rather than something skipped: silently dropping a deny rule leaves
// the operator believing a network is blocked when it is not, and silently
// dropping an allow rule starts refusing mail that should be accepted.
func NewAccessControl(cfg *AccessControlConfig, logger *slog.Logger) (*AccessControl, error) {
	ac := &AccessControl{
		allowDomains: map[string]struct{}{},
		denyDomains:  map[string]struct{}{},
		logger:       logger,
	}
	if cfg == nil || !cfg.Enabled {
		return ac, nil
	}
	ac.enabled = true

	var err error
	if ac.allowNets, err = parseAccessNetworks(cfg.AllowIPs); err != nil {
		return nil, fmt.Errorf("allow_ips: %w", err)
	}
	if ac.denyNets, err = parseAccessNetworks(cfg.DenyIPs); err != nil {
		return nil, fmt.Errorf("deny_ips: %w", err)
	}
	for _, d := range cfg.AllowDomains {
		if d = normalizeAccessDomain(d); d != "" {
			ac.allowDomains[d] = struct{}{}
		}
	}
	for _, d := range cfg.DenyDomains {
		if d = normalizeAccessDomain(d); d != "" {
			ac.denyDomains[d] = struct{}{}
		}
	}
	return ac, nil
}

// Enabled reports whether any checking happens at all.
func (ac *AccessControl) Enabled() bool { return ac != nil && ac.enabled }

// CheckPeer decides whether a connecting address may proceed.
func (ac *AccessControl) CheckPeer(addr net.Addr) AccessDecision {
	if !ac.Enabled() || addr == nil {
		return AccessDecision{}
	}
	ip := ipFromAddr(addr)
	if ip == nil {
		// An address that cannot be parsed cannot be matched against a rule.
		// Denying here would refuse mail on the strength of a parsing failure,
		// so it is left to the rest of the pipeline.
		return AccessDecision{}
	}

	if network := matchNetwork(ip, ac.allowNets); network != "" {
		return AccessDecision{Rule: "allow_ips " + network}
	}
	if network := matchNetwork(ip, ac.denyNets); network != "" {
		return AccessDecision{
			Denied: true,
			Reason: "connection refused by policy",
			Rule:   "deny_ips " + network,
		}
	}
	return AccessDecision{}
}

// CheckSender decides whether a MAIL FROM domain may be used.
//
// The empty sender ("<>") is the bounce path and is never matched against
// domain rules: refusing it would break delivery status notifications, which
// an operator blocking a spam domain is not asking for.
func (ac *AccessControl) CheckSender(sender string) AccessDecision {
	if !ac.Enabled() {
		return AccessDecision{}
	}
	domain := senderDomain(sender)
	if domain == "" {
		return AccessDecision{}
	}

	for _, candidate := range domainAndParents(domain) {
		if _, ok := ac.allowDomains[candidate]; ok {
			return AccessDecision{Rule: "allow_domains " + candidate}
		}
	}
	for _, candidate := range domainAndParents(domain) {
		if _, ok := ac.denyDomains[candidate]; ok {
			return AccessDecision{
				Denied: true,
				Reason: "sender domain refused by policy",
				Rule:   "deny_domains " + candidate,
			}
		}
	}
	return AccessDecision{}
}

// parseAccessNetworks accepts CIDRs and bare addresses. Requiring CIDR would
// reject "192.0.2.66", which is the obvious way to write a single host and the
// form an operator reaches for first.
func parseAccessNetworks(entries []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			out = append(out, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR range", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func matchNetwork(ip net.IP, networks []*net.IPNet) string {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return network.String()
		}
	}
	return ""
}

// ipFromAddr extracts the address, tolerating a missing port, brackets around
// an IPv6 literal and a zone identifier.
func ipFromAddr(addr net.Addr) net.IP {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// senderDomain pulls the domain out of a MAIL FROM address, which may arrive
// wrapped in angle brackets.
func senderDomain(sender string) string {
	s := strings.TrimSpace(sender)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	at := strings.LastIndex(s, "@")
	if at < 0 || at == len(s)-1 {
		return ""
	}
	return normalizeAccessDomain(s[at+1:])
}

// domainAndParents yields the domain and each parent, so "deny_domains" entry
// "example.com" also covers "mail.example.com". An operator blocking a domain
// means its subdomains too; requiring each to be listed is a rule that quietly
// fails to do its job.
func domainAndParents(domain string) []string {
	out := []string{domain}
	for {
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			return out
		}
		domain = domain[dot+1:]
		if !strings.Contains(domain, ".") {
			// Stop before a bare TLD: an entry of "com" must not block
			// everything under it.
			return out
		}
		out = append(out, domain)
	}
}

func normalizeAccessDomain(d string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
}
