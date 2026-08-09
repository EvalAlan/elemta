package smtp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// Private network ranges as defined in RFC 1918 and RFC 4193
var privateNetworks []*net.IPNet

func init() {
	networks, err := initPrivateNetworks()
	if err != nil {
		slog.Error("Failed to initialize private networks", "error", err)
		privateNetworks = []*net.IPNet{}
		return
	}
	privateNetworks = networks
}

func initPrivateNetworks() ([]*net.IPNet, error) {
	cidrs := []string{
		// IPv4 private networks
		"10.0.0.0/8",     // Class A private
		"172.16.0.0/12",  // Class B private
		"192.168.0.0/16", // Class C private
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local

		// IPv6 private networks
		"::1/128",   // IPv6 loopback
		"fc00::/7",  // IPv6 unique local addresses
		"fe80::/10", // IPv6 link-local
	}

	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		network, err := parseNetwork(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", cidr, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func parseNetwork(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation %q: %w", cidr, err)
	}
	return network, nil
}

// IsPrivateNetwork checks if an IP address is in a private network range
func IsPrivateNetwork(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check against all private network ranges
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// defaultTrustedCIDRs are the networks treated as internal when the operator
// has not configured trusted_networks.
//
// This is deliberately narrower than privateNetworks, which also covers
// 192.168.0.0/16, link-local and IPv6 ULA. Those are reasonable answers to
// "is this a private address" but a different question from "should this peer
// skip content validation", and adding them here would silently widen trust
// beyond what the previous implementation granted. Operators who want them can
// list them in trusted_networks.
var defaultTrustedCIDRs = []string{
	"127.0.0.0/8",   // IPv4 loopback
	"::1/128",       // IPv6 loopback
	"10.0.0.0/8",    // RFC 1918
	"172.16.0.0/12", // RFC 1918 — note /12, not the /8 the old prefix match implied
}

var defaultTrustedNetworks []*net.IPNet

func init() {
	for _, cidr := range defaultTrustedCIDRs {
		network, err := parseNetwork(cidr)
		if err != nil {
			// These are compile-time constants; a failure here is a bug.
			slog.Error("Failed to parse default trusted network", "cidr", cidr, "error", err)
			continue
		}
		defaultTrustedNetworks = append(defaultTrustedNetworks, network)
	}
}

// DefaultTrustedNetworks returns the CIDRs treated as internal when an
// operator has not configured trusted_networks.
func DefaultTrustedNetworks() []*net.IPNet {
	out := make([]*net.IPNet, len(defaultTrustedNetworks))
	copy(out, defaultTrustedNetworks)
	return out
}

// ParseTrustedNetworks turns operator-supplied CIDRs into matchable networks.
// A nil slice means "use the defaults"; a non-nil but empty slice means "trust
// nothing", which is how a test drives the external path from loopback.
func ParseTrustedNetworks(cidrs []string) ([]*net.IPNet, error) {
	if cidrs == nil {
		return DefaultTrustedNetworks(), nil
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		network, err := parseNetwork(strings.TrimSpace(cidr))
		if err != nil {
			return nil, err
		}
		out = append(out, network)
	}
	return out, nil
}

// PeerIsWithin reports whether the connection's peer falls inside any of the
// given networks.
//
// It parses the address rather than matching its text. String prefixes get
// this wrong in ways that matter: "172." covers 172.0.0.0/8 while only
// 172.16.0.0/12 is private, and a substring test for "::1" matches any IPv6
// address ending in ::1 — a conventional first host address in a subnet, and
// routable. An unparseable or absent address is treated as external.
func PeerIsWithin(conn net.Conn, networks []*net.IPNet) bool {
	if conn == nil {
		return false
	}
	remote := conn.RemoteAddr()
	if remote == nil {
		return false
	}

	host := remote.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// SplitHostPort leaves brackets on a bare IPv6 literal without a port.
	host = strings.Trim(host, "[]")
	// Drop any IPv6 zone identifier, e.g. fe80::1%eth0.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateNetworkAddr checks if an address string represents a private network IP
func IsPrivateNetworkAddr(addr string) bool {
	// Extract IP from address (remove port if present)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use the address as is
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return IsPrivateNetwork(ip)
}

// IsInternalConnection checks if a connection is from an internal/private network
func IsInternalConnection(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return false
	}

	return IsPrivateNetworkAddr(remoteAddr.String())
}

// GetClientIP extracts the client IP address from a connection
func GetClientIP(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return nil
	}

	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	default:
		// Try to parse the string representation
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		return net.ParseIP(host)
	}
}

// IsAllowedRelay checks if an IP is allowed to relay messages
// This includes both explicit allowed relays and internal networks
func IsAllowedRelay(ip net.IP, allowedRelays []string) bool {
	if ip == nil {
		return false
	}

	ipStr := ip.String()

	// Check explicit allowed relays first
	for _, relay := range allowedRelays {
		// Support both IP addresses and CIDR notation
		if strings.Contains(relay, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(relay)
			if err != nil {
				slog.Warn("Invalid CIDR in allowed relays", "cidr", relay, "error", err)
				continue // Skip invalid instead of crashing
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			// Direct IP comparison
			if relay == ipStr {
				return true
			}
		}
	}

	// Always allow internal/private networks
	return IsPrivateNetwork(ip)
}

// IsAllowedRelayAddr checks if an address string is allowed to relay
func IsAllowedRelayAddr(addr string, allowedRelays []string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		// Try to extract IP from host:port format
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	return IsAllowedRelay(ip, allowedRelays)
}
