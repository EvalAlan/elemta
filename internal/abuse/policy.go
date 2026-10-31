// Package abuse is one view of who is misbehaving, shared by every service
// that takes a connection or a password: the MTA, the mailbox service, the
// webmail and the admin console. Each of them used to keep its own limits, so
// an attacker could move to another protocol, or another replica, and start
// again.
//
// What it decides reaches the services through Valkey. The policy lives in the
// runtime configuration, so it outlasts Valkey, and the admin console publishes
// it from there. Valkey being down must never lock anyone out: each service
// keeps the last policy it saw and falls back to counting on its own.
package abuse

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// How a policy applies.
const (
	ModeEnforce = "enforce"
	ModeLog     = "log" // record what would be blocked, and block nothing
	ModeOff     = "off"
)

// What the host firewall does with blocks.
const (
	FirewallOff   = "off"
	FirewallLog   = "log"
	FirewallApply = "apply"
)

// Policy is what an administrator edits.
type Policy struct {
	Mode string `toml:"mode" json:"mode"`
	// ConnectionsPerAddress caps one address's open connections to one
	// service instance.
	ConnectionsPerAddress int `toml:"connections_per_address" json:"connections_per_address"`
	// ConnectionsPerMinute caps how fast one address may open connections to
	// one instance; 0 turns it off. Port 25 isn't counted.
	ConnectionsPerMinute int `toml:"connections_per_minute" json:"connections_per_minute"`
	// FailuresPerAddress is how many failed sign-ins, across every service
	// and account, block an address within WindowMinutes.
	FailuresPerAddress int `toml:"failures_per_address" json:"failures_per_address"`
	// FailuresPerNetwork does the same for a whole /24 or /48, for attackers
	// spread across a rented block; 0 turns it off.
	FailuresPerNetwork int `toml:"failures_per_network" json:"failures_per_network"`
	WindowMinutes      int `toml:"window_minutes" json:"window_minutes"`
	// BlockMinutes is the first block; each repeat lasts four times longer,
	// up to MaxBlockHours.
	BlockMinutes  int `toml:"block_minutes" json:"block_minutes"`
	MaxBlockHours int `toml:"max_block_hours" json:"max_block_hours"`
	// Firewall is what the host's nftables agent does with blocks: off, log
	// (report only) or apply. Apply stops traffic before it reaches a
	// service, where it costs almost nothing, and is the one setting here that
	// can cut off a whole network at the kernel, so it starts at log.
	Firewall string `toml:"firewall" json:"firewall"`
	// Allowlist holds addresses and networks that are never limited or
	// blocked: an operator's own, monitoring, trusted relays.
	Allowlist []string `toml:"allowlist" json:"allowlist"`
}

// DefaultPolicy leaves room for a busy office behind one address and for large
// mail senders, and is far below what one host needs to exhaust a service.
func DefaultPolicy() Policy {
	return Policy{Mode: ModeEnforce, ConnectionsPerAddress: 25, ConnectionsPerMinute: 120, FailuresPerAddress: 50,
		FailuresPerNetwork: 200, WindowMinutes: 15, BlockMinutes: 15, MaxBlockHours: 24, Firewall: FirewallLog, Allowlist: []string{}}
}

// Validate refuses a policy that couldn't be applied. A typo in an allowlist
// entry must be an error here, not a silently ignored exemption that locks its
// owner out later.
func (p Policy) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeLog, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, log or off, not %q", p.Mode)
	}
	if p.ConnectionsPerAddress < 1 || p.ConnectionsPerAddress > 100000 {
		return errors.New("connections per address must be between 1 and 100000")
	}
	switch p.Firewall {
	case FirewallOff, FirewallLog, FirewallApply:
	default:
		return fmt.Errorf("firewall must be off, log or apply, not %q", p.Firewall)
	}
	if p.ConnectionsPerMinute < 0 || p.ConnectionsPerMinute > 1000000 {
		return errors.New("connections per minute must be between 0 and 1000000")
	}
	if p.FailuresPerNetwork < 0 || p.FailuresPerNetwork > 1000000 {
		return errors.New("failures per network must be between 0 and 1000000")
	}
	if p.FailuresPerAddress < 1 || p.FailuresPerAddress > 100000 {
		return errors.New("failures per address must be between 1 and 100000")
	}
	if p.WindowMinutes < 1 || p.WindowMinutes > 1440 {
		return errors.New("the window must be between 1 minute and 24 hours")
	}
	if p.BlockMinutes < 1 || p.BlockMinutes > 10080 {
		return errors.New("a block must last between 1 minute and 7 days")
	}
	if p.MaxBlockHours < 1 || p.MaxBlockHours > 720 {
		return errors.New("the longest block must be between 1 hour and 30 days")
	}
	if _, err := parseNetworks(p.Allowlist); err != nil {
		return err
	}
	return nil
}

// WithDefaults fills settings a policy doesn't name, such as one saved before
// they existed, so an older configuration still validates.
func (p Policy) WithDefaults() Policy {
	d := DefaultPolicy()
	if p.Mode == "" {
		p.Mode = d.Mode
	}
	if p.ConnectionsPerAddress == 0 {
		p.ConnectionsPerAddress = d.ConnectionsPerAddress
	}
	if p.Firewall == "" {
		p.Firewall = d.Firewall
		// Set together: a policy saved before these existed has neither, and
		// zero means off for the two below.
		p.ConnectionsPerMinute = d.ConnectionsPerMinute
		p.FailuresPerNetwork = d.FailuresPerNetwork
	}
	if p.FailuresPerAddress == 0 {
		p.FailuresPerAddress = d.FailuresPerAddress
	}
	if p.WindowMinutes == 0 {
		p.WindowMinutes = d.WindowMinutes
	}
	if p.BlockMinutes == 0 {
		p.BlockMinutes = d.BlockMinutes
	}
	if p.MaxBlockHours == 0 {
		p.MaxBlockHours = d.MaxBlockHours
	}
	if p.Allowlist == nil {
		p.Allowlist = []string{}
	}
	return p
}

func parseNetworks(entries []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("%q is not an address or network", entry)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			entry = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or network", entry)
		}
		out = append(out, network)
	}
	return out, nil
}

// Network is the unit an address is counted as: an IPv4 address, or an IPv6
// client's /64, since one network holds all of it and single addresses would
// be free to rotate. It returns "" for something that isn't an address.
func Network(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// Subnet is the network an address is rolled up into: a /24, or a /48 for IPv6.
func Subnet(network string) string {
	ip := net.ParseIP(network)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// Target normalises what an administrator can block: an address, or a network
// no wider than a /16 (a /32 for IPv6), so a typo can't take out half the
// internet. It returns "" for anything else.
func Target(value string) string {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		return Network(value)
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return ""
	}
	ones, bits := network.Mask.Size()
	if (bits == 32 && ones < 16) || (bits == 128 && ones < 32) {
		return ""
	}
	return network.String()
}
