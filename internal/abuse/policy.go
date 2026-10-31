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

// Policy is what an administrator edits.
type Policy struct {
	Mode string `toml:"mode" json:"mode"`
	// ConnectionsPerAddress caps one address's open connections to one
	// service instance.
	ConnectionsPerAddress int `toml:"connections_per_address" json:"connections_per_address"`
	// Allowlist holds addresses and networks that are never limited or
	// blocked: an operator's own, monitoring, trusted relays.
	Allowlist []string `toml:"allowlist" json:"allowlist"`
}

// DefaultPolicy leaves room for a busy office behind one address and for large
// mail senders, and is far below what one host needs to exhaust a service.
func DefaultPolicy() Policy {
	return Policy{Mode: ModeEnforce, ConnectionsPerAddress: 25, Allowlist: []string{}}
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
	if _, err := parseNetworks(p.Allowlist); err != nil {
		return err
	}
	return nil
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
