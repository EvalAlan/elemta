package abuse

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"
)

const keyEnforcers = "elemta:abuse:enforcers"

// Enforcer is the last report from something applying blocks outside the
// services, so the console can show it working rather than assume it.
type Enforcer struct {
	Name    string    `json:"name"`
	Host    string    `json:"host"`
	Mode    string    `json:"mode"`
	Entries int       `json:"entries"`
	Dropped int64     `json:"dropped"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

// ReportEnforcer records an enforcer's state.
func (e *Engine) ReportEnforcer(ctx context.Context, r Enforcer) error {
	r.At = time.Now().UTC()
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	client := e.connect()
	if client == nil {
		return errNoValkey
	}
	return client.Do(ctx, client.B().Hset().Key(keyEnforcers).FieldValue().FieldValue(r.Name+"@"+r.Host, string(raw)).Build()).Error()
}

// Enforcers returns the latest report from each.
func (e *Engine) Enforcers(ctx context.Context) []Enforcer {
	out := []Enforcer{}
	client := e.valkey()
	if client == nil {
		return out
	}
	rows, err := client.Do(ctx, client.B().Hgetall().Key(keyEnforcers).Build()).AsStrMap()
	if err != nil {
		return out
	}
	for _, raw := range rows {
		var r Enforcer
		if json.Unmarshal([]byte(raw), &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Host < out[j].Name+out[j].Host })
	return out
}

// FirewallEntry is one thing for the firewall to drop.
type FirewallEntry struct {
	Target  string
	Seconds int
}

// FirewallPlan is what the host agent should apply.
type FirewallPlan struct {
	Mode    string
	Allow   []string
	Entries []FirewallEntry
}

// Plan works out the firewall's contents. It leaves out anything touching the
// allowlist, and addresses inside a blocked network: nftables refuses
// overlapping intervals, which would fail the whole update.
func (e *Engine) Plan() FirewallPlan {
	p := e.Policy()
	plan := FirewallPlan{Mode: p.Firewall, Allow: []string{}}
	if p.Mode != ModeEnforce {
		plan.Mode = FirewallOff
	}
	exempt, _ := parseNetworks(p.Allowlist)
	for _, n := range exempt {
		plan.Allow = append(plan.Allow, n.String())
	}
	blocks := e.Blocks()
	networks := []*net.IPNet{}
	for _, b := range blocks {
		if _, n, err := net.ParseCIDR(b.Network); err == nil {
			networks = append(networks, n)
		}
	}
	covered := func(target string) bool {
		_, self, selfErr := net.ParseCIDR(target)
		ip := net.ParseIP(target)
		for _, n := range networks {
			if selfErr == nil {
				if n.String() != self.String() && n.Contains(self.IP) {
					ones, _ := n.Mask.Size()
					own, _ := self.Mask.Size()
					if ones < own {
						return true
					}
				}
			} else if ip != nil && n.Contains(ip) {
				return true
			}
		}
		return false
	}
	now := time.Now()
	for _, b := range blocks {
		seconds := int(b.Until.Sub(now).Seconds())
		if seconds < 1 || e.overlapsExempt(b.Network) || covered(b.Network) {
			continue
		}
		plan.Entries = append(plan.Entries, FirewallEntry{Target: b.Network, Seconds: seconds})
	}
	sort.Slice(plan.Entries, func(i, j int) bool {
		return strings.Compare(plan.Entries[i].Target, plan.Entries[j].Target) < 0
	})
	return plan
}

// SyncNow reads the shared state once, for commands that don't run the loop.
// It reports whether Valkey answered: a plan from a stale view must not be
// mistaken for the real one.
func (e *Engine) SyncNow(ctx context.Context) bool {
	e.sync(ctx)
	return e.Shared(ctx)
}
