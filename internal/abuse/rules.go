package abuse

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Rules are an administrator's own allow and deny decisions. They travel with
// the policy, so a change reaches every service without a restart.
//
// Allow beats deny, so one host can be let through a denied range without
// restating the rest of it. An allow rule never skips virus or spam scanning:
// a sender's address is easily forged, so all it can do is cancel a deny.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"

	// DirectionInbound covers clients connecting here and mail from outside.
	DirectionInbound = "inbound"
	// DirectionOutbound covers where mail leaving here is going.
	DirectionOutbound = "outbound"
	DirectionBoth     = "both"

	// Protocols a rule can name. Empty means all of them.
	ProtocolSMTP    = "smtp"
	ProtocolIMAP    = "imap"
	ProtocolPOP3    = "pop3"
	ProtocolSieve   = "sieve"
	ProtocolWebmail = "webmail"
	ProtocolAdmin   = "admin"

	// RefusedRule counts what a deny rule turned away.
	RefusedRule = "rule"

	maxRules    = 2000
	maxRuleNote = 200
)

// Rule is one allow or deny decision. Value is an address or network, a domain
// (subdomains included) or a full mail address.
type Rule struct {
	Action    string `toml:"action" json:"action"`
	Direction string `toml:"direction" json:"direction"`
	Value     string `toml:"value" json:"value"`
	// Protocols is a comma-separated list, empty for all. It only narrows a
	// rule on an address or network: domains and mail addresses are about mail.
	Protocols string `toml:"protocols,omitempty" json:"protocols,omitempty"`
	// Expires is an RFC 3339 time, empty for never.
	Expires string `toml:"expires,omitempty" json:"expires,omitempty"`
	Note    string `toml:"note,omitempty" json:"note,omitempty"`
}

// compiledRule is a Rule ready to match.
type compiledRule struct {
	Rule
	network   *net.IPNet
	domain    string
	address   string
	protocols map[string]bool
	expires   time.Time
}

func (c compiledRule) live(now time.Time) bool {
	return c.expires.IsZero() || now.Before(c.expires)
}

func (c compiledRule) covers(direction string) bool {
	return c.Direction == DirectionBoth || c.Direction == direction
}

func (c compiledRule) onProtocol(protocol string) bool {
	return len(c.protocols) == 0 || c.protocols[protocol]
}

func compileRule(r Rule) (compiledRule, error) {
	c := compiledRule{Rule: r}
	switch r.Action {
	case ActionAllow, ActionDeny:
	default:
		return c, fmt.Errorf("a rule's action must be allow or deny, not %q", r.Action)
	}
	switch r.Direction {
	case DirectionInbound, DirectionOutbound, DirectionBoth:
	default:
		return c, fmt.Errorf("a rule's direction must be inbound, outbound or both, not %q", r.Direction)
	}
	if len(r.Note) > maxRuleNote {
		return c, fmt.Errorf("keep a rule's note under %d characters", maxRuleNote)
	}
	if r.Expires != "" {
		expires, err := time.Parse(time.RFC3339, r.Expires)
		if err != nil {
			return c, fmt.Errorf("%q is not a valid expiry time", r.Expires)
		}
		c.expires = expires
	}
	value := strings.ToLower(strings.TrimSpace(r.Value))
	c.Value = value
	switch {
	case value == "":
		return c, errors.New("a rule needs an address, network, domain or mail address")
	case strings.Contains(value, "@"):
		local, domain, _ := strings.Cut(value, "@")
		if local == "" || !validDomain(domain) || strings.ContainsAny(value, " <>\"") {
			return c, fmt.Errorf("%q is not a mail address", r.Value)
		}
		c.address = value
	case net.ParseIP(value) != nil || strings.Contains(value, "/"):
		networks, err := parseNetworks([]string{value})
		if err != nil {
			return c, err
		}
		c.network = networks[0]
	case validDomain(value):
		c.domain = value
	default:
		return c, fmt.Errorf("%q is not an address, network, domain or mail address", r.Value)
	}
	for _, protocol := range strings.Split(r.Protocols, ",") {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		switch protocol {
		case "":
			continue
		case ProtocolSMTP, ProtocolIMAP, ProtocolPOP3, ProtocolSieve, ProtocolWebmail, ProtocolAdmin:
		default:
			return c, fmt.Errorf("%q is not a protocol a rule can name", protocol)
		}
		if c.network == nil {
			return c, errors.New("only a rule on an address or network can name protocols")
		}
		if c.protocols == nil {
			c.protocols = map[string]bool{}
		}
		c.protocols[protocol] = true
	}
	// A rule outbound on an address is about the server mail goes to, which has
	// no protocol to choose: it's always SMTP.
	if c.network != nil && r.Direction == DirectionOutbound && len(c.protocols) > 0 {
		return c, errors.New("an outbound rule can't name protocols")
	}
	return c, nil
}

func validDomain(domain string) bool {
	if !strings.Contains(domain, ".") || len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	// No top-level domain is all digits, so this is a mistyped address, and
	// taking it for a domain would be a rule that quietly matches nothing.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && r < 0x80 {
				return false
			}
		}
	}
	return true
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	if len(rules) > maxRules {
		return nil, fmt.Errorf("a policy can hold %d rules", maxRules)
	}
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		c, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decide applies allow-beats-deny over the rules match accepts.
func (e *Engine) decide(match func(compiledRule) bool) (Rule, bool) {
	if e == nil {
		return Rule{}, false
	}
	now := time.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.policy.Mode == ModeOff {
		return Rule{}, false
	}
	var deny *compiledRule
	for i := range e.rules {
		r := &e.rules[i]
		if !r.live(now) || !match(*r) {
			continue
		}
		if r.Action == ActionAllow {
			return Rule{}, false
		}
		if deny == nil {
			deny = r
		}
	}
	if deny == nil {
		return Rule{}, false
	}
	return deny.Rule, true
}

// refusal counts a deny, and in log mode lets it through having counted it.
func (e *Engine) refusal(r Rule, denied bool, subject string) (Rule, bool) {
	if !denied {
		return Rule{}, false
	}
	e.Refused(RefusedRule)
	e.log.Info("Refused by a rule", "subject", subject, "rule", r.Value, "direction", r.Direction, "mode", e.Policy().Mode)
	return r, e.Policy().Mode == ModeEnforce
}

// DenyPeer reports whether a rule refuses a client at addr on protocol.
func (e *Engine) DenyPeer(addr, protocol string) (Rule, bool) {
	r, denied := e.WouldDenyPeer(addr, protocol)
	return e.refusal(r, denied, addr)
}

// WouldDenyPeer is DenyPeer without counting a refusal, for asking in advance.
func (e *Engine) WouldDenyPeer(addr, protocol string) (Rule, bool) {
	ip := hostIP(addr)
	if ip == nil || e == nil || e.Exempt(addr) {
		// The allowlist is what keeps an operator from locking themselves out.
		return Rule{}, false
	}
	return e.decide(func(c compiledRule) bool {
		return c.network != nil && c.covers(DirectionInbound) && c.onProtocol(protocol) && c.network.Contains(ip)
	})
}

// DenySender reports whether a rule refuses mail arriving from sender.
func (e *Engine) DenySender(sender string) (Rule, bool) {
	sender = strings.ToLower(strings.TrimSpace(sender))
	if sender == "" {
		return Rule{}, false // a bounce, which has no sender to judge
	}
	r, denied := e.decide(func(c compiledRule) bool { return c.covers(DirectionInbound) && c.matchesMail(sender) })
	return e.refusal(r, denied, sender)
}

// DenyRecipient reports whether a rule refuses mail leaving for recipient.
func (e *Engine) DenyRecipient(recipient string) (Rule, bool) {
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	r, denied := e.decide(func(c compiledRule) bool { return c.covers(DirectionOutbound) && c.matchesMail(recipient) })
	return e.refusal(r, denied, recipient)
}

// DenyDestination reports whether a rule refuses delivery to the mail server at ip.
func (e *Engine) DenyDestination(ip net.IP) (Rule, bool) {
	r, denied := e.decide(func(c compiledRule) bool {
		return c.network != nil && c.covers(DirectionOutbound) && c.network.Contains(ip)
	})
	return e.refusal(r, denied, ip.String())
}

// exempts reports whether this allow rule exempts its network from limits and
// blocks, as the allowlist did. A rule naming protocols doesn't: letting a
// relay through on SMTP is no reason to stop counting its failed IMAP
// passwords.
func (c compiledRule) exempts(now time.Time) bool {
	return c.Action == ActionAllow && c.network != nil && len(c.protocols) == 0 && c.covers(DirectionInbound) && c.live(now)
}

// exemptNetworks lists what is never limited or blocked. The caller holds e.mu.
func (e *Engine) exemptNetworks(now time.Time) []*net.IPNet {
	out := append([]*net.IPNet{}, e.exempt...)
	for i := range e.rules {
		if e.rules[i].exempts(now) {
			out = append(out, e.rules[i].network)
		}
	}
	return out
}

// AccessControlRules turns the older [access_control] lists into rules. Those
// lists only ever applied to SMTP, so the addresses keep to it. An entry no
// rule can hold, such as a bare top-level domain the old lists ignored, is
// returned in skipped rather than failing the rest.
func AccessControlRules(allowIPs, denyIPs, allowDomains, denyDomains []string) (rules []Rule, skipped []string) {
	add := func(action, protocols string, values []string) {
		for _, value := range values {
			r := Rule{Action: action, Direction: DirectionInbound, Value: strings.TrimSpace(value), Protocols: protocols, Note: "From [access_control]"}
			if r.Value == "" {
				continue
			}
			if _, err := compileRule(r); err != nil {
				skipped = append(skipped, value)
				continue
			}
			rules = append(rules, r)
		}
	}
	add(ActionAllow, ProtocolSMTP, allowIPs)
	add(ActionDeny, ProtocolSMTP, denyIPs)
	add(ActionAllow, "", allowDomains)
	add(ActionDeny, "", denyDomains)
	return rules, skipped
}

// AddRules appends rules the policy doesn't already have, and reports how
// many it added, so a migration run twice adds nothing the second time.
func (p Policy) AddRules(extra []Rule) (Policy, int) {
	have := map[string]bool{}
	key := func(r Rule) string {
		return r.Action + "|" + r.Direction + "|" + strings.ToLower(strings.TrimSpace(r.Value)) + "|" + r.Protocols
	}
	for _, r := range p.Rules {
		have[key(r)] = true
	}
	added := 0
	rules := append([]Rule{}, p.Rules...)
	for _, r := range extra {
		if have[key(r)] {
			continue
		}
		have[key(r)] = true
		rules = append(rules, r)
		added++
	}
	p.Rules = rules
	return p, added
}

// MoveAllowlist turns the allowlist into allow rules, which do everything it
// did: an allow rule on all protocols exempts its network from limits and
// blocks, and beats any deny. One list is easier to reason about than two
// that overlap.
func (p Policy) MoveAllowlist() (Policy, int) {
	if len(p.Allowlist) == 0 {
		if p.Allowlist == nil {
			p.Allowlist = []string{}
		}
		return p, 0
	}
	extra := make([]Rule, 0, len(p.Allowlist))
	for _, entry := range p.Allowlist {
		if entry = strings.TrimSpace(entry); entry != "" {
			extra = append(extra, Rule{Action: ActionAllow, Direction: DirectionInbound, Value: entry, Note: "From the allowlist"})
		}
	}
	p, added := p.AddRules(extra)
	p.Allowlist = []string{}
	return p, added
}

func (c compiledRule) matchesMail(address string) bool {
	if c.address != "" {
		return c.address == address
	}
	if c.domain == "" {
		return false
	}
	_, domain, ok := strings.Cut(address, "@")
	return ok && (domain == c.domain || strings.HasSuffix(domain, "."+c.domain))
}

func hostIP(addr string) net.IP {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	return net.ParseIP(addr)
}
