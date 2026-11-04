package abuse

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func ruleEngine(t *testing.T, mode string, rules ...Rule) *Engine {
	t.Helper()
	p := DefaultPolicy()
	p.Mode, p.Rules = mode, rules
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e := New("test", "", nil)
	e.Own(p)
	return e
}

func deny(direction, value string) Rule {
	return Rule{Action: ActionDeny, Direction: direction, Value: value}
}

func TestPeerRules(t *testing.T) {
	e := ruleEngine(t, ModeEnforce,
		deny(DirectionInbound, "203.0.113.0/24"),
		Rule{Action: ActionAllow, Direction: DirectionInbound, Value: "203.0.113.9"},
		Rule{Action: ActionDeny, Direction: DirectionBoth, Value: "198.51.100.1", Protocols: "imap, pop3"},
		deny(DirectionOutbound, "192.0.2.0/24"),
		deny(DirectionInbound, "2001:db8::/32"),
	)
	for _, c := range []struct {
		addr, protocol string
		denied         bool
	}{
		{"203.0.113.7:1234", ProtocolSMTP, true},
		{"203.0.113.7", ProtocolWebmail, true},
		{"203.0.113.9:1234", ProtocolSMTP, false}, // allow beats deny
		{"198.51.100.1", ProtocolIMAP, true},
		{"198.51.100.1", ProtocolSMTP, false}, // not a protocol it names
		{"192.0.2.1", ProtocolSMTP, false},    // outbound isn't about clients
		{"[2001:db8::5]:25", ProtocolSMTP, true},
		{"127.0.0.1", ProtocolSMTP, false},
		{"not an address", ProtocolSMTP, false},
	} {
		if _, denied := e.DenyPeer(c.addr, c.protocol); denied != c.denied {
			t.Errorf("%s on %s: denied = %v", c.addr, c.protocol, denied)
		}
	}
}

func TestMailRulesFollowDirection(t *testing.T) {
	e := ruleEngine(t, ModeEnforce,
		deny(DirectionInbound, "spam.example"),
		deny(DirectionOutbound, "rival.example"),
		deny(DirectionOutbound, "one@partner.example"),
		deny(DirectionBoth, "both.example"),
		Rule{Action: ActionAllow, Direction: DirectionInbound, Value: "good.spam.example"},
	)
	for sender, denied := range map[string]bool{
		"a@spam.example": true, "a@sub.spam.example": true, "A@SPAM.EXAMPLE": true,
		"a@good.spam.example": false, "a@notspam.example": false, "a@rival.example": false,
		"a@both.example": true, "": false,
	} {
		if _, got := e.DenySender(sender); got != denied {
			t.Errorf("sender %q: denied = %v", sender, got)
		}
	}
	for recipient, denied := range map[string]bool{
		"a@rival.example": true, "one@partner.example": true, "two@partner.example": false,
		"a@spam.example": false, "a@both.example": true,
	} {
		if _, got := e.DenyRecipient(recipient); got != denied {
			t.Errorf("recipient %q: denied = %v", recipient, got)
		}
	}
}

func TestDestinationRules(t *testing.T) {
	e := ruleEngine(t, ModeEnforce, deny(DirectionOutbound, "192.0.2.0/24"), deny(DirectionInbound, "198.51.100.0/24"))
	if _, denied := e.DenyDestination(net.ParseIP("192.0.2.9")); !denied {
		t.Error("an outbound network was not refused")
	}
	if _, denied := e.DenyDestination(net.ParseIP("198.51.100.9")); denied {
		t.Error("an inbound rule stopped delivery")
	}
}

// Expired rules must stop applying by themselves, with nobody saving anything.
func TestRulesExpire(t *testing.T) {
	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	e := ruleEngine(t, ModeEnforce,
		Rule{Action: ActionDeny, Direction: DirectionInbound, Value: "203.0.113.1", Expires: past},
		Rule{Action: ActionDeny, Direction: DirectionInbound, Value: "203.0.113.2", Expires: future},
	)
	if _, denied := e.DenyPeer("203.0.113.1", ProtocolSMTP); denied {
		t.Error("an expired rule still applies")
	}
	if _, denied := e.DenyPeer("203.0.113.2", ProtocolSMTP); !denied {
		t.Error("a rule that hasn't expired doesn't apply")
	}
}

// An expired allow rule mustn't keep cancelling a deny.
func TestExpiredAllowDoesNotCancelDeny(t *testing.T) {
	e := ruleEngine(t, ModeEnforce,
		deny(DirectionInbound, "203.0.113.0/24"),
		Rule{Action: ActionAllow, Direction: DirectionInbound, Value: "203.0.113.1", Expires: time.Now().Add(-time.Minute).Format(time.RFC3339)},
	)
	if _, denied := e.DenyPeer("203.0.113.1", ProtocolSMTP); !denied {
		t.Error("an expired allow rule cancelled a deny")
	}
}

func TestModesApplyToRules(t *testing.T) {
	rule := deny(DirectionInbound, "203.0.113.0/24")
	if _, denied := ruleEngine(t, ModeLog, rule).DenyPeer("203.0.113.1", ProtocolSMTP); denied {
		t.Error("log mode refused")
	}
	if _, denied := ruleEngine(t, ModeOff, rule).DenyPeer("203.0.113.1", ProtocolSMTP); denied {
		t.Error("off refused")
	}
}

func TestAllowlistBeatsDenyRule(t *testing.T) {
	p := DefaultPolicy()
	p.Allowlist = []string{"203.0.113.1"}
	p.Rules = []Rule{deny(DirectionInbound, "203.0.113.0/24")}
	e := New("test", "", nil)
	e.Own(p)
	if _, denied := e.DenyPeer("203.0.113.1", ProtocolAdmin); denied {
		t.Error("the allowlist didn't protect its address")
	}
}

func TestAllowRuleExemptsFromLimits(t *testing.T) {
	e := ruleEngine(t, ModeEnforce, Rule{Action: ActionAllow, Direction: DirectionInbound, Value: "203.0.113.0/24"})
	if !e.Exempt("203.0.113.1") {
		t.Error("an inbound allow rule should exempt its network")
	}
	e = ruleEngine(t, ModeEnforce, Rule{Action: ActionAllow, Direction: DirectionOutbound, Value: "203.0.113.0/24"})
	if e.Exempt("203.0.113.1") {
		t.Error("an outbound allow rule says nothing about clients")
	}
}

func TestInvalidRulesAreRefused(t *testing.T) {
	for _, r := range []Rule{
		{Action: "maybe", Direction: DirectionInbound, Value: "example.org"},
		{Action: ActionDeny, Direction: "sideways", Value: "example.org"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: ""},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "not a thing"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "localhost"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "300.1.1.1"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "10.0.0.0/99"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "@example.org"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "example.org", Protocols: "imap"},
		{Action: ActionDeny, Direction: DirectionOutbound, Value: "192.0.2.1", Protocols: "smtp"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "192.0.2.1", Protocols: "gopher"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "192.0.2.1", Expires: "soon"},
		{Action: ActionDeny, Direction: DirectionInbound, Value: "192.0.2.1", Note: strings.Repeat("x", 201)},
	} {
		p := DefaultPolicy()
		p.Rules = []Rule{r}
		if err := p.Validate(); err == nil {
			t.Errorf("%+v was accepted", r)
		}
	}
}

// The allowlist becomes allow rules that do everything it did, once.
func TestMoveAllowlist(t *testing.T) {
	p := Policy{Allowlist: []string{"198.51.100.7", " 2001:db8::/48 ", ""}}.WithDefaults()
	if len(p.Allowlist) != 0 || len(p.Rules) != 2 {
		t.Fatalf("allowlist %v rules %+v", p.Allowlist, p.Rules)
	}
	again, added := Policy{Allowlist: []string{"198.51.100.7"}, Rules: p.Rules}.MoveAllowlist()
	if added != 0 || len(again.Rules) != 2 {
		t.Fatalf("moved twice: added %d, %+v", added, again.Rules)
	}
	p.Rules = append(p.Rules, Rule{Action: ActionDeny, Direction: DirectionInbound, Value: "198.51.100.0/24"})
	e := New("test", "", nil)
	e.Own(p)
	if !e.Exempt("198.51.100.7:25") || !e.Exempt("2001:db8::1") {
		t.Error("a moved address lost its exemption")
	}
	if _, denied := e.DenyPeer("198.51.100.7", ProtocolIMAP); denied {
		t.Error("a moved address was denied by a wider rule")
	}
	if _, err := e.BlockAddress(context.Background(), "198.51.100.7", "", "test", time.Hour); err == nil {
		t.Error("a moved address could be blocked by hand")
	}
	if plan := e.Plan(); len(plan.Allow) != 2 {
		t.Errorf("firewall allows %v", plan.Allow)
	}
}

// An allow rule for one protocol lets the address through there, but isn't a
// pass from limits on every other protocol.
func TestProtocolAllowDoesNotExempt(t *testing.T) {
	p := DefaultPolicy()
	p.Rules = []Rule{{Action: ActionAllow, Direction: DirectionInbound, Value: "192.0.2.5", Protocols: "smtp"}}
	e := New("test", "", nil)
	e.Own(p)
	if e.Exempt("192.0.2.5") {
		t.Error("an SMTP-only allow exempted the address everywhere")
	}
}

func TestAccessControlRules(t *testing.T) {
	rules, skipped := AccessControlRules([]string{"192.0.2.1"}, []string{"203.0.113.0/24"}, []string{"partner.example"}, []string{"com", "spam.example"})
	if len(skipped) != 1 || skipped[0] != "com" {
		t.Errorf("skipped %v", skipped)
	}
	if len(rules) != 4 {
		t.Fatalf("rules %+v", rules)
	}
	if rules[0].Action != ActionAllow || rules[0].Protocols != ProtocolSMTP || rules[1].Action != ActionDeny || rules[1].Protocols != ProtocolSMTP {
		t.Errorf("address rules %+v", rules[:2])
	}
	if rules[2].Protocols != "" || rules[3].Value != "spam.example" {
		t.Errorf("domain rules %+v", rules[2:])
	}
}

// A policy published in the old form reads as rules on every service, and
// receiving it again isn't a change.
func TestReceivedAllowlistReadsAsRules(t *testing.T) {
	e := New("test", "", nil)
	changes := 0
	e.OnPolicy(func(Policy) { changes++ })
	old := DefaultPolicy()
	old.Allowlist = []string{"198.51.100.7"}
	e.receive(old)
	e.receive(old)
	p := e.Policy()
	if len(p.Allowlist) != 0 || len(p.Rules) != 1 || p.Rules[0].Value != "198.51.100.7" || !e.Exempt("198.51.100.7") {
		t.Fatalf("policy %+v", p)
	}
	if changes != 1 {
		t.Fatalf("%d changes for one policy", changes)
	}
}
