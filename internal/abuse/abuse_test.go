package abuse

import (
	"context"
	"strings"
	"testing"
)

func TestNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":                "203.0.113.9",
		"203.0.113.9:143":            "203.0.113.9",
		"[2001:db8:1:2:3:4:5:6]:993": "2001:db8:1:2::",
		"2001:db8:1:2:9:9:9:9":       "2001:db8:1:2::",
		"::ffff:203.0.113.9":         "203.0.113.9",
		"not an address":             "",
		"":                           "",
	} {
		if got := Network(in); got != want {
			t.Errorf("Network(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	good := DefaultPolicy()
	good.Allowlist = []string{"203.0.113.9", "198.51.100.0/24", "2001:db8::/32", " "}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Policy){
		"mode":      func(p *Policy) { p.Mode = "maybe" },
		"limit":     func(p *Policy) { p.ConnectionsPerAddress = 0 },
		"allowlist": func(p *Policy) { p.Allowlist = []string{"203.0.113.999"} },
	} {
		p := DefaultPolicy()
		change(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func testEngine(t *testing.T, p Policy) *Engine {
	t.Helper()
	e := New("test", "", nil)
	if err := e.Publish(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestConnectionLimit(t *testing.T) {
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 2
	e := testEngine(t, p)
	first, ok := e.Acquire("203.0.113.9:1000")
	if !ok {
		t.Fatal("first connection refused")
	}
	if _, ok = e.Acquire("203.0.113.9:1001"); !ok {
		t.Fatal("second connection refused")
	}
	if _, ok = e.Acquire("203.0.113.9:1002"); ok {
		t.Fatal("third connection accepted")
	}
	if _, ok = e.Acquire("198.51.100.1:1000"); !ok {
		t.Fatal("another address was refused")
	}
	first()
	first() // releasing twice must not free two slots
	if _, ok = e.Acquire("203.0.113.9:1003"); !ok {
		t.Fatal("a released slot wasn't reusable")
	}
	if _, ok = e.Acquire("203.0.113.9:1004"); ok {
		t.Fatal("one release freed two slots")
	}
}

func TestIPv6CountsAsOneNetwork(t *testing.T) {
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 1
	e := testEngine(t, p)
	if _, ok := e.Acquire("[2001:db8:1:2::1]:1000"); !ok {
		t.Fatal("first refused")
	}
	if _, ok := e.Acquire("[2001:db8:1:2::2]:1000"); ok {
		t.Fatal("a second address in the /64 got its own limit")
	}
}

func TestExemptAddressesAreNeverLimited(t *testing.T) {
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 1
	p.Allowlist = []string{"198.51.100.0/24"}
	e := testEngine(t, p)
	for i := 0; i < 5; i++ {
		for _, addr := range []string{"198.51.100.7:1", "127.0.0.1:1", "[::1]:1"} {
			if _, ok := e.Acquire(addr); !ok {
				t.Fatalf("%s was limited", addr)
			}
		}
	}
}

func TestModes(t *testing.T) {
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 1
	p.Mode = ModeLog
	e := testEngine(t, p)
	e.Acquire("203.0.113.9:1")
	if _, ok := e.Acquire("203.0.113.9:2"); !ok {
		t.Fatal("log mode refused a connection")
	}
	p.Mode = ModeOff
	if err := e.Publish(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Acquire("203.0.113.9:3"); !ok {
		t.Fatal("off refused a connection")
	}
}

func TestOnPolicyRunsForPublishedPolicies(t *testing.T) {
	e := New("test", "", nil)
	var got []int
	e.OnPolicy(func(p Policy) { got = append(got, p.ConnectionsPerAddress) })
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 7
	if err := e.Publish(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := e.Publish(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("callbacks = %v", got)
	}
	late := 0
	e.OnPolicy(func(p Policy) { late = p.ConnectionsPerAddress })
	if late != 7 {
		t.Fatal("a late subscriber missed the policy in force")
	}
}

func TestPublishRefusesAnInvalidPolicy(t *testing.T) {
	e := New("test", "", nil)
	p := DefaultPolicy()
	p.Allowlist = []string{"nonsense"}
	err := e.Publish(context.Background(), p)
	if err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("publish = %v", err)
	}
}
