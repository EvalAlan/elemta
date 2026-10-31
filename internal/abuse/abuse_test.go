package abuse

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

func blockPolicy() Policy {
	p := DefaultPolicy()
	p.FailuresPerAddress = 3
	return p
}

func fail(e *Engine, addr string, n int) {
	for i := 0; i < n; i++ {
		e.Failure(context.Background(), addr, "imap", "dana@example.com")
	}
}

func TestFailuresAcrossServicesBlockAnAddress(t *testing.T) {
	e := testEngine(t, blockPolicy())
	ctx := context.Background()
	e.Failure(ctx, "203.0.113.9", "smtp", "dana@example.com")
	e.Failure(ctx, "203.0.113.9:443", "webmail", "lee@example.com")
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("blocked below the limit")
	}
	e.Failure(ctx, "203.0.113.9", "imap", "sam@example.com")
	b, blocked := e.Blocked("203.0.113.9:1234")
	if !blocked {
		t.Fatal("not blocked at the limit, spread over services and accounts")
	}
	if b.Service != "imap" || b.Strikes != 1 {
		t.Fatalf("block = %+v", b)
	}
	if _, blocked := e.Blocked("198.51.100.1"); blocked {
		t.Fatal("another address was blocked")
	}
}

// The rule the whole design rests on: failures never block an account.
func TestAccountsAreCountedButNeverBlocked(t *testing.T) {
	e := testEngine(t, blockPolicy())
	for i := 0; i < 50; i++ {
		e.Failure(context.Background(), "203.0.113."+strconv.Itoa(i), "imap", "Dana@Example.com")
	}
	if _, blocked := e.Blocked("198.51.100.1"); blocked {
		t.Fatal("an uninvolved address was blocked")
	}
	accounts := e.Accounts(context.Background())
	if len(accounts) != 1 || accounts[0].Account != "dana@example.com" || accounts[0].Failures != 50 {
		t.Fatalf("accounts = %+v", accounts)
	}
}

func TestRepeatBlocksEscalateToTheCeiling(t *testing.T) {
	p := DefaultPolicy()
	for strikes, want := range map[int]time.Duration{1: 15 * time.Minute, 2: time.Hour, 3: 4 * time.Hour, 4: 16 * time.Hour, 5: 24 * time.Hour, 50: 24 * time.Hour} {
		if got := blockDuration(p, strikes); got != want {
			t.Errorf("strike %d = %s, want %s", strikes, got, want)
		}
	}
}

func TestExemptAddressesAreNeverBlocked(t *testing.T) {
	p := blockPolicy()
	p.Allowlist = []string{"198.51.100.0/24"}
	e := testEngine(t, p)
	fail(e, "198.51.100.7", 10)
	fail(e, "127.0.0.1", 10)
	if _, blocked := e.Blocked("198.51.100.7"); blocked {
		t.Fatal("an allowlisted address was blocked")
	}
	if _, blocked := e.Blocked("127.0.0.1"); blocked {
		t.Fatal("loopback was blocked")
	}
	if _, err := e.BlockAddress(context.Background(), "198.51.100.7", "", "root", time.Hour); err == nil {
		t.Fatal("an allowlisted address was blocked by hand")
	}
}

func TestLogModeBlocksNothingButRecordsIt(t *testing.T) {
	p := blockPolicy()
	p.Mode = ModeLog
	e := testEngine(t, p)
	fail(e, "203.0.113.9", 3)
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("log mode blocked an address")
	}
	if len(e.Blocks()) != 0 {
		t.Fatal("log mode stored a block")
	}
	events := e.Events(context.Background())
	if len(events) != 1 || events[0].Action != "would-block" {
		t.Fatalf("events = %+v", events)
	}
}

func TestUnblockForgetsTheHistory(t *testing.T) {
	e := testEngine(t, blockPolicy())
	ctx := context.Background()
	fail(e, "203.0.113.9", 3)
	if err := e.Unblock(ctx, "203.0.113.9", "root"); err != nil {
		t.Fatal(err)
	}
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("still blocked")
	}
	fail(e, "203.0.113.9", 3)
	if b, blocked := e.Blocked("203.0.113.9"); !blocked || b.Strikes != 1 {
		t.Fatalf("after unblocking the next block = %+v, %v", b, blocked)
	}
}

func TestManualBlock(t *testing.T) {
	e := testEngine(t, DefaultPolicy())
	b, err := e.BlockAddress(context.Background(), "[2001:db8:1:2::9]:993", "", "root", time.Hour)
	if err != nil || b.Network != "2001:db8:1:2::" || !b.Manual {
		t.Fatalf("block = %+v, %v", b, err)
	}
	if _, blocked := e.Blocked("2001:db8:1:2::5"); !blocked {
		t.Fatal("the rest of the /64 wasn't blocked")
	}
	if _, err := e.BlockAddress(context.Background(), "nonsense", "", "root", time.Hour); err == nil {
		t.Fatal("accepted something that isn't an address")
	}
}

func TestNilEngineIsHarmless(t *testing.T) {
	var e *Engine
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("a nil engine blocked")
	}
	e.Failure(context.Background(), "203.0.113.9", "imap", "dana@example.com")
}

// Two services, one Valkey. Set ELEMTA_TEST_VALKEY_ADDR to run it.
func TestServicesShareBlocksThroughValkey(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("ELEMTA_TEST_VALKEY_ADDR not set")
	}
	ctx := context.Background()
	mta, mailbox := New("mta", addr, nil), New("mailbox", addr, nil)
	owner := New("admin", addr, nil)
	p := blockPolicy()
	owner.Own(p)
	if err := owner.Publish(ctx, p); err != nil {
		t.Fatal(err)
	}
	mta.sync(ctx)
	mailbox.sync(ctx)
	if mta.Policy().FailuresPerAddress != 3 || mailbox.Policy().FailuresPerAddress != 3 {
		t.Fatal("the policy didn't reach the services")
	}
	const attacker = "203.0.113.77"
	t.Cleanup(func() { _ = owner.Unblock(ctx, attacker, "test") })
	_ = owner.Unblock(ctx, attacker, "test")
	mta.Failure(ctx, attacker, "smtp", "dana@example.com")
	mailbox.Failure(ctx, attacker, "imap", "dana@example.com")
	mta.Failure(ctx, attacker, "smtp", "lee@example.com")
	if _, blocked := mta.Blocked(attacker); !blocked {
		t.Fatal("failures on two services didn't add up")
	}
	mailbox.sync(ctx)
	if _, blocked := mailbox.Blocked(attacker); !blocked {
		t.Fatal("the block didn't reach the other service")
	}
	if err := owner.Unblock(ctx, attacker, "root"); err != nil {
		t.Fatal(err)
	}
	mta.sync(ctx)
	mailbox.sync(ctx)
	if _, blocked := mta.Blocked(attacker); blocked {
		t.Fatal("the unblock didn't reach a service")
	}
	if len(owner.Events(ctx)) == 0 {
		t.Fatal("no history recorded")
	}
}

// Valkey going away must never lock anyone out, and a service still protects
// itself on its own.
func TestUnreachableValkeyFailsOpen(t *testing.T) {
	e := New("mta", "127.0.0.1:1", nil)
	p := blockPolicy()
	e.receive(p)
	if err := e.Publish(context.Background(), p); err == nil {
		t.Log("publish reported success with no Valkey")
	}
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("an address started out blocked")
	}
	// An address that doesn't answer at all must not slow a sign-in down: only
	// the background sync may wait on connecting.
	hung := New("mta", "203.0.113.200:6379", nil)
	hung.receive(p)
	started := time.Now()
	fail(hung, "203.0.113.9", 3)
	if took := time.Since(started); took > 200*time.Millisecond {
		t.Fatalf("failed sign-ins waited %s on Valkey", took)
	}
	fail(e, "203.0.113.9", 3)
	if _, blocked := e.Blocked("203.0.113.9"); !blocked {
		t.Fatal("the local fallback didn't block")
	}
	if _, ok := e.Acquire("198.51.100.1:1"); !ok {
		t.Fatal("a connection was refused because Valkey was away")
	}
}
