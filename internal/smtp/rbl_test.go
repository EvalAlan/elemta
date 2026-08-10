package smtp

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Blocklists refuse mail on the strength of a third party's answer over UDP, so
// these tests are mostly about the ways that answer can be wrong, absent, or
// about something other than the sender.

// fakeResolver answers blocklist queries without a network, and without a live
// blocklist's opinion of whatever machine is running the tests.
type fakeResolver struct {
	mu    sync.Mutex
	a     map[string][]string // query name -> A records
	txt   map[string][]string
	err   map[string]error
	delay time.Duration
	// listEverythingIn answers any query under this zone as listed, whatever
	// address was reversed into it. The socket-level tests use it because the
	// test server binds [::] and the probe therefore arrives over IPv6
	// loopback: pinning the exact 32-nibble query name would make those tests
	// about the address family rather than about whether the server consults
	// the blocklist at all.
	listEverythingIn string
	queries          []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		a:   map[string][]string{},
		txt: map[string][]string{},
		err: map[string]error{},
	}
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	f.queries = append(f.queries, host)
	delay, err, records := f.delay, f.err[host], f.a[host]
	if f.listEverythingIn != "" && strings.HasSuffix(host, "."+f.listEverythingIn) {
		records = []string{"127.0.0.2"}
	}
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	out := make([]net.IPAddr, 0, len(records))
	for _, r := range records {
		out = append(out, net.IPAddr{IP: net.ParseIP(r)})
	}
	return out, nil
}

func (f *fakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if txt, ok := f.txt[host]; ok {
		return txt, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *fakeResolver) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.queries))
	copy(out, f.queries)
	return out
}

func mustRBL(t *testing.T, cfg *RBLConfig, resolver rblResolver) *RBLChecker {
	t.Helper()
	checker, err := NewRBLChecker(cfg, quietLogger())
	if err != nil {
		t.Fatalf("build checker: %v", err)
	}
	if resolver != nil {
		checker.resolver = resolver
	}
	return checker
}

func TestRBLQueryNameReversesTheAddress(t *testing.T) {
	name, err := rblQueryName(net.ParseIP("198.51.100.7"), "bl.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if name != "7.100.51.198.bl.example.org" {
		t.Errorf("query name = %q, want the octets reversed", name)
	}

	// RFC 5782 §2.4: IPv6 is queried as reversed nibbles.
	name, err = rblQueryName(net.ParseIP("2001:db8::1"), "bl.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".bl.example.org") || !strings.HasPrefix(name, "1.0.0.0.") {
		t.Errorf("IPv6 query name = %q, want reversed nibbles", name)
	}
	// 32 nibbles, each followed by a dot, then the zone.
	nibbles := strings.TrimSuffix(name, ".bl.example.org")
	if got := len(strings.Split(nibbles, ".")); got != 32 {
		t.Errorf("IPv6 query name has %d nibbles, want 32: %q", got, name)
	}
}

func TestRBLDisabledChecksNothing(t *testing.T) {
	resolver := newFakeResolver()
	for _, cfg := range []*RBLConfig{nil, {Enabled: false, Zones: []string{"bl.example.org"}}} {
		checker := mustRBL(t, cfg, resolver)
		if checker.Check(context.Background(), net.ParseIP("198.51.100.7")).Listed {
			t.Error("a disabled blocklist must not list anything")
		}
	}
	if len(resolver.asked()) != 0 {
		t.Errorf("a disabled blocklist must not query DNS: %v", resolver.asked())
	}
}

func TestRBLListedAndUnlisted(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.bl.example.org"] = []string{"127.0.0.2"}
	resolver.txt["7.100.51.198.bl.example.org"] = []string{"https://example.org/lookup/198.51.100.7"}

	checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)

	listed := checker.Check(context.Background(), net.ParseIP("198.51.100.7"))
	if !listed.Listed {
		t.Fatal("an address with a 127.0.0.2 answer should be listed")
	}
	if listed.Zone != "bl.example.org" || listed.Code != "127.0.0.2" {
		t.Errorf("decision = %+v, want the zone and code recorded", listed)
	}
	// The sender needs to know which list to appeal to.
	if !strings.Contains(listed.Message(), "bl.example.org") ||
		!strings.Contains(listed.Message(), "example.org/lookup") {
		t.Errorf("message should name the list and quote its reason: %q", listed.Message())
	}

	if checker.Check(context.Background(), net.ParseIP("203.0.113.9")).Listed {
		t.Error("an address with no answer must not be listed")
	}
}

// TestRBLIgnoresCodesAboutTheQuerier is the one that matters most.
//
// Blocklists answer in 127.0.0.0/8, and the range outside 127.0.0.0/24 is used
// to tell the *querier* something about themselves: Spamhaus returns
// 127.255.255.254 for querying through a public resolver and .255 for exceeding
// the query limit. Reading those as "listed" refuses every message from every
// sender, and reports each one as spam.
func TestRBLIgnoresCodesAboutTheQuerier(t *testing.T) {
	for _, code := range []string{"127.255.255.252", "127.255.255.254", "127.255.255.255"} {
		t.Run(code, func(t *testing.T) {
			resolver := newFakeResolver()
			resolver.a["7.100.51.198.bl.example.org"] = []string{code}
			checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)

			if checker.Check(context.Background(), net.ParseIP("198.51.100.7")).Listed {
				t.Errorf("%s is the blocklist talking about this server, not the sender; "+
					"treating it as a listing refuses all mail", code)
			}
		})
	}
}

// TestRBLFailsOpenOnResolverFailure: failing closed would turn a DNS outage
// into a mail outage — every message refused, from every sender, for as long as
// the resolver is unreachable.
func TestRBLFailsOpenOnResolverFailure(t *testing.T) {
	resolver := newFakeResolver()
	resolver.err["7.100.51.198.bl.example.org"] = errors.New("server misbehaving")

	checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)
	if checker.Check(context.Background(), net.ParseIP("198.51.100.7")).Listed {
		t.Error("a resolver failure must not be read as a listing")
	}
}

// TestRBLTimeoutDoesNotStallTheSession bounds the whole check, not each zone.
func TestRBLTimeoutDoesNotStallTheSession(t *testing.T) {
	resolver := newFakeResolver()
	resolver.delay = 5 * time.Second
	resolver.a["7.100.51.198.slow.example.org"] = []string{"127.0.0.2"}

	checker := mustRBL(t, &RBLConfig{
		Enabled: true,
		Zones:   []string{"slow.example.org"},
		Timeout: 1,
		Reject:  true,
	}, resolver)

	start := time.Now()
	decision := checker.Check(context.Background(), net.ParseIP("198.51.100.7"))
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("check took %v; a slow blocklist must not stall the session", elapsed)
	}
	if decision.Listed {
		t.Error("a check that timed out must not be read as a listing")
	}
}

func TestRBLQueriesEveryZoneAndOneListingIsEnough(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.second.example.org"] = []string{"127.0.0.10"}

	checker := mustRBL(t, &RBLConfig{
		Enabled: true,
		Zones:   []string{"first.example.org", "second.example.org"},
		Reject:  true,
	}, resolver)

	decision := checker.Check(context.Background(), net.ParseIP("198.51.100.7"))
	if !decision.Listed || decision.Zone != "second.example.org" {
		t.Errorf("decision = %+v, want a listing from the second zone", decision)
	}
}

func TestRBLSkipsConfiguredNetworks(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.bl.example.org"] = []string{"127.0.0.2"}

	checker := mustRBL(t, &RBLConfig{
		Enabled: true,
		Zones:   []string{"bl.example.org"},
		SkipIPs: []string{"198.51.100.0/24"},
		Reject:  true,
	}, resolver)

	if checker.Check(context.Background(), net.ParseIP("198.51.100.7")).Listed {
		t.Error("an address in skip_ips must not be checked")
	}
	if len(resolver.asked()) != 0 {
		t.Errorf("a skipped address must not cost a DNS query: %v", resolver.asked())
	}
}

func TestRBLCachesAnswers(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.bl.example.org"] = []string{"127.0.0.2"}

	checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)

	for i := 0; i < 5; i++ {
		if !checker.Check(context.Background(), net.ParseIP("198.51.100.7")).Listed {
			t.Fatal("expected a listing")
		}
	}
	// One A lookup, plus the TXT that went with it.
	if got := len(resolver.asked()); got != 1 {
		t.Errorf("made %d lookups for the same address, want 1 — a burst of "+
			"connections from one host should cost one query", got)
	}
}

// TestRBLCacheIsBounded: keyed by peer address and left to grow, the cache is a
// memory exhaustion vector — connecting once from each of many addresses is
// cheap for the sender and permanently expensive for us.
func TestRBLCacheIsBounded(t *testing.T) {
	cache := newRBLCache(10, time.Hour)
	for i := 0; i < 500; i++ {
		cache.put(net.IPv4(10, 0, byte(i/256), byte(i%256)).String(), RBLDecision{})
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()

	if size > 10 {
		t.Errorf("cache holds %d entries with a maximum of 10", size)
	}
}

// TestRBLCacheExpires: a delisted address has to be able to send again without
// restarting the server.
func TestRBLCacheExpires(t *testing.T) {
	cache := newRBLCache(10, 10*time.Millisecond)
	cache.put("198.51.100.7", RBLDecision{Listed: true, Zone: "bl.example.org"})

	if _, ok := cache.get("198.51.100.7"); !ok {
		t.Fatal("entry should be cached immediately after being stored")
	}
	time.Sleep(25 * time.Millisecond)
	if _, ok := cache.get("198.51.100.7"); ok {
		t.Error("an expired entry must not be served")
	}
}

// TestRBLReasonCannotWriteSMTPReplyLines: the TXT record comes from a third
// party, and anyone who can get themselves listed can often influence its text.
// SMTP replies are line-oriented, so a CRLF in it would let the blocklist write
// its own reply lines into our session.
func TestRBLReasonCannotWriteSMTPReplyLines(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.bl.example.org"] = []string{"127.0.0.2"}
	resolver.txt["7.100.51.198.bl.example.org"] = []string{
		"listed\r\n250 OK\r\nDATA\r\nInjected: header",
	}

	checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)
	decision := checker.Check(context.Background(), net.ParseIP("198.51.100.7"))

	if strings.ContainsAny(decision.Reason, "\r\n") {
		t.Errorf("reason still contains line breaks: %q", decision.Reason)
	}
	if strings.ContainsAny(decision.Message(), "\r\n") {
		t.Errorf("reply message still contains line breaks: %q", decision.Message())
	}
}

func TestRBLReasonIsLengthLimited(t *testing.T) {
	resolver := newFakeResolver()
	resolver.a["7.100.51.198.bl.example.org"] = []string{"127.0.0.2"}
	resolver.txt["7.100.51.198.bl.example.org"] = []string{strings.Repeat("x", 5000)}

	checker := mustRBL(t, &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}, resolver)
	decision := checker.Check(context.Background(), net.ParseIP("198.51.100.7"))

	// RFC 5321 §4.5.3.1.5 caps a reply line at 512 octets, so an unbounded TXT
	// would produce a reply the client is entitled to reject.
	if len(decision.Message()) > 512 {
		t.Errorf("reply is %d bytes; RFC 5321 caps a reply line at 512", len(decision.Message()))
	}
}

func TestRBLRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		cfg  *RBLConfig
	}{
		{"enabled with no zones", &RBLConfig{Enabled: true}},
		{"zone that is not a domain", &RBLConfig{Enabled: true, Zones: []string{"notadomain"}}},
		{"zone with a scheme", &RBLConfig{Enabled: true, Zones: []string{"http://bl.example.org"}}},
		{"unparseable skip network", &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, SkipIPs: []string{"nope"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRBLChecker(tc.cfg, quietLogger()); err == nil {
				t.Error("a blocklist that silently fails to load is a filter the operator thinks is running")
			}
		})
	}
}

// The unit tests above check the matcher. These check a running server actually
// consults it — the gap where a correct checker enforces nothing because it was
// never wired in.

func TestRBLRefusesListedPeerOverSMTP(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.RBL = &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	// The probe connects from loopback; list whatever address that turns out
	// to be, so the test is about the wiring and not the address family.
	resolver := newFakeResolver()
	resolver.listEverythingIn = "bl.example.org"
	server.rblChecker.resolver = resolver

	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")

	reply := p.cmd("MAIL FROM:<someone@example.com>")
	if !strings.HasPrefix(reply, "554") {
		t.Errorf("a listed peer should be refused with 554, got %q", reply)
	}
	if !strings.Contains(reply, "bl.example.org") {
		t.Errorf("the rejection should name the blocklist so the sender can appeal: %q", reply)
	}
}

// TestRBLDoesNotRefuseUnlistedPeer guards the other direction: a blocklist that
// refuses everything is worse than no blocklist.
func TestRBLDoesNotRefuseUnlistedPeer(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.RBL = &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: true}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	server.rblChecker.resolver = newFakeResolver() // nothing is listed

	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")

	if reply := p.cmd("MAIL FROM:<someone@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("an unlisted peer should be accepted, got %q", reply)
	}
}

// TestRBLTagModeDeliversTheMessage: tagging rather than rejecting is what makes
// a new blocklist safe to try, so a listing must not refuse anything.
func TestRBLTagModeDeliversTheMessage(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.RBL = &RBLConfig{Enabled: true, Zones: []string{"bl.example.org"}, Reject: false}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	resolver := newFakeResolver()
	resolver.listEverythingIn = "bl.example.org"
	server.rblChecker.resolver = resolver

	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	p := dialProbe(t, server.Addr().String())
	p.cmd("EHLO probe.example")

	if reply := p.cmd("MAIL FROM:<someone@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("tag-only mode must not refuse the sender, got %q", reply)
	}
}
