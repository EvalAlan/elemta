package queue

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// A cache in front of DNS is only worth having if it stops asking, keeps
// answering the same thing, and lets go of what it knows soon enough that a
// domain moving its MX is noticed. These test all three, plus the failure this
// design deliberately avoids: caching an error.

type countingResolver struct {
	mu      sync.Mutex
	calls   map[string]int
	records []*net.MX
	err     error
}

func (r *countingResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[name]++
	if r.err != nil {
		return nil, r.err
	}
	return r.records, nil
}

func (r *countingResolver) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

func mx(host string, pref uint16) *net.MX { return &net.MX{Host: host, Pref: pref} }

// size lives here rather than beside the cache: nothing in the server needs it,
// and a method kept alive only by its tests is the kind of thing that later
// looks like real API.
func (c *cachingMXResolver) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func TestRepeatedLookupsAskDNSOnce(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("mx1.example.com.", 10)}}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	for i := 0; i < 25; i++ {
		records, err := cache.LookupMX(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 || records[0].Host != "mx1.example.com." {
			t.Fatalf("attempt %d returned %+v", i, records)
		}
	}
	if got := inner.count("example.com"); got != 1 {
		t.Errorf("asked DNS %d times for 25 deliveries; the cache is not working", got)
	}
}

func TestDifferentDomainsAreCachedSeparately(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("mx.example.", 10)}}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	for _, domain := range []string{"a.example", "b.example", "a.example", "b.example"} {
		if _, err := cache.LookupMX(context.Background(), domain); err != nil {
			t.Fatal(err)
		}
	}
	if inner.count("a.example") != 1 || inner.count("b.example") != 1 {
		t.Errorf("a=%d b=%d; each domain should be resolved once",
			inner.count("a.example"), inner.count("b.example"))
	}
}

// TestTheCacheLetsGo is the one that stops this being a correctness bug. Go's
// resolver does not expose record TTLs, so the window is fixed — but it has to
// actually expire, or a domain that moves its MX never gets mail again.
func TestTheCacheLetsGo(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("old.example.", 10)}}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	clock := time.Now()
	cache.now = func() time.Time { return clock }

	if _, err := cache.LookupMX(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// The domain moves.
	inner.records = []*net.MX{mx("new.example.", 10)}

	// Still inside the window: the old answer stands.
	records, _ := cache.LookupMX(context.Background(), "example.com")
	if records[0].Host != "old.example." {
		t.Errorf("inside the window the cache returned %q", records[0].Host)
	}

	clock = clock.Add(time.Minute + time.Second)
	records, err := cache.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Host != "new.example." {
		t.Errorf("after the window the cache still returned %q; an MX change would never be seen", records[0].Host)
	}
}

// TestFailuresAreNotCached. A resolver hiccup pinned for the cache window keeps
// refusing a destination that has already recovered, turning a momentary blip
// into minutes of deferred mail.
func TestFailuresAreNotCached(t *testing.T) {
	inner := &countingResolver{err: errors.New("SERVFAIL")}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	for i := 0; i < 3; i++ {
		if _, err := cache.LookupMX(context.Background(), "example.com"); err == nil {
			t.Fatal("expected the lookup to fail")
		}
	}
	if got := inner.count("example.com"); got != 3 {
		t.Errorf("DNS was asked %d times; a failure was cached and the domain stays broken", got)
	}

	// And once it recovers, the very next lookup succeeds.
	inner.err = nil
	inner.records = []*net.MX{mx("mx.example.", 10)}
	if _, err := cache.LookupMX(context.Background(), "example.com"); err != nil {
		t.Errorf("the domain recovered but the cache still refused it: %v", err)
	}
}

// TestCallersCannotCorruptTheCache: the handler sorts MX records by preference,
// and handing out the cached backing array would let one delivery rearrange
// what every later one sees.
func TestCallersCannotCorruptTheCache(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("first.example.", 10), mx("second.example.", 20)}}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	first, _ := cache.LookupMX(context.Background(), "example.com")
	first[0], first[1] = first[1], first[0]
	first[0].Host = "tampered.example."

	second, _ := cache.LookupMX(context.Background(), "example.com")
	if second[0].Host != "first.example." {
		t.Errorf("a previous caller's reordering leaked into the cache: %q", second[0].Host)
	}
}

// TestTheCacheIsBounded: mail goes to an unbounded set of domains, so a map
// that only grows is a leak in a process that runs for months.
func TestTheCacheIsBounded(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("mx.example.", 10)}}
	cache := newCachingMXResolver(inner, time.Hour, 50)

	for i := 0; i < 500; i++ {
		if _, err := cache.LookupMX(context.Background(), fmt.Sprintf("d%03d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if size := cache.size(); size > 50 {
		t.Errorf("cache holds %d entries with a limit of 50", size)
	}
}

func TestConcurrentLookupsAreSafe(t *testing.T) {
	inner := &countingResolver{records: []*net.MX{mx("mx.example.", 10)}}
	cache := newCachingMXResolver(inner, time.Minute, 100)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = cache.LookupMX(context.Background(), fmt.Sprintf("d%d.example", i%5))
		}(i)
	}
	wg.Wait()
}

// TestNoInnerResolverStillResolves keeps the zero value usable rather than a
// nil dereference on the delivery path.
func TestNoInnerResolverStillResolves(t *testing.T) {
	var cache *cachingMXResolver
	// Only asserting it does not panic; the lookup itself needs real DNS.
	_, _ = cache.LookupMX(context.Background(), "invalid.invalid")
}
