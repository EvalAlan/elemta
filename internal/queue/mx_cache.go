package queue

import (
	"context"
	"net"
	"sync"
	"time"
)

// cachingMXResolver remembers MX lookups for a short while.
//
// Every delivery attempt resolved MX from scratch. Go's resolver does not
// cache, so a queue draining a hundred messages to one domain asked for the
// same records a hundred times — latency on every send, and load on a resolver
// that gains nothing from being asked again.
//
// This wraps the resolver the handler already uses rather than adopting the
// larger DNS cache in internal/delivery. That one retries internally, and the
// handler retries too, so composing them would multiply attempts; it also
// hardcodes net.DefaultResolver, which makes anything built on it impossible to
// test without real DNS.
type cachingMXResolver struct {
	inner mxResolver
	ttl   time.Duration
	max   int

	mu      sync.Mutex
	entries map[string]*mxCacheEntry
	// now is swappable so expiry can be tested without sleeping.
	now func() time.Time
}

type mxCacheEntry struct {
	records []*net.MX
	expires time.Time
}

const (
	// defaultMXCacheTTL is deliberately short.
	//
	// Go's resolver does not expose record TTLs, so this is a fixed window
	// rather than the value DNS published. The consequence is that a domain
	// which moves its MX is not noticed until the window passes, and mail keeps
	// going to the old host until then. Minutes are enough to collapse a queue
	// drain into one lookup; hours would be trading correctness for very little.
	defaultMXCacheTTL = 5 * time.Minute

	// defaultMXCacheSize bounds the cache. Mail goes to an unbounded set of
	// domains, so a map that only grows is a leak in a long-running process.
	defaultMXCacheSize = 2048
)

func newCachingMXResolver(inner mxResolver, ttl time.Duration, max int) *cachingMXResolver {
	if ttl <= 0 {
		ttl = defaultMXCacheTTL
	}
	if max <= 0 {
		max = defaultMXCacheSize
	}
	return &cachingMXResolver{
		inner:   inner,
		ttl:     ttl,
		max:     max,
		entries: make(map[string]*mxCacheEntry),
		now:     time.Now,
	}
}

// LookupMX returns cached records when they are still fresh.
//
// Failures are never cached. A lookup can fail because a resolver hiccuped or a
// domain is briefly unreachable, and pinning that for the cache window would
// keep refusing a destination that had already recovered — turning a momentary
// blip into minutes of deferred mail. The handler's own retry loop is the right
// place to absorb those.
func (c *cachingMXResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if c == nil || c.inner == nil {
		return net.DefaultResolver.LookupMX(ctx, name)
	}

	if records, ok := c.get(name); ok {
		return records, nil
	}

	records, err := c.inner.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	c.put(name, records)
	return records, nil
}

func (c *cachingMXResolver) get(name string) ([]*net.MX, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[name]
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, name)
		return nil, false
	}
	// A copy: callers sort and reorder MX slices, and handing out the cached
	// backing array would let one delivery rearrange what every later one sees.
	out := make([]*net.MX, len(entry.records))
	copy(out, entry.records)
	return out, true
}

func (c *cachingMXResolver) put(name string, records []*net.MX) {
	stored := make([]*net.MX, len(records))
	copy(stored, records)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[name] = &mxCacheEntry{records: stored, expires: c.now().Add(c.ttl)}
}

// evictLocked makes room. Expired entries go first because they are free; if
// none have expired, the entry closest to expiry goes, which is the one whose
// value is about to run out anyway.
func (c *cachingMXResolver) evictLocked() {
	now := c.now()
	for name, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, name)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	var oldestName string
	var oldest time.Time
	for name, entry := range c.entries {
		if oldestName == "" || entry.expires.Before(oldest) {
			oldestName, oldest = name, entry.expires
		}
	}
	if oldestName != "" {
		delete(c.entries, oldestName)
	}
}
