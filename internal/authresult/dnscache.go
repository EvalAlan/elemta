package authresult

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Resolver is the DNS surface verification needs. It matches spf.DNSResolver
// and is satisfied by *net.Resolver.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

const (
	// Go's resolver does not expose record TTLs, so answers are kept for a
	// fixed, short time. A minute is long enough to absorb a burst of mail from
	// one domain and short enough that a record the sender just fixed is seen
	// almost at once.
	txtCacheTTL = time.Minute
	// "No such record" is cached for less time than an answer: it is the
	// result a sender is most likely to be in the middle of correcting.
	txtNegativeCacheTTL = 30 * time.Second
	// txtCacheMaxEntries bounds memory. A server under a spam run sees an
	// unbounded number of distinct domains; when the cache fills, expired
	// entries are dropped and, failing that, the whole cache is.
	txtCacheMaxEntries = 4096
	// txtLookupTimeout bounds one shared lookup. Each caller still gives up
	// at its own deadline; this only stops an abandoned lookup running on.
	txtLookupTimeout = 30 * time.Second
)

type txtCacheEntry struct {
	records []string
	err     error
	expires time.Time
}

// cachingResolver caches TXT answers and folds concurrent lookups of one name
// into a single query.
//
// Every message costs at least one SPF and one DMARC TXT lookup, plus one per
// DKIM signature, all while the client waits at end-of-DATA. Under load most
// of these are for the same few domains, and sending each to the resolver
// separately is what turns a busy minute into a resolver that refuses work —
// at which point every check times out together and every waiting client
// gives up. Only TXT is cached: it is what SPF, DKIM, DMARC and ARC all start
// from, and the address lookups SPF sometimes makes are passed straight
// through.
type cachingResolver struct {
	Resolver
	now   func() time.Time
	group singleflight.Group

	mu      sync.Mutex
	entries map[string]txtCacheEntry
}

func newCachingResolver(upstream Resolver) *cachingResolver {
	return &cachingResolver{
		Resolver: upstream,
		now:      time.Now,
		entries:  make(map[string]txtCacheEntry),
	}
}

func (r *cachingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if records, err, ok := r.cached(name); ok {
		return records, err
	}

	// The lookup is shared, so it must not die with whichever caller happened
	// to start it; it runs detached under its own bound and each caller waits
	// only as long as its own context allows.
	result := r.group.DoChan(name, func() (interface{}, error) {
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), txtLookupTimeout)
		defer cancel()
		records, err := r.Resolver.LookupTXT(lookupCtx, name)
		r.store(name, records, err)
		return records, err
	})
	select {
	case res := <-result:
		records, _ := res.Val.([]string)
		return records, res.Err
	case <-ctx.Done():
		// Shaped as net.Resolver reports it, because the SPF library decides
		// temperror versus permerror by asking a *net.DNSError, and running
		// out of time is the textbook temporary failure.
		return nil, &net.DNSError{
			Err:         ctx.Err().Error(),
			Name:        name,
			IsTimeout:   errors.Is(ctx.Err(), context.DeadlineExceeded),
			IsTemporary: true,
			UnwrapErr:   ctx.Err(),
		}
	}
}

func (r *cachingResolver) cached(name string) ([]string, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[name]
	if !ok {
		return nil, nil, false
	}
	if !r.now().Before(entry.expires) {
		delete(r.entries, name)
		return nil, nil, false
	}
	return entry.records, entry.err, true
}

func (r *cachingResolver) store(name string, records []string, err error) {
	ttl := txtCacheTTL
	if err != nil {
		// A timeout or a failed server says nothing about the record and
		// caching it would spread one bad moment across a minute of mail.
		if !isNotFound(err) {
			return
		}
		ttl = txtNegativeCacheTTL
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.entries) >= txtCacheMaxEntries {
		for key, entry := range r.entries {
			if !now.Before(entry.expires) {
				delete(r.entries, key)
			}
		}
		if len(r.entries) >= txtCacheMaxEntries {
			r.entries = make(map[string]txtCacheEntry)
		}
	}
	r.entries[name] = txtCacheEntry{records: records, err: err, expires: now.Add(ttl)}
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
