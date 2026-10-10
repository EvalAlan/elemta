package queue

import (
	"net"
	"net/smtp"
	"sync"
	"time"
)

// Outbound SMTP session reuse.
//
// Every delivery used to dial, wait for the banner, EHLO, STARTTLS (a full TLS
// handshake), and EHLO again before sending MAIL FROM: five or six round trips
// and the receiver's most expensive operation, repeated for every message.
// Draining a queue to one large receiver is dominated by that setup, not by
// the transfer. RFC 5321 §3.3 allows any number of transactions per session,
// so after a delivery the session is RSET and parked here for the next message
// to the same MX address.
//
// The key is the MX address (host:port), not the recipient domain: one
// provider's MX hosts serve thousands of domains, and those are exactly the
// destinations where reuse pays.
//
// Limits are deliberately short, in the spirit of Postfix's connection cache
// (2s idle, 300s total): a parked session ties up a slot on the receiver, and
// receivers drop idle clients well before RFC 5321's five-minute minimum.
// A parked session is not probed before reuse: the caller reconnects if the
// first command on it finds the receiver gone (see deliverToAddressWithMetadata),
// which costs nothing in the common case where the session is still there.
//
// Parked sessions are not counted by the shaper. The shaper limits concurrent
// deliveries per domain, and a parked session is not delivering anything; the
// per-host cap below is what bounds idle connections to a receiver.

const (
	defaultSessionIdleTimeout = 5 * time.Second
	defaultSessionMaxLifetime = 5 * time.Minute
	defaultSessionMaxUses     = 100
	defaultSessionMaxPerHost  = 4
	defaultSessionMaxTotal    = 256
	// sessionProbeTimeout bounds the NOOP/RSET/QUIT exchanges done on behalf of
	// the cache, so a receiver that stopped answering cannot hold a worker.
	sessionProbeTimeout = 10 * time.Second
)

// outboundSession is an established SMTP session and what was negotiated on it.
type outboundSession struct {
	client     *smtp.Client
	conn       net.Conn
	tls        outboundTLS
	requireTLS bool // next hop advertised REQUIRETLS
	created    time.Time
	idleSince  time.Time
	uses       int
}

// sessionCache holds idle outbound sessions keyed by MX address.
type sessionCache struct {
	mu    sync.Mutex
	idle  map[string][]*outboundSession
	total int

	idleTimeout time.Duration
	maxLifetime time.Duration
	maxUses     int
	maxPerHost  int
	maxTotal    int
	now         func() time.Time

	hits, misses, parked, discarded uint64
}

func newSessionCache() *sessionCache {
	return &sessionCache{
		idle:        make(map[string][]*outboundSession),
		idleTimeout: defaultSessionIdleTimeout,
		maxLifetime: defaultSessionMaxLifetime,
		maxUses:     defaultSessionMaxUses,
		maxPerHost:  defaultSessionMaxPerHost,
		maxTotal:    defaultSessionMaxTotal,
		now:         time.Now,
	}
}

// expired reports whether s may no longer be handed out.
func (c *sessionCache) expired(s *outboundSession, now time.Time) bool {
	return now.Sub(s.idleSince) > c.idleTimeout ||
		now.Sub(s.created) > c.maxLifetime ||
		s.uses >= c.maxUses
}

// get returns a live idle session for address, or nil. needRequireTLS limits
// the choice to sessions that satisfy REQUIRETLS (verified TLS and a next hop
// that advertised it), so a REQUIRETLS message never rides a session that was
// set up with weaker guarantees.
func (c *sessionCache) get(address string, needRequireTLS bool) *outboundSession {
	s, stale := c.take(address, needRequireTLS)
	for _, old := range stale {
		closeSession(old)
	}
	c.mu.Lock()
	if s == nil {
		c.misses++
	} else {
		c.hits++
	}
	c.mu.Unlock()
	return s
}

// take removes and returns the most recently parked usable session (the one
// least likely to have been timed out by the receiver), along with any
// expired sessions found on the way, which the caller closes outside the lock.
func (c *sessionCache) take(address string, needRequireTLS bool) (*outboundSession, []*outboundSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	list := c.idle[address]
	var stale []*outboundSession
	kept := list[:0]
	var found *outboundSession
	for i := len(list) - 1; i >= 0; i-- {
		s := list[i]
		switch {
		case c.expired(s, now):
			stale = append(stale, s)
		case found == nil && (!needRequireTLS || (s.tls == tlsVerified && s.requireTLS)):
			found = s
		default:
			kept = append(kept, s)
		}
	}
	// kept was filled newest-first; restore oldest-first order.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	c.total -= len(list) - len(kept)
	if len(kept) == 0 {
		delete(c.idle, address)
	} else {
		c.idle[address] = kept
	}
	c.discarded += uint64(len(stale))
	return found, stale
}

// put parks s for reuse, or closes it if it has reached a limit or the cache
// is full. clean means the last transaction completed with a 250 to the end
// of data, so the session is already ready for MAIL FROM; otherwise it is
// RSET first.
func (c *sessionCache) put(address string, s *outboundSession, clean bool) {
	s.uses++
	if !clean && !resetSession(s) {
		_ = s.client.Close()
		c.mu.Lock()
		c.discarded++
		c.mu.Unlock()
		return
	}

	c.mu.Lock()
	now := c.now()
	s.idleSince = now
	var evicted []*outboundSession
	if c.expired(s, now) || len(c.idle[address]) >= c.maxPerHost {
		evicted = append(evicted, s)
	} else {
		if c.total >= c.maxTotal {
			evicted = append(evicted, c.evictOldestLocked()...)
		}
		if c.total < c.maxTotal {
			c.idle[address] = append(c.idle[address], s)
			c.total++
			c.parked++
		} else {
			evicted = append(evicted, s)
		}
	}
	c.discarded += uint64(len(evicted))
	c.mu.Unlock()

	for _, old := range evicted {
		closeSession(old)
	}
}

// evictOldestLocked removes the longest-idle session in the cache.
func (c *sessionCache) evictOldestLocked() []*outboundSession {
	var oldestKey string
	oldestIdx := -1
	var oldest time.Time
	for key, list := range c.idle {
		for i, s := range list {
			if oldestIdx < 0 || s.idleSince.Before(oldest) {
				oldestKey, oldestIdx, oldest = key, i, s.idleSince
			}
		}
	}
	if oldestIdx < 0 {
		return nil
	}
	list := c.idle[oldestKey]
	s := list[oldestIdx]
	list = append(list[:oldestIdx], list[oldestIdx+1:]...)
	if len(list) == 0 {
		delete(c.idle, oldestKey)
	} else {
		c.idle[oldestKey] = list
	}
	c.total--
	return []*outboundSession{s}
}

// closeAll closes every idle session; used at shutdown.
func (c *sessionCache) closeAll() {
	c.mu.Lock()
	var all []*outboundSession
	for _, list := range c.idle {
		all = append(all, list...)
	}
	c.idle = make(map[string][]*outboundSession)
	c.total = 0
	c.mu.Unlock()
	for _, s := range all {
		closeSession(s)
	}
}

// SessionCacheStats is a snapshot of the outbound session cache.
type SessionCacheStats struct {
	Idle      int    `json:"idle"`
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Parked    uint64 `json:"parked"`
	Discarded uint64 `json:"discarded"`
}

func (c *sessionCache) stats() SessionCacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SessionCacheStats{Idle: c.total, Hits: c.hits, Misses: c.misses, Parked: c.parked, Discarded: c.discarded}
}

// resetSession ends the finished transaction so the session can carry another.
func resetSession(s *outboundSession) bool {
	return withDeadline(s, s.client.Reset) == nil
}

// closeSession says QUIT, bounded, and closes the connection either way.
func closeSession(s *outboundSession) {
	_ = withDeadline(s, s.client.Quit)
	_ = s.client.Close()
}

// withDeadline runs fn with a short I/O deadline, then clears it so the
// next transaction runs under the delivery's own timing as before.
func withDeadline(s *outboundSession, fn func() error) error {
	if s.conn != nil {
		_ = s.conn.SetDeadline(time.Now().Add(sessionProbeTimeout))
		defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	}
	return fn()
}
