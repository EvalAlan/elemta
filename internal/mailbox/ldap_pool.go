package mailbox

// Directory connections and a short cache of what they answer.
//
// Every sign-in, every delivery and every directory question used to dial
// the directory afresh: a TCP connection, a TLS handshake and a bind,
// then a single search, then hang up. At a few thousand sign-ins and
// deliveries a second that is a few thousand TLS handshakes a second
// against one directory server, most of them to ask the same questions
// about the same few addresses (a phone reconnecting, a burst of mail to
// one person).
//
// Connections are now kept and reused: one pool bound as the mailbox
// service for searches, and one for checking passwords, which binds as
// each user in turn. A connection that fails is dropped, and a request
// that failed on a reused connection is tried once more on a new one, as
// the directory may have closed it while it sat idle.
//
// Answers are kept for a short while (auth.cache_seconds, 30 by default):
// what the directory says about an address, and that a password was
// right. A changed password, suspension or forward therefore takes up to
// that long to apply everywhere; a wrong password is never cached, so
// nothing is ever let in that the directory didn't approve within the
// window. Passwords are kept only as an HMAC under a key made at start
// and never stored.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	// ldapIdleMax is how many unused connections each pool keeps.
	ldapIdleMax = 16
	// ldapIdleFor is how long an unused connection is trusted; directories
	// close idle connections, and a reused dead one costs a retry.
	ldapIdleFor = time.Minute
	// ldapCacheMax bounds the cache; past it, the cache starts over.
	ldapCacheMax = 200_000
	// ldapNegativeFor caps how long "no such address" is kept, so a new
	// account receives mail soon after it's made.
	ldapNegativeFor = 10 * time.Second
)

// ldapPool keeps directory connections for reuse.
type ldapPool struct {
	mu   sync.Mutex
	idle []pooledLDAP
	open func() (*ldap.Conn, error)
	// opened counts new connections, for tests and metrics.
	opened int64
}

type pooledLDAP struct {
	c    *ldap.Conn
	used time.Time
}

func (p *ldapPool) get() (*ldap.Conn, bool, error) {
	p.mu.Lock()
	for len(p.idle) > 0 {
		pc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if time.Since(pc.used) < ldapIdleFor && !pc.c.IsClosing() {
			p.mu.Unlock()
			return pc.c, true, nil
		}
		_ = pc.c.Close()
	}
	p.opened++
	p.mu.Unlock()
	c, err := p.open()
	return c, false, err
}

func (p *ldapPool) put(c *ldap.Conn) {
	if c.IsClosing() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) >= ldapIdleMax {
		_ = c.Close()
		return
	}
	p.idle = append(p.idle, pooledLDAP{c: c, used: time.Now()})
}

// connectionFailed says whether err means the connection is unusable, as
// opposed to the directory answering (no such entry, wrong password).
func connectionFailed(err error) bool {
	if err == nil {
		return false
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return le.ResultCode == ldap.ErrorNetwork || le.ResultCode == ldap.LDAPResultUnavailable || le.ResultCode == ldap.LDAPResultBusy
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// do runs fn on a pooled connection. When a reused connection fails, fn
// runs once more on a new one.
func (p *ldapPool) do(fn func(*ldap.Conn) error) error {
	for attempt := 0; ; attempt++ {
		c, reused, err := p.get()
		if err != nil {
			return err
		}
		err = fn(c)
		if connectionFailed(err) {
			_ = c.Close()
			if reused && attempt == 0 {
				continue
			}
			return err
		}
		p.put(c)
		return err
	}
}

// ldapCache keeps directory answers for a short while.
type ldapCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cached
	key     []byte
	now     func() time.Time
	hits    int64
}

type cached struct {
	account Account
	dn      string
	ok      bool
	expires time.Time
}

func newLDAPCache(ttl time.Duration) *ldapCache {
	if ttl <= 0 {
		return nil
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &ldapCache{ttl: ttl, entries: map[string]cached{}, key: key, now: time.Now}
}

func (c *ldapCache) get(k string) (cached, bool) {
	if c == nil {
		return cached{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || c.now().After(e.expires) {
		return cached{}, false
	}
	c.hits++
	// Callers may change what they're given; the cache's copy stays.
	a := &e.account
	a.Forward, a.SendAs, a.Aliases = slices.Clone(a.Forward), slices.Clone(a.SendAs), slices.Clone(a.Aliases)
	return e, true
}

func (c *ldapCache) put(k string, e cached) {
	if c == nil {
		return
	}
	ttl := c.ttl
	if !e.ok && ttl > ldapNegativeFor {
		ttl = ldapNegativeFor
	}
	e.expires = c.now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= ldapCacheMax {
		now := c.now()
		for k, v := range c.entries {
			if now.After(v.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= ldapCacheMax {
			c.entries = map[string]cached{}
		}
	}
	c.entries[k] = e
}

// password is the cache key for a correct password: an HMAC, so the
// cache never holds the password itself.
func (c *ldapCache) password(address, password string) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(address))
	m.Write([]byte{0})
	m.Write([]byte(password))
	return "p:" + hex.EncodeToString(m.Sum(nil))
}
