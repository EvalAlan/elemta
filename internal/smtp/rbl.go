package smtp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// DNS blocklists (RBL/DNSBL).
//
// A blocklist answers "is this address a known source of spam" by encoding the
// address into a hostname and looking it up: 198.51.100.7 becomes
// 7.100.51.198.zen.spamhaus.org, and an A record in reply means listed.
//
// The whole feature refuses mail on the strength of a third party's opinion
// delivered over UDP, so most of what follows is about the ways that goes
// wrong.

const (
	// listedNet is the only range that means "listed". Blocklists answer in
	// 127.0.0.0/8, and the part outside 127.0.0.0/24 is reserved for telling
	// the *querier* something about themselves.
	//
	// This distinction is the single most damaging thing to get wrong here.
	// Spamhaus returns 127.255.255.252 for a typing error, .254 for querying
	// through a public resolver, and .255 for exceeding the free query limit.
	// A naive "got an A record, therefore listed" refuses every message the
	// server receives, from every sender, the moment the query budget runs out
	// — and the server keeps reporting the rejections as spam.
	listedNetCIDR = "127.0.0.0/24"

	// defaultRBLTimeout bounds the whole check, not each zone. A blocklist that
	// stops answering must not turn into a stalled SMTP session.
	defaultRBLTimeout = 5 * time.Second

	defaultRBLCacheTTL  = time.Hour
	defaultRBLCacheSize = 10000
)

// rblResolver is the DNS surface this needs, so tests can answer without a
// network and without a live blocklist's opinion of the test runner.
type rblResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// RBLDecision is the outcome of a check.
type RBLDecision struct {
	Listed bool
	Zone   string
	// Reason is the blocklist's own TXT explanation when it gave one. Quoting
	// it back means the sender is told which list to appeal to, instead of
	// being refused by an anonymous server for anonymous reasons.
	Reason string
	// Code is the A record that was returned, for logs.
	Code string
}

// RBLChecker looks addresses up in the configured blocklists.
//
// A zero value is safe: with no zones configured nothing is ever listed, so an
// absent or disabled section cannot start refusing mail.
type RBLChecker struct {
	enabled  bool
	zones    []string
	timeout  time.Duration
	reject   bool
	skipNets []*net.IPNet

	resolver  rblResolver
	listedNet *net.IPNet
	logger    *slog.Logger

	cache *rblCache
}

// NewRBLChecker builds the checker. A malformed zone or skip network stops
// startup: a blocklist that silently fails to load leaves the operator
// believing mail is being filtered when it is not.
func NewRBLChecker(cfg *RBLConfig, logger *slog.Logger) (*RBLChecker, error) {
	_, listedNet, err := net.ParseCIDR(listedNetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parsing the listed range: %w", err)
	}

	r := &RBLChecker{
		listedNet: listedNet,
		logger:    logger,
		resolver:  net.DefaultResolver,
	}
	if cfg == nil || !cfg.Enabled {
		return r, nil
	}

	for _, zone := range cfg.Zones {
		zone = strings.TrimSpace(strings.ToLower(strings.Trim(zone, ".")))
		if zone == "" {
			continue
		}
		if strings.ContainsAny(zone, " \t/:") || !strings.Contains(zone, ".") {
			return nil, fmt.Errorf("zone %q is not a domain name", zone)
		}
		r.zones = append(r.zones, zone)
	}
	if len(r.zones) == 0 {
		// Enabled with nothing to query is a configuration the operator thinks
		// is protecting them.
		return nil, fmt.Errorf("rbl is enabled but no zones are configured")
	}

	if r.skipNets, err = parseAccessNetworks(cfg.SkipIPs); err != nil {
		return nil, fmt.Errorf("skip_ips: %w", err)
	}

	r.enabled = true
	r.reject = cfg.Reject
	r.timeout = time.Duration(cfg.Timeout) * time.Second
	if r.timeout <= 0 {
		r.timeout = defaultRBLTimeout
	}

	ttl := time.Duration(cfg.CacheTTL) * time.Second
	if ttl <= 0 {
		ttl = defaultRBLCacheTTL
	}
	size := cfg.CacheSize
	if size <= 0 {
		size = defaultRBLCacheSize
	}
	r.cache = newRBLCache(size, ttl)

	return r, nil
}

// Enabled reports whether any zone will actually be queried.
func (r *RBLChecker) Enabled() bool { return r != nil && r.enabled }

// Reject reports whether a listing refuses the message or only marks it.
// Tagging rather than rejecting is what makes a new blocklist safe to try:
// the operator can see what it would have refused before letting it.
func (r *RBLChecker) Reject() bool { return r != nil && r.reject }

// Check looks the peer up in every configured zone.
//
// Zones are queried concurrently and the first listing wins. Querying them in
// sequence would make the timeout the sum of the slow ones, and the answer is
// the same either way — one listing is enough.
func (r *RBLChecker) Check(ctx context.Context, ip net.IP) RBLDecision {
	if !r.Enabled() || ip == nil {
		return RBLDecision{}
	}

	// A skip entry is for the addresses an operator already trusts: relays,
	// monitoring, their own networks. Checking them costs a lookup and risks
	// refusing mail from themselves.
	for _, n := range r.skipNets {
		if n.Contains(ip) {
			return RBLDecision{}
		}
	}

	key := ip.String()
	if cached, ok := r.cache.get(key); ok {
		return cached
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	results := make(chan RBLDecision, len(r.zones))
	var wg sync.WaitGroup
	for _, zone := range r.zones {
		wg.Add(1)
		go func(zone string) {
			defer wg.Done()
			results <- r.checkZone(ctx, ip, zone)
		}(zone)
	}
	go func() { wg.Wait(); close(results) }()

	decision := RBLDecision{}
	for result := range results {
		if result.Listed {
			decision = result
			break
		}
	}

	r.cache.put(key, decision)
	return decision
}

// checkZone queries one blocklist.
func (r *RBLChecker) checkZone(ctx context.Context, ip net.IP, zone string) RBLDecision {
	host, err := rblQueryName(ip, zone)
	if err != nil {
		return RBLDecision{}
	}

	addrs, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		// NXDOMAIN — not listed — arrives as an error, and so does a resolver
		// that is unreachable. They are told apart because failing closed on
		// the second would turn a DNS outage into a mail outage: every message
		// refused, from every sender, for as long as DNS is down.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return RBLDecision{}
		}
		r.logger.Warn("Blocklist lookup failed; treating the address as unlisted",
			"zone", zone, "ip", ip.String(), "error", err)
		return RBLDecision{}
	}

	for _, addr := range addrs {
		v4 := addr.IP.To4()
		if v4 == nil {
			continue
		}
		if !r.listedNet.Contains(v4) {
			// See listedNetCIDR: this is the blocklist talking about the
			// querier, not about the sender. Refusing on it blocks everything.
			r.logger.Warn("Blocklist returned a status code about this server, not the sender; ignoring it",
				"zone", zone,
				"ip", ip.String(),
				"code", v4.String(),
				"hint", "usually a query limit or a public-resolver restriction — check the blocklist's terms",
			)
			continue
		}

		decision := RBLDecision{Listed: true, Zone: zone, Code: v4.String()}
		// Best effort: the sender is being refused either way, so a slow or
		// missing TXT must not change the outcome.
		if txt, txtErr := r.resolver.LookupTXT(ctx, host); txtErr == nil && len(txt) > 0 {
			decision.Reason = sanitizeRBLReason(txt[0])
		}
		return decision
	}

	return RBLDecision{}
}

// Message is what the sender is told. It names the list, because a rejection
// the sender cannot act on is a rejection they will retry forever.
func (d RBLDecision) Message() string {
	msg := fmt.Sprintf("Client host blocked by %s", d.Zone)
	if d.Reason != "" {
		msg += ": " + d.Reason
	}
	return msg
}

// sanitizeRBLReason makes a third party's TXT record safe to put in an SMTP
// reply. The string is attacker-influenced — anyone who can get listed can
// often influence the text — and an SMTP reply is line-oriented, so a CRLF in
// it would let the blocklist write its own reply lines into our session.
func sanitizeRBLReason(txt string) string {
	txt = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return ' '
		}
		return r
	}, txt)
	txt = strings.TrimSpace(txt)

	const maxReason = 200
	if len(txt) > maxReason {
		txt = txt[:maxReason] + "..."
	}
	return txt
}

// rblQueryName builds the lookup name: the address reversed, then the zone.
func rblQueryName(ip net.IP, zone string) (string, error) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.%s", v4[3], v4[2], v4[1], v4[0], zone), nil
	}
	if v6 := ip.To16(); v6 != nil {
		// RFC 5782 §2.4: nibbles, reversed, dot-separated.
		var b strings.Builder
		const hexDigits = "0123456789abcdef"
		for i := len(v6) - 1; i >= 0; i-- {
			b.WriteByte(hexDigits[v6[i]&0x0f])
			b.WriteByte('.')
			b.WriteByte(hexDigits[v6[i]>>4])
			b.WriteByte('.')
		}
		b.WriteString(zone)
		return b.String(), nil
	}
	return "", fmt.Errorf("%q is neither IPv4 nor IPv6", ip)
}

// ----------------------------------------------------------------- cache

// rblCache remembers answers so a burst of connections from one address costs
// one lookup.
//
// It is bounded. Keyed by peer address and left to grow, it would be a memory
// exhaustion vector: connecting once from each of a large number of addresses
// is cheap for the sender and permanently expensive for us.
type rblCache struct {
	mu      sync.Mutex
	entries map[string]rblCacheEntry
	maxSize int
	ttl     time.Duration
}

type rblCacheEntry struct {
	decision RBLDecision
	expires  time.Time
}

func newRBLCache(maxSize int, ttl time.Duration) *rblCache {
	return &rblCache{
		entries: make(map[string]rblCacheEntry, maxSize/4+1),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *rblCache) get(key string) (RBLDecision, bool) {
	if c == nil {
		return RBLDecision{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return RBLDecision{}, false
	}
	if time.Now().After(entry.expires) {
		// A delisted address must be able to send again without a restart.
		delete(c.entries, key)
		return RBLDecision{}, false
	}
	return entry.decision, true
}

func (c *rblCache) put(key string, decision RBLDecision) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[key] = rblCacheEntry{decision: decision, expires: time.Now().Add(c.ttl)}
}

// evictLocked drops expired entries, and if that was not enough, drops
// arbitrary ones until there is room. Arbitrary rather than least-recently-used
// because the cost of a wrong eviction is one DNS lookup, which does not
// justify carrying the bookkeeping an LRU needs on every hit.
func (c *rblCache) evictLocked() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, key)
		}
	}

	for key := range c.entries {
		if len(c.entries) < c.maxSize {
			return
		}
		delete(c.entries, key)
	}
}
