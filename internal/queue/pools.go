package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sending IP pools (virtual MTAs).
//
// Without pools every outbound connection leaves from whatever address the
// kernel picks, so every kind of mail shares one reputation: a marketing
// send that draws complaints drags down the password resets sent from the
// same address. Receivers keep reputation per sending IP (and per domain),
// so the lever an operator needs is "this mail leaves from these addresses".
//
// A pool is a named set of source addresses, each with the EHLO name that
// its reverse DNS points at. Mail is put into a pool by envelope sender, so
// the separation follows the streams an operator already thinks in
// (news.example.com versus example.com) and needs no header or API to carry
// it. Within a pool, deliveries rotate across the addresses that still have
// warmup allowance.
//
// Warmup exists because receivers treat a new IP with no history as
// suspicious: a fresh address that sends at full volume on day one is
// throttled or junked. Each address gets a daily cap that grows on a
// schedule from the day it was put into service, and the cap is spread
// across the day rather than spent in the first hour, because a burst from
// an unknown IP is exactly the pattern receivers punish.
//
// Pool limits and destination limits are separate on purpose. A pool at its
// warmup cap is our own policy, not a receiver complaining, so it defers the
// message without backing off from the destination (see ErrPoolAtCapacity).

// PoolConfig defines one sending pool.
type PoolConfig struct {
	Name string `toml:"name" json:"name"`
	// Senders selects mail for this pool by envelope sender: a full address
	// ("alerts@example.com"), a domain ("example.com"), or a leading-dot
	// domain (".example.com") for every subdomain. An address match wins over
	// a domain match, and a domain match over a subdomain match.
	Senders []string `toml:"senders" json:"senders"`
	// IPs are the source addresses this pool sends from.
	IPs []PoolIPConfig `toml:"ips" json:"ips"`
	// WarmupSchedule is the daily message cap for an address on each day
	// after its warmup_start: element 0 is the first day. Past the end of the
	// schedule an address is warm and uncapped. Empty means no warmup.
	WarmupSchedule []int `toml:"warmup_schedule" json:"warmup_schedule"`
}

// PoolIPConfig is one source address in a pool.
type PoolIPConfig struct {
	Address string `toml:"address" json:"address"`
	// Helo is the EHLO name for connections from this address. It should be
	// the address's PTR name, with an A/AAAA record pointing back: receivers
	// check that forward and reverse agree. Defaults to the server hostname.
	Helo string `toml:"helo" json:"helo"`
	// WarmupStart is the UTC date (YYYY-MM-DD) this address entered service.
	// Empty means the address is already warm and the schedule does not apply.
	WarmupStart string `toml:"warmup_start" json:"warmup_start"`
}

// PoolsConfig is the full pool setup.
type PoolsConfig struct {
	Pools []PoolConfig
	// DefaultPool receives mail whose sender matches no pool. Empty leaves
	// that mail unpooled: the kernel picks the source address, as before.
	DefaultPool string
	// StateFile keeps warmup counts across restarts. Empty keeps them in
	// memory only, which restarts a day's count from zero on every restart.
	StateFile string
}

// ErrPoolAtCapacity says every address in a pool has used today's warmup
// allowance. The message is deferred; the destination is not at fault and is
// not backed off from.
var ErrPoolAtCapacity = errors.New("sending pool has no warmup allowance left")

// sourceIP is a resolved pool address.
type sourceIP struct {
	pool  string
	ip    net.IP
	addr  string // canonical text form; the key for counts and state
	helo  string
	start time.Time // zero when the address is warm
}

type sendingPool struct {
	name     string
	ips      []*sourceIP
	schedule []int
	next     int // round-robin cursor
}

// ipUsage is how much of today's allowance an address has used. Day is the
// UTC date it applies to, so a count from yesterday is recognised as stale
// rather than carried over.
type ipUsage struct {
	Day  string `json:"day"`
	Sent int    `json:"sent"`
}

// PoolRouter maps senders to pools and hands out source addresses.
type PoolRouter struct {
	logger *slog.Logger

	pools       map[string]*sendingPool
	byAddress   map[string]string // full sender address -> pool
	byDomain    map[string]string // exact sender domain -> pool
	bySubdomain map[string]string // parent domain -> pool, for ".example.com"
	defaultPool string

	stateFile string
	now       func() time.Time

	mu    sync.Mutex
	usage map[string]*ipUsage // by sourceIP.addr
	dirty bool

	stop chan struct{}
	done chan struct{}
}

// NewPoolRouter validates cfg and builds a router. It returns nil, nil when no
// pools are configured, which the delivery handler treats as unpooled.
func NewPoolRouter(cfg PoolsConfig, logger *slog.Logger) (*PoolRouter, error) {
	if len(cfg.Pools) == 0 {
		if cfg.DefaultPool != "" {
			return nil, fmt.Errorf("default_pool %q names a pool, but no pools are configured", cfg.DefaultPool)
		}
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	r := &PoolRouter{
		logger:      logger.With("component", "sending-pools"),
		pools:       make(map[string]*sendingPool),
		byAddress:   make(map[string]string),
		byDomain:    make(map[string]string),
		bySubdomain: make(map[string]string),
		stateFile:   cfg.StateFile,
		now:         time.Now,
		usage:       make(map[string]*ipUsage),
	}

	// An address may only be in one pool. Two pools sharing an address share
	// its reputation, which defeats the reason for having two pools, and
	// would also split its warmup count in two.
	owner := make(map[string]string)
	for i, pc := range cfg.Pools {
		name := strings.TrimSpace(pc.Name)
		if name == "" {
			return nil, fmt.Errorf("pool %d has no name", i+1)
		}
		if _, dup := r.pools[name]; dup {
			return nil, fmt.Errorf("pool %q is defined twice", name)
		}
		if len(pc.IPs) == 0 {
			return nil, fmt.Errorf("pool %q has no ips", name)
		}
		for day, limit := range pc.WarmupSchedule {
			if limit <= 0 {
				return nil, fmt.Errorf("pool %q: warmup_schedule day %d is %d; every day needs a positive cap", name, day+1, limit)
			}
		}
		pool := &sendingPool{name: name, schedule: append([]int(nil), pc.WarmupSchedule...)}
		for _, ipc := range pc.IPs {
			ip := net.ParseIP(strings.TrimSpace(ipc.Address))
			if ip == nil {
				return nil, fmt.Errorf("pool %q: %q is not an IP address", name, ipc.Address)
			}
			if ip.IsUnspecified() {
				return nil, fmt.Errorf("pool %q: %s is the unspecified address; name the address mail should leave from", name, ipc.Address)
			}
			src := &sourceIP{pool: name, ip: ip, addr: ip.String(), helo: strings.TrimSpace(ipc.Helo)}
			if prev, dup := owner[src.addr]; dup {
				return nil, fmt.Errorf("address %s is in both pool %q and pool %q", src.addr, prev, name)
			}
			owner[src.addr] = name
			if ipc.WarmupStart != "" {
				start, err := time.Parse("2006-01-02", strings.TrimSpace(ipc.WarmupStart))
				if err != nil {
					return nil, fmt.Errorf("pool %q: warmup_start %q for %s is not a YYYY-MM-DD date", name, ipc.WarmupStart, src.addr)
				}
				if len(pool.schedule) == 0 {
					return nil, fmt.Errorf("pool %q: %s has a warmup_start but the pool has no warmup_schedule", name, src.addr)
				}
				src.start = start
			}
			pool.ips = append(pool.ips, src)
		}
		r.pools[name] = pool

		for _, s := range pc.Senders {
			s = strings.ToLower(strings.TrimSpace(s))
			var table map[string]string
			key := s
			switch {
			case s == "":
				continue
			case strings.Contains(s, "@"):
				table = r.byAddress
			case strings.HasPrefix(s, "."):
				table, key = r.bySubdomain, strings.TrimPrefix(s, ".")
			default:
				table = r.byDomain
			}
			if prev, dup := table[key]; dup && prev != name {
				return nil, fmt.Errorf("sender %q is claimed by both pool %q and pool %q", s, prev, name)
			}
			table[key] = name
		}
	}

	if cfg.DefaultPool != "" {
		if _, ok := r.pools[cfg.DefaultPool]; !ok {
			return nil, fmt.Errorf("default_pool %q is not a defined pool", cfg.DefaultPool)
		}
		r.defaultPool = cfg.DefaultPool
	}

	if err := r.loadState(); err != nil {
		// Starting from zero after a corrupt state file over-sends for at most
		// one day; refusing to start would stop all mail. Say so loudly.
		r.logger.Error("Could not read warmup state; today's counts start from zero",
			"file", r.stateFile, "error", err)
	}
	return r, nil
}

// CheckLocalAddresses reports pool addresses this host cannot send from.
// Binding to one fails on every connection, and those failures would look
// like the destination refusing us, so callers refuse to start instead.
//
// It tries to bind rather than comparing against the interface list: that
// is the operation delivery will perform, and it gives the right answer for
// cases a list does not show, such as the rest of 127.0.0.0/8 or a host
// with ip_nonlocal_bind set.
func (r *PoolRouter) CheckLocalAddresses() error {
	if r == nil {
		return nil
	}
	var missing []string
	for _, pool := range r.pools {
		for _, src := range pool.ips {
			ln, err := net.Listen("tcp", net.JoinHostPort(src.addr, "0"))
			if err != nil {
				missing = append(missing, fmt.Sprintf("%s (pool %q)", src.addr, pool.name))
				continue
			}
			_ = ln.Close()
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("cannot bind pool addresses on this host: %s", strings.Join(missing, ", "))
	}
	return nil
}

// poolForAddress returns the pool a source address belongs to, and the
// address in canonical form, or "", "" when it is not a pool address.
func (r *PoolRouter) poolForAddress(addr string) (string, string) {
	if r == nil {
		return "", ""
	}
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return "", ""
	}
	canonical := ip.String()
	for _, pool := range r.pools {
		for _, src := range pool.ips {
			if src.addr == canonical {
				return pool.name, canonical
			}
		}
	}
	return "", ""
}

// poolFor returns the pool for an envelope sender, or "" for unpooled.
func (r *PoolRouter) poolFor(sender string) string {
	sender = strings.ToLower(strings.Trim(strings.TrimSpace(sender), "<>"))
	if sender != "" {
		if name, ok := r.byAddress[sender]; ok {
			return name
		}
		if at := strings.LastIndexByte(sender, '@'); at >= 0 {
			domain := sender[at+1:]
			if name, ok := r.byDomain[domain]; ok {
				return name
			}
			// Walk up the labels so ".example.com" covers a.b.example.com,
			// with the most specific parent winning.
			for d := domain; ; {
				dot := strings.IndexByte(d, '.')
				if dot < 0 {
					break
				}
				d = d[dot+1:]
				if name, ok := r.bySubdomain[d]; ok {
					return name
				}
			}
		}
	}
	// The null sender (DSNs) also lands here, which is deliberate: bounces
	// belong with the server's own mail, not with whichever stream caused them.
	return r.defaultPool
}

// acquire picks a source address for a message from sender and reserves one
// unit of its warmup allowance. It returns nil, nil when the sender is
// unpooled. The returned release refunds the reservation and must be called
// when nothing was handed to the receiver, so a run of failed connections
// does not use up a warming address's day.
func (r *PoolRouter) acquire(sender string) (*sourceIP, func(), error) {
	if r == nil {
		return nil, func() {}, nil
	}
	name := r.poolFor(sender)
	if name == "" {
		return nil, func() {}, nil
	}
	pool := r.pools[name]

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()
	day := now.Format("2006-01-02")

	// Round-robin, skipping addresses that are paced out for now. Starting
	// from a moving cursor spreads load evenly across warm addresses rather
	// than piling it on the first.
	for i := 0; i < len(pool.ips); i++ {
		src := pool.ips[(pool.next+i)%len(pool.ips)]
		allowed := pool.allowedSoFar(src, now)
		u := r.usageLocked(src.addr, day)
		if allowed >= 0 && u.Sent >= allowed {
			continue
		}
		pool.next = (pool.next + i + 1) % len(pool.ips)
		u.Sent++
		r.dirty = true
		refunded := false
		return src, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if refunded {
				return
			}
			refunded = true
			// Only refund against the day it was taken from.
			if cur := r.usage[src.addr]; cur != nil && cur.Day == day && cur.Sent > 0 {
				cur.Sent--
				r.dirty = true
			}
		}, nil
	}
	return nil, nil, &poolCapacityError{pool: name}
}

// poolCapacityError is ErrPoolAtCapacity for one pool. It is explicitly
// temporary: the processor's classifier would otherwise read an unrecognised
// error as permanent-or-unknown, and a warmup cap must never bounce mail.
type poolCapacityError struct{ pool string }

func (e *poolCapacityError) Error() string {
	return fmt.Sprintf("%v: pool %q", ErrPoolAtCapacity, e.pool)
}
func (e *poolCapacityError) Unwrap() error   { return ErrPoolAtCapacity }
func (e *poolCapacityError) Temporary() bool { return true }

// usageLocked returns today's usage for an address, resetting a stale day.
func (r *PoolRouter) usageLocked(addr, day string) *ipUsage {
	u := r.usage[addr]
	if u == nil {
		u = &ipUsage{Day: day}
		r.usage[addr] = u
	}
	if u.Day != day {
		u.Day, u.Sent = day, 0
	}
	return u
}

// dailyCap is an address's cap for the UTC day containing now, or -1 when it
// is uncapped (warm, or past the end of the schedule).
func (p *sendingPool) dailyCap(src *sourceIP, now time.Time) int {
	if src.start.IsZero() || len(p.schedule) == 0 {
		return -1
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	day := int(today.Sub(src.start).Hours() / 24)
	if day < 0 {
		// Not in service yet by its own date; give it day one's allowance
		// rather than nothing, so a start date set a day early still sends.
		day = 0
	}
	if day >= len(p.schedule) {
		return -1
	}
	return p.schedule[day]
}

// allowedSoFar is how many messages an address may have sent by now today,
// or -1 for uncapped.
//
// The day's cap is released evenly over the day, plus one hour's worth up
// front so a quiet night does not leave the first message of the morning
// waiting. Spending a warming address's whole cap in a burst is the pattern
// receivers penalise most, and pacing it pushes the rest of the burst onto
// the pool's warm addresses, which is where it belongs.
func (p *sendingPool) allowedSoFar(src *sourceIP, now time.Time) int {
	limit := p.dailyCap(src, now)
	if limit < 0 {
		return -1
	}
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	fraction := now.Sub(midnight).Hours()/24 + 1.0/24
	allowed := int(math.Ceil(float64(limit) * fraction))
	if allowed > limit {
		allowed = limit
	}
	return allowed
}

// PoolIPStatus describes one pool address, for logs and the dashboard.
type PoolIPStatus struct {
	Pool         string `json:"pool"`
	Address      string `json:"address"`
	Helo         string `json:"helo,omitempty"`
	WarmupDay    int    `json:"warmup_day,omitempty"` // 1-based; 0 when warm
	DailyCap     int    `json:"daily_cap"`            // -1 when uncapped
	SentToday    int    `json:"sent_today"`
	AllowedSoFar int    `json:"allowed_so_far"` // -1 when uncapped
}

// Statuses reports every pool address, sorted by pool then address.
func (r *PoolRouter) Statuses() []PoolIPStatus {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()
	day := now.Format("2006-01-02")
	var out []PoolIPStatus
	for _, pool := range r.pools {
		for _, src := range pool.ips {
			st := PoolIPStatus{
				Pool: pool.name, Address: src.addr, Helo: src.helo,
				DailyCap:     pool.dailyCap(src, now),
				AllowedSoFar: pool.allowedSoFar(src, now),
			}
			if st.DailyCap >= 0 {
				today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
				st.WarmupDay = max(int(today.Sub(src.start).Hours()/24), 0) + 1
			}
			if u := r.usage[src.addr]; u != nil && u.Day == day {
				st.SentToday = u.Sent
			}
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pool != out[j].Pool {
			return out[i].Pool < out[j].Pool
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// Start begins writing warmup counts to the state file in the background.
// Writes are batched rather than made per message: losing a few seconds of
// counts in a crash over-sends by that much, which is a far smaller cost
// than a disk write on every delivery.
func (r *PoolRouter) Start(interval time.Duration) {
	if r == nil || r.stateFile == "" || r.stop != nil {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				r.flush()
				return
			case <-ticker.C:
				r.flush()
			}
		}
	}()
}

// Close writes the final counts and stops the background writer.
func (r *PoolRouter) Close() {
	if r == nil || r.stop == nil {
		return
	}
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	<-r.done
}

func (r *PoolRouter) flush() {
	r.mu.Lock()
	if !r.dirty {
		r.mu.Unlock()
		return
	}
	snapshot := make(map[string]ipUsage, len(r.usage))
	for k, v := range r.usage {
		snapshot[k] = *v
	}
	r.dirty = false
	r.mu.Unlock()

	if err := writeJSONAtomic(r.stateFile, snapshot); err != nil {
		r.logger.Warn("Could not save warmup state", "file", r.stateFile, "error", err)
		r.mu.Lock()
		r.dirty = true
		r.mu.Unlock()
	}
}

func (r *PoolRouter) loadState() error {
	if r.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(r.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved map[string]ipUsage
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	for addr, u := range saved {
		u := u
		r.usage[addr] = &u
	}
	return nil
}

// writeJSONAtomic writes v to path via a temporary file and rename, so a
// crash mid-write leaves the previous state rather than a truncated file.
func writeJSONAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// sourceContextKey carries the chosen source address down the dial path.
//
// A context value rather than another parameter because the source has to
// reach every place a connection is made for this delivery (the first dial,
// the opportunistic-TLS redials, the session cache lookup) and nothing else
// along the way needs it. It is scoped to one delivery to one domain.
type sourceContextKey struct{}

func withSource(ctx context.Context, src *sourceIP) context.Context {
	if src == nil {
		return ctx
	}
	return context.WithValue(ctx, sourceContextKey{}, src)
}

func sourceFrom(ctx context.Context) *sourceIP {
	src, _ := ctx.Value(sourceContextKey{}).(*sourceIP)
	return src
}

// sessionKey is the session cache key for a delivery. A parked session left
// from one source address must never carry mail meant to leave from another,
// or pools would leak into each other through connection reuse.
func sessionKey(src *sourceIP, address string) string {
	if src == nil {
		return address
	}
	return src.addr + ">" + address
}

// shapingKey is what per-destination limits are tracked under. With pools,
// limits and backoff are per source address per destination: receivers
// throttle and defer by sending IP, so a deferral seen on one address says
// nothing about the others.
func shapingKey(src *sourceIP, domain string) string {
	if src == nil {
		return domain
	}
	return domain + shapingKeySep + src.addr
}

const shapingKeySep = "\x00"
