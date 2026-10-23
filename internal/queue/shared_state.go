package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

// Shared delivery state across nodes.
//
// Warmup counts and provider throttles are facts about a sending IP and a
// receiver's opinion of it, not about the process that happens to hold them.
// With several nodes on one queue backend, per-process state means each node
// spends the whole daily warmup cap, and a 421 from Gmail to one node leaves
// the others sending at full speed into the same throttle. A SharedState
// makes those numbers cluster-wide.
//
// It is optional and strictly advisory. A node that cannot reach the store
// falls back to its own counts: over-sending a warming address for the length
// of an outage is a reputation cost, but refusing to deliver because a
// coordination service is down would be an outage of the thing the
// coordination exists to protect.

// SharedState holds warmup counts and provider throttle state that every node
// sees. Implementations must be safe for concurrent use.
type SharedState interface {
	// TakeWarmup reserves one unit of addr's allowance for the UTC day if
	// fewer than allowed have been sent, in a single atomic step so two nodes
	// cannot both take the last unit. allowed < 0 means uncapped. It returns
	// whether the unit was taken and the day's count after the attempt.
	TakeWarmup(ctx context.Context, day, addr string, allowed int) (taken bool, sent int, err error)
	// RefundWarmup returns a unit taken by TakeWarmup that never reached a
	// receiver. It never takes the count below zero.
	RefundWarmup(ctx context.Context, day, addr string) error
	// WarmupSent is the day's count for addr.
	WarmupSent(ctx context.Context, day, addr string) (int, error)
	// MergeThrottle folds st into the shared state for a shaping key, keeping
	// the later backoff and the heavier penalty, and returns the result.
	MergeThrottle(ctx context.Context, key string, st ThrottleState) (ThrottleState, error)
	// Throttle is the shared state for a shaping key; zero when there is none.
	Throttle(ctx context.Context, key string) (ThrottleState, error)
}

// ThrottleState is the part of a destination's shaping state that other
// nodes need to see: how long it asked us to stop, and how hard it has been
// limiting us.
type ThrottleState struct {
	DeferUntil time.Time
	// Penalty is the number of send-rate halvings in force at PenaltyDecayAt
	// minus one decay period; see Shaper.ReportThrottle.
	Penalty        int
	PenaltyDecayAt time.Time
}

// normalized decays a penalty to what it would be at now, so states written
// at different times compare like for like.
func (t ThrottleState) normalized(now time.Time) ThrottleState {
	if t.Penalty > 0 && !now.Before(t.PenaltyDecayAt) {
		steps := 1 + int(now.Sub(t.PenaltyDecayAt)/penaltyDecay)
		t.Penalty -= steps
		t.PenaltyDecayAt = t.PenaltyDecayAt.Add(time.Duration(steps) * penaltyDecay)
		if t.Penalty <= 0 {
			t.Penalty, t.PenaltyDecayAt = 0, time.Time{}
		}
	}
	return t
}

// expiry is when the state stops meaning anything: the backoff is over and
// every penalty level has decayed.
func (t ThrottleState) expiry() time.Time {
	end := t.DeferUntil
	if t.Penalty > 0 {
		if e := t.PenaltyDecayAt.Add(time.Duration(t.Penalty-1) * penaltyDecay); e.After(end) {
			end = e
		}
	}
	return end
}

const (
	// sharedOpTimeout bounds every store call. These sit on the delivery
	// path, so a slow store must cost milliseconds, not a worker.
	sharedOpTimeout = 250 * time.Millisecond
	// sharedCooldown is how long the store is skipped after a failure. A
	// blackholed store would otherwise charge the full timeout to every
	// delivery for the length of the outage.
	sharedCooldown = 10 * time.Second
	// sharedLogInterval rate-limits the "store unreachable" warning.
	sharedLogInterval = time.Minute
	// sharedSyncInterval is how stale a node's copy of a provider's shared
	// throttle may be. Throttles last minutes, so seconds of lag is
	// immaterial, and it keeps the store off the per-message path.
	sharedSyncInterval = 5 * time.Second
)

// sharedGuard wraps a SharedState with the fail-open policy: a cooldown after
// errors and rate-limited logging. One guard is shared by the pool router and
// the shaper so one outage produces one stream of warnings.
type sharedGuard struct {
	store  SharedState
	logger *slog.Logger

	mu         sync.Mutex
	skipUntil  time.Time
	lastLog    time.Time
	suppressed int
	failing    bool
}

func newSharedGuard(store SharedState, logger *slog.Logger) *sharedGuard {
	if store == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &sharedGuard{store: store, logger: logger.With("component", "shared-delivery-state")}
}

// available reports whether the store should be tried now.
func (g *sharedGuard) available() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !time.Now().Before(g.skipUntil)
}

func (g *sharedGuard) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), sharedOpTimeout)
}

// fail records a store error and starts the cooldown.
func (g *sharedGuard) fail(op string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.skipUntil = now.Add(sharedCooldown)
	g.failing = true
	if now.Sub(g.lastLog) < sharedLogInterval {
		g.suppressed++
		return
	}
	g.logger.Warn("Shared delivery state unavailable; using this node's own warmup counts and throttles",
		"operation", op, "error", err, "suppressed_since_last", g.suppressed,
		"retry_in", sharedCooldown.String())
	g.lastLog, g.suppressed = now, 0
}

// ok records a successful call, saying so once after an outage so the log
// shows when the cluster went back to shared accounting.
func (g *sharedGuard) ok() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failing {
		g.failing = false
		g.logger.Info("Shared delivery state reachable again")
	}
}

// ValkeyState is a SharedState in Valkey (or Redis).
type ValkeyState struct {
	addr   string
	prefix string

	mu       sync.Mutex
	client   valkey.Client
	nextDial time.Time
}

// NewValkeyState returns a store for addr (host:port). It does not connect:
// the first call does, and a failed connection is retried on later calls, so
// a node that starts while Valkey is down joins the shared state once it is
// back instead of staying local until a restart.
func NewValkeyState(addr, prefix string) *ValkeyState {
	if prefix == "" {
		prefix = DefaultSharedStatePrefix
	}
	return &ValkeyState{addr: addr, prefix: prefix}
}

// DefaultSharedStatePrefix namespaces the keys. Two clusters sharing one
// Valkey need different prefixes or they will share warmup counts too.
const DefaultSharedStatePrefix = "elemta:delivery:"

// warmupTTL keeps a day's counter past its UTC day so a node whose clock is
// a little behind still finds it, then lets it go.
const warmupTTL = 48 * time.Hour

func (v *ValkeyState) conn() (valkey.Client, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.client != nil {
		return v.client, nil
	}
	if time.Now().Before(v.nextDial) {
		return nil, errors.New("valkey: waiting before reconnecting")
	}
	client, err := valkeyaddr.NewClient(v.addr, func(o *valkey.ClientOption) {
		o.Dialer = net.Dialer{Timeout: sharedOpTimeout * 4}
		// Client-side caching would serve stale counts, which is exactly
		// what an atomic shared counter exists to avoid.
		o.DisableCache = true
		o.ConnWriteTimeout = sharedOpTimeout * 4
	})
	if err != nil {
		v.nextDial = time.Now().Add(sharedCooldown)
		return nil, fmt.Errorf("valkey %s: %w", valkeyaddr.Display(v.addr), err)
	}
	v.client = client
	return client, nil
}

// Close releases the connection.
func (v *ValkeyState) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.client != nil {
		v.client.Close()
		v.client = nil
	}
}

func (v *ValkeyState) warmupKey(day, addr string) string {
	return v.prefix + "warmup:" + day + ":" + addr
}

func (v *ValkeyState) throttleKey(key string) string {
	// The shaping key separates destination and source with a NUL; a
	// printable separator keeps the keys readable in valkey-cli.
	return v.prefix + "throttle:" + strings.ReplaceAll(key, shapingKeySep, "|")
}

// takeWarmupScript checks and increments in one step: a GET then INCR from
// the client would let two nodes both read cap-1 and both send.
var takeWarmupScript = valkey.NewLuaScript(`
local n = tonumber(redis.call('GET', KEYS[1]) or '0')
local cap = tonumber(ARGV[1])
if cap >= 0 and n >= cap then return {0, n} end
n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return {1, n}
`)

var refundWarmupScript = valkey.NewLuaScript(`
local n = tonumber(redis.call('GET', KEYS[1]) or '0')
if n > 0 then return redis.call('DECR', KEYS[1]) end
return 0
`)

// mergeThrottleScript keeps the later backoff and the heavier penalty. Both
// sides are decayed to the caller's clock first, or a stale penalty written
// an hour ago would outweigh a fresh lighter one.
var mergeThrottleScript = valkey.NewLuaScript(`
local now = tonumber(ARGV[4])
local decay = tonumber(ARGV[5])
local function norm(p, da)
  if p > 0 and now >= da then
    local steps = 1 + math.floor((now - da) / decay)
    p = p - steps
    da = da + steps * decay
    if p <= 0 then p = 0; da = 0 end
  end
  return p, da
end
local cur = redis.call('HMGET', KEYS[1], 'defer_until', 'penalty', 'decay_at')
local du = tonumber(cur[1] or '0')
local p, da = norm(tonumber(cur[2] or '0'), tonumber(cur[3] or '0'))
local ndu = tonumber(ARGV[1])
local np, nda = norm(tonumber(ARGV[2]), tonumber(ARGV[3]))
if ndu > du then du = ndu end
if np > p or (np == p and nda > da) then p = np; da = nda end
redis.call('HSET', KEYS[1], 'defer_until', du, 'penalty', p, 'decay_at', da)
local ttl = tonumber(ARGV[6])
if redis.call('PTTL', KEYS[1]) < ttl then redis.call('PEXPIRE', KEYS[1], ttl) end
return {du, p, da}
`)

// TakeWarmup implements SharedState.
func (v *ValkeyState) TakeWarmup(ctx context.Context, day, addr string, allowed int) (bool, int, error) {
	c, err := v.conn()
	if err != nil {
		return false, 0, err
	}
	res, err := takeWarmupScript.Exec(ctx, c, []string{v.warmupKey(day, addr)},
		[]string{strconv.Itoa(allowed), strconv.Itoa(int(warmupTTL.Seconds()))}).AsIntSlice()
	if err != nil {
		return false, 0, err
	}
	if len(res) != 2 {
		return false, 0, fmt.Errorf("valkey: unexpected warmup reply %v", res)
	}
	return res[0] == 1, int(res[1]), nil
}

// RefundWarmup implements SharedState.
func (v *ValkeyState) RefundWarmup(ctx context.Context, day, addr string) error {
	c, err := v.conn()
	if err != nil {
		return err
	}
	return refundWarmupScript.Exec(ctx, c, []string{v.warmupKey(day, addr)}, nil).Error()
}

// WarmupSent implements SharedState.
func (v *ValkeyState) WarmupSent(ctx context.Context, day, addr string) (int, error) {
	c, err := v.conn()
	if err != nil {
		return 0, err
	}
	n, err := c.Do(ctx, c.B().Get().Key(v.warmupKey(day, addr)).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		return 0, nil
	}
	return int(n), err
}

// MergeThrottle implements SharedState.
func (v *ValkeyState) MergeThrottle(ctx context.Context, key string, st ThrottleState) (ThrottleState, error) {
	c, err := v.conn()
	if err != nil {
		return ThrottleState{}, err
	}
	now := time.Now()
	ttl := st.expiry().Sub(now)
	if ttl < time.Second {
		ttl = time.Second
	}
	res, err := mergeThrottleScript.Exec(ctx, c, []string{v.throttleKey(key)}, []string{
		strconv.FormatInt(unixMilli(st.DeferUntil), 10),
		strconv.Itoa(st.Penalty),
		strconv.FormatInt(unixMilli(st.PenaltyDecayAt), 10),
		strconv.FormatInt(now.UnixMilli(), 10),
		strconv.FormatInt(penaltyDecay.Milliseconds(), 10),
		strconv.FormatInt(ttl.Milliseconds(), 10),
	}).AsIntSlice()
	if err != nil {
		return ThrottleState{}, err
	}
	if len(res) != 3 {
		return ThrottleState{}, fmt.Errorf("valkey: unexpected throttle reply %v", res)
	}
	return ThrottleState{DeferUntil: fromMilli(res[0]), Penalty: int(res[1]), PenaltyDecayAt: fromMilli(res[2])}, nil
}

// Throttle implements SharedState.
func (v *ValkeyState) Throttle(ctx context.Context, key string) (ThrottleState, error) {
	c, err := v.conn()
	if err != nil {
		return ThrottleState{}, err
	}
	vals, err := c.Do(ctx, c.B().Hmget().Key(v.throttleKey(key)).Field("defer_until", "penalty", "decay_at").Build()).ToArray()
	if err != nil {
		return ThrottleState{}, err
	}
	field := func(i int) int64 {
		if i >= len(vals) {
			return 0
		}
		n, err := vals[i].AsInt64()
		if err != nil {
			return 0
		}
		return n
	}
	return ThrottleState{DeferUntil: fromMilli(field(0)), Penalty: int(field(1)), PenaltyDecayAt: fromMilli(field(2))}, nil
}

func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMilli(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
