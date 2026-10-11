package queue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memSharedState is an in-memory SharedState: what two nodes pointed at one
// Valkey would see, without the network.
type memSharedState struct {
	mu        sync.Mutex
	warmup    map[string]int
	throttles map[string]ThrottleState
	down      atomic.Bool
	calls     atomic.Int64
}

func newMemSharedState() *memSharedState {
	return &memSharedState{warmup: map[string]int{}, throttles: map[string]ThrottleState{}}
}

var errStoreDown = errors.New("store unreachable")

func (m *memSharedState) check() error {
	m.calls.Add(1)
	if m.down.Load() {
		return errStoreDown
	}
	return nil
}

func (m *memSharedState) TakeWarmup(_ context.Context, day, addr string, allowed int) (bool, int, error) {
	if err := m.check(); err != nil {
		return false, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := day + "|" + addr
	if allowed >= 0 && m.warmup[k] >= allowed {
		return false, m.warmup[k], nil
	}
	m.warmup[k]++
	return true, m.warmup[k], nil
}

func (m *memSharedState) RefundWarmup(_ context.Context, day, addr string) error {
	if err := m.check(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if k := day + "|" + addr; m.warmup[k] > 0 {
		m.warmup[k]--
	}
	return nil
}

func (m *memSharedState) WarmupSent(_ context.Context, day, addr string) (int, error) {
	if err := m.check(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.warmup[day+"|"+addr], nil
}

func (m *memSharedState) MergeThrottle(_ context.Context, key string, st ThrottleState) (ThrottleState, error) {
	if err := m.check(); err != nil {
		return ThrottleState{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cur := m.throttles[key].normalized(now)
	st = st.normalized(now)
	if st.DeferUntil.After(cur.DeferUntil) {
		cur.DeferUntil = st.DeferUntil
	}
	if st.Penalty > cur.Penalty || (st.Penalty == cur.Penalty && st.PenaltyDecayAt.After(cur.PenaltyDecayAt)) {
		cur.Penalty, cur.PenaltyDecayAt = st.Penalty, st.PenaltyDecayAt
	}
	m.throttles[key] = cur
	return cur, nil
}

func (m *memSharedState) Throttle(_ context.Context, key string) (ThrottleState, error) {
	if err := m.check(); err != nil {
		return ThrottleState{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.throttles[key], nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// warmingPool is one pool with a single warming address on day one of a
// 50-a-day schedule.
func warmingPool(stateFile string) PoolsConfig {
	return PoolsConfig{
		Pools: []PoolConfig{{
			Name:           "bulk",
			Senders:        []string{"news.example.com"},
			WarmupSchedule: []int{50},
			IPs:            []PoolIPConfig{{Address: "192.0.2.20", WarmupStart: "2026-10-01"}},
		}},
		StateFile: stateFile,
	}
}

// lateInDay is late enough on the warmup start date that the whole day's cap
// has been released by the pacing.
var lateInDay = time.Date(2026, 10, 1, 23, 30, 0, 0, time.UTC)

func newNode(t *testing.T, store SharedState) *PoolRouter {
	t.Helper()
	r := mustPoolRouter(t, warmingPool(""))
	r.now = func() time.Time { return lateInDay }
	r.setShared(newSharedGuard(store, quietLogger()))
	return r
}

func TestTwoNodesSharingAStoreRespectOneWarmupCap(t *testing.T) {
	store := newMemSharedState()
	nodes := []*PoolRouter{newNode(t, store), newNode(t, store)}

	var sent atomic.Int64
	var wg sync.WaitGroup
	for _, node := range nodes {
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func(r *PoolRouter) {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					src, _, err := r.acquire("x@news.example.com")
					if err == nil && src != nil {
						sent.Add(1)
					} else if !errors.Is(err, ErrPoolAtCapacity) {
						t.Errorf("acquire: %v", err)
					}
				}
			}(node)
		}
	}
	wg.Wait()

	if got := sent.Load(); got != 50 {
		t.Fatalf("two nodes sent %d between them, want the single cap of 50", got)
	}
	for i, node := range nodes {
		st := node.Statuses()
		if len(st) != 1 || st[0].SentToday != 50 {
			t.Errorf("node %d reports %+v, want the cluster's 50 sent today", i, st)
		}
	}
}

func TestSharedRefundReturnsTheUnitToEveryNode(t *testing.T) {
	store := newMemSharedState()
	a, b := newNode(t, store), newNode(t, store)
	var releases []func()
	for i := 0; i < 50; i++ {
		_, release, err := a.acquire("x@news.example.com")
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		releases = append(releases, release)
	}
	if _, _, err := b.acquire("x@news.example.com"); !errors.Is(err, ErrPoolAtCapacity) {
		t.Fatalf("node b acquired past the shared cap: %v", err)
	}
	releases[0]()
	releases[0]() // a second call must not refund twice
	if _, _, err := b.acquire("x@news.example.com"); err != nil {
		t.Fatalf("node b could not use the refunded unit: %v", err)
	}
	if _, _, err := b.acquire("x@news.example.com"); !errors.Is(err, ErrPoolAtCapacity) {
		t.Fatalf("one refund let through two sends: %v", err)
	}
}

func TestUnreachableStoreFallsBackToLocalCounting(t *testing.T) {
	store := newMemSharedState()
	store.down.Store(true)
	r := newNode(t, store)

	sent := 0
	for i := 0; i < 80; i++ {
		if src, _, err := r.acquire("x@news.example.com"); err == nil && src != nil {
			sent++
		}
	}
	if sent != 50 {
		t.Fatalf("with the store down the node sent %d, want its local cap of 50", sent)
	}
	// After the first failure the store is left alone for the cooldown, so
	// an outage costs one timeout, not one per delivery.
	if calls := store.calls.Load(); calls != 1 {
		t.Errorf("store was called %d times during the cooldown, want 1", calls)
	}
}

func TestSharedStoreIsTriedAgainAfterTheCooldown(t *testing.T) {
	store := newMemSharedState()
	g := newSharedGuard(store, quietLogger())
	g.fail("test", errStoreDown)
	if g.available() {
		t.Fatal("store available straight after a failure")
	}
	g.mu.Lock()
	g.skipUntil = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if !g.available() {
		t.Fatal("store still skipped after the cooldown")
	}
}

func TestWarmAddressesAreNotCountedRemotely(t *testing.T) {
	store := newMemSharedState()
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "warm", Senders: []string{"example.com"}, IPs: []PoolIPConfig{{Address: "192.0.2.30"}},
	}}})
	r.setShared(newSharedGuard(store, quietLogger()))
	for i := 0; i < 10; i++ {
		if _, _, err := r.acquire("x@example.com"); err != nil {
			t.Fatalf("acquire: %v", err)
		}
	}
	if calls := store.calls.Load(); calls != 0 {
		t.Errorf("uncapped address made %d store calls, want 0", calls)
	}
}

func TestProviderThrottleOnOneNodeSlowsTheOther(t *testing.T) {
	store := newMemSharedState()
	a, b := NewShaper(DefaultShapingConfig()), NewShaper(DefaultShapingConfig())
	a.SetSharedState(store, quietLogger())
	b.SetSharedState(store, quietLogger())

	key := shapingKey(&sourceIP{addr: "192.0.2.20"}, "provider:gmail")
	a.ReportThrottle(key, 10*time.Minute, time.Hour)

	if wait, backingOff := b.BackingOff(key); !backingOff || wait < 9*time.Minute {
		t.Fatalf("node b BackingOff = %v, %v; want the 10m pause node a was given", wait, backingOff)
	}
	// Force a fresh read: the first one above was already cached.
	b.mu.Lock()
	b.sharedSynced = map[string]time.Time{}
	b.mu.Unlock()
	if _, err := b.AcquireWithLimits(context.Background(), key, nil); !errors.Is(err, ErrDestinationBackingOff) {
		t.Fatalf("node b acquired a throttled provider: %v", err)
	}
	for _, st := range b.Statuses() {
		if st.Penalty != 1 || st.RatePerMinute != DefaultThrottledRate {
			t.Errorf("node b status %+v; want the shared penalty and throttled rate", st)
		}
	}
}

func TestPlainDomainBackoffStaysLocal(t *testing.T) {
	store := newMemSharedState()
	a, b := NewShaper(DefaultShapingConfig()), NewShaper(DefaultShapingConfig())
	a.SetSharedState(store, quietLogger())
	b.SetSharedState(store, quietLogger())
	a.ReportThrottle("example.com", time.Minute, time.Hour)
	if _, backingOff := b.BackingOff("example.com"); backingOff {
		t.Fatal("a plain domain's backoff reached another node")
	}
	if calls := store.calls.Load(); calls != 0 {
		t.Errorf("plain domain made %d store calls, want 0", calls)
	}
}

func TestShaperWithUnreachableStoreStillShapesLocally(t *testing.T) {
	store := newMemSharedState()
	store.down.Store(true)
	s := NewShaper(DefaultShapingConfig())
	s.SetSharedState(store, quietLogger())
	s.ReportThrottle("provider:gmail", time.Minute, time.Hour)
	if _, backingOff := s.BackingOff("provider:gmail"); !backingOff {
		t.Fatal("local throttle lost when the store is down")
	}
}

func TestThrottleStateNormalizedDecaysPenalty(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st := ThrottleState{Penalty: 3, PenaltyDecayAt: now.Add(-penaltyDecay - time.Minute)}
	got := st.normalized(now)
	if got.Penalty != 1 || !got.PenaltyDecayAt.Equal(st.PenaltyDecayAt.Add(2*penaltyDecay)) {
		t.Fatalf("normalized = %+v; want penalty 1 decaying at %v", got, st.PenaltyDecayAt.Add(2*penaltyDecay))
	}
	if got := (ThrottleState{Penalty: 1, PenaltyDecayAt: now.Add(-time.Hour)}).normalized(now); got.Penalty != 0 {
		t.Fatalf("fully decayed penalty = %d, want 0", got.Penalty)
	}
}

func TestReplacePoolRouterKeepsTodaysCounts(t *testing.T) {
	dir := t.TempDir()
	h := NewSMTPDeliveryHandler(0)
	first := mustPoolRouter(t, warmingPool(filepath.Join(dir, "pool-state.json")))
	first.now = func() time.Time { return lateInDay }
	h.SetPoolRouter(first)
	for i := 0; i < 50; i++ {
		if _, _, err := h.poolRouter().acquire("x@news.example.com"); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	cfg := warmingPool(filepath.Join(dir, "pool-state.json"))
	cfg.Pools[0].Senders = append(cfg.Pools[0].Senders, "promo.example.com")
	second := mustPoolRouter(t, cfg)
	second.now = func() time.Time { return lateInDay }
	h.ReplacePoolRouter(second)
	defer h.poolRouter().Close()

	if h.poolRouter() != second {
		t.Fatal("reload did not install the new router")
	}
	if _, _, err := second.acquire("x@promo.example.com"); !errors.Is(err, ErrPoolAtCapacity) {
		t.Fatalf("reload reset the warmup count: %v", err)
	}

	h.ReplacePoolRouter(nil)
	if src, _, err := h.poolRouter().acquire("x@news.example.com"); err != nil || src != nil {
		t.Fatalf("after removing pools acquire = %v, %v; want unpooled", src, err)
	}
}

// TestValkeyStateAgainstRedis runs the Lua scripts against a real server
// when one is installed; the in-memory fake cannot tell whether they parse.
func TestValkeyStateAgainstRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a redis-server")
	}
	bin, err := exec.LookPath("valkey-server")
	if err != nil {
		if bin, err = exec.LookPath("redis-server"); err != nil {
			t.Skip("no valkey-server or redis-server installed")
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--save", "", "--appendonly", "no", "--bind", "127.0.0.1") // #nosec G204 -- test-only, binary from PATH
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	ctx := context.Background()
	a, b := NewValkeyState(addr, "test:"), NewValkeyState(addr, "test:")
	defer a.Close()
	defer b.Close()

	var taken atomic.Int64
	var wg sync.WaitGroup
	for _, st := range []*ValkeyState{a, b} {
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(st *ValkeyState) {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					ok, _, err := st.TakeWarmup(ctx, "2026-10-01", "192.0.2.20", 25)
					if err != nil {
						t.Errorf("TakeWarmup: %v", err)
						return
					}
					if ok {
						taken.Add(1)
					}
				}
			}(st)
		}
	}
	wg.Wait()
	if got := taken.Load(); got != 25 {
		t.Fatalf("took %d units against a cap of 25", got)
	}
	if err := a.RefundWarmup(ctx, "2026-10-01", "192.0.2.20"); err != nil {
		t.Fatal(err)
	}
	if n, err := b.WarmupSent(ctx, "2026-10-01", "192.0.2.20"); err != nil || n != 24 {
		t.Fatalf("WarmupSent = %d, %v; want 24", n, err)
	}
	if n, err := b.WarmupSent(ctx, "2026-10-02", "192.0.2.20"); err != nil || n != 0 {
		t.Fatalf("WarmupSent for an unused day = %d, %v; want 0", n, err)
	}

	key := shapingKey(&sourceIP{addr: "192.0.2.20"}, "provider:gmail")
	now := time.Now()
	in := ThrottleState{DeferUntil: now.Add(10 * time.Minute), Penalty: 2, PenaltyDecayAt: now.Add(penaltyDecay)}
	if _, err := a.MergeThrottle(ctx, key, in); err != nil {
		t.Fatal(err)
	}
	// A lighter, shorter throttle from another node must not lift the first.
	merged, err := b.MergeThrottle(ctx, key, ThrottleState{DeferUntil: now.Add(time.Minute), Penalty: 1, PenaltyDecayAt: now.Add(penaltyDecay)})
	if err != nil {
		t.Fatal(err)
	}
	if merged.Penalty != 2 || merged.DeferUntil.UnixMilli() != in.DeferUntil.UnixMilli() {
		t.Fatalf("merged = %+v; want the heavier, longer throttle %+v", merged, in)
	}
	got, err := b.Throttle(ctx, key)
	if err != nil || got.Penalty != 2 || got.DeferUntil.UnixMilli() != in.DeferUntil.UnixMilli() {
		t.Fatalf("Throttle = %+v, %v; want %+v", got, err, in)
	}
	if none, err := b.Throttle(ctx, "provider:yahoo"); err != nil || !none.DeferUntil.IsZero() || none.Penalty != 0 {
		t.Fatalf("Throttle for an unknown key = %+v, %v; want zero", none, err)
	}
}

func TestValkeyStateUnreachableFailsFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	st := NewValkeyState(addr, "")
	defer st.Close()
	start := time.Now()
	if _, _, err := st.TakeWarmup(context.Background(), "2026-10-01", "192.0.2.20", 1); err == nil {
		t.Fatal("TakeWarmup against nothing succeeded")
	}
	// The second call inside the redial wait does not dial at all.
	if _, _, err := st.TakeWarmup(context.Background(), "2026-10-01", "192.0.2.20", 1); err == nil {
		t.Fatal("TakeWarmup against nothing succeeded")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("unreachable store took %v to fail", elapsed)
	}
}
