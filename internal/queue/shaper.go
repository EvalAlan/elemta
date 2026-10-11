package queue

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Traffic shaping: how fast, and how hard, to push at one destination.
//
// Delivery was previously governed only by a global worker count, which means
// every destination is treated the same and none of them are treated the way
// they ask to be. Large receivers do not publish a rate; they tell you by
// deferring, and the correct response to their 4xx is to slow down for *that*
// destination and leave the rest alone. max_connections_per_domain existed in
// the configuration, was shown in the UI, and was recorded in the config
// tripwire as "not currently consumed" — it did nothing at all.
//
// The shape of the answer matters as much as the numbers:
//
//   - A destination in backoff must not block a delivery worker. Sleeping until
//     Gmail is ready would hold a worker for minutes while every other domain
//     waits behind it — one slow destination becomes a stalled queue. So a
//     backed-off destination refuses immediately and the message is deferred,
//     which is what the retry schedule is for.
//   - Limits are per destination and nothing else. A global limit cannot express
//     "Gmail is unhappy" without also punishing everyone else.

// ShapingConfig bounds what is sent to a single destination.
type ShapingConfig struct {
	// MaxConnectionsPerDomain caps simultaneous deliveries to one destination.
	// Zero means no limit.
	MaxConnectionsPerDomain int
	// MaxMessagesPerMinute caps the send rate to one destination. Zero means no
	// limit.
	MaxMessagesPerMinute int
	// BackoffInitial is how long a destination is left alone after it first
	// defers, doubling up to BackoffMax.
	BackoffInitial time.Duration
	BackoffMax     time.Duration
}

// DefaultShapingConfig is deliberately permissive.
//
// Shaping that is too aggressive by default silently slows every deployment,
// including the ones delivering to a single internal mailbox server that would
// happily take everything at once. The backoff is where the value is, and it
// only engages when a destination has actually complained.
func DefaultShapingConfig() ShapingConfig {
	return ShapingConfig{
		MaxConnectionsPerDomain: 10,
		MaxMessagesPerMinute:    0,
		BackoffInitial:          30 * time.Second,
		BackoffMax:              30 * time.Minute,
	}
}

// ErrDestinationBackingOff says a destination asked for a pause and is still in
// it. The caller should defer the message rather than wait.
var ErrDestinationBackingOff = fmt.Errorf("destination is backing off after a deferral")

// Shaper applies per-destination limits.
type Shaper struct {
	config ShapingConfig

	mu      sync.Mutex
	domains map[string]*domainState
}

type domainState struct {
	// slots is the connection limit. Buffered channel rather than a counter so
	// waiting for one can respect a context.
	slots chan struct{}

	// nextSend enforces the rate limit; deferUntil enforces the backoff. They
	// are separate because they mean different things: one is a policy we chose,
	// the other is the destination telling us to stop.
	nextSend   time.Time
	deferUntil time.Time
	failures   int

	lastUsed time.Time

	// rate is this destination's own messages-per-minute cap, set from a
	// provider profile; zero falls back to the shaper-wide cap.
	rate int
	// throttledRate is the cap applied once the destination has said this
	// sender is going too fast; see ReportThrottle.
	throttledRate int
	// penalty is how many times, recently, the destination has throttled
	// us. Each level halves the send rate; one level is forgiven per
	// penaltyDecay without another throttle.
	penalty        int
	penaltyDecayAt time.Time
	throttled      uint64

	// Outcome counts for this destination since it started being tracked.
	// Deliberately not a complete ledger: idle destinations are evicted after
	// an hour and the table is capped, so these describe recent behaviour, not
	// history. Anything presenting them has to say so, or an operator reads
	// "0 bounces" as good news when it means "we forgot".
	delivered uint64
	deferred  uint64
	bounced   uint64
}

func NewShaper(config ShapingConfig) *Shaper {
	if config.BackoffInitial <= 0 {
		config.BackoffInitial = DefaultShapingConfig().BackoffInitial
	}
	if config.BackoffMax < config.BackoffInitial {
		config.BackoffMax = config.BackoffInitial
	}
	return &Shaper{config: config, domains: make(map[string]*domainState)}
}

// Acquire takes a delivery slot for a destination, waiting for the rate limit
// if there is one. The returned function releases the slot.
//
// It returns ErrDestinationBackingOff immediately when the destination is
// pausing, so the caller can defer the message instead of holding a worker.
func (s *Shaper) Acquire(ctx context.Context, domain string) (func(), error) {
	return s.AcquireWithLimits(ctx, domain, nil)
}

// Limits are per-destination overrides of the shaper-wide limits, used for
// destinations that a provider profile describes. Zero fields fall back to
// the shaper-wide values.
type Limits struct {
	MaxConnections       int
	MaxMessagesPerMinute int
	// ThrottledMessagesPerMinute is the rate after the destination throttles
	// us, before penalty halving. Zero means DefaultThrottledRate.
	ThrottledMessagesPerMinute int
}

// DefaultThrottledRate is the rate a throttled destination drops to when its
// profile does not say. A destination that has just told us we are sending
// too fast gets a slower pace after the backoff, not the pace that caused it.
const DefaultThrottledRate = 60

// penaltyDecay is how long a throttle penalty level lasts without a new
// throttle. Long enough that a receiver's rate window has rolled over;
// short enough that one bad hour does not slow a day.
const penaltyDecay = 15 * time.Minute

// maxPenalty bounds the halving: at the default throttled rate, four levels
// is under four messages a minute, which is slow enough to be polite and
// still enough to tell whether the receiver has recovered.
const maxPenalty = 4

// AcquireWithLimits is Acquire for a destination with its own limits. The
// connection cap is fixed when a destination is first seen; rates apply on
// every call, so a reload of profile rates takes effect.
func (s *Shaper) AcquireWithLimits(ctx context.Context, domain string, limits *Limits) (func(), error) {
	if s == nil {
		return func() {}, nil
	}

	now := time.Now()
	s.mu.Lock()
	state := s.stateForLimits(domain, now, limits)
	if limits != nil {
		state.rate = limits.MaxMessagesPerMinute
		state.throttledRate = limits.ThrottledMessagesPerMinute
	}
	if state.penalty > 0 && !now.Before(state.penaltyDecayAt) {
		state.penalty--
		state.penaltyDecayAt = now.Add(penaltyDecay)
	}

	if now.Before(state.deferUntil) {
		wait := state.deferUntil.Sub(now)
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s for another %s", ErrDestinationBackingOff, domain, wait.Round(time.Second))
	}

	// Reserve this send's place in the rate limit while holding the lock, so
	// concurrent workers space out rather than all reading the same nextSend.
	var wait time.Duration
	if interval := s.sendInterval(state); interval > 0 {
		if state.nextSend.After(now) {
			wait = state.nextSend.Sub(now)
		}
		base := state.nextSend
		if base.Before(now) {
			base = now
		}
		state.nextSend = base.Add(interval)
	}
	slots := state.slots
	s.mu.Unlock()

	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	if slots != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case slots <- struct{}{}:
		}
		return func() { <-slots }, nil
	}
	return func() {}, nil
}

// ReportSuccess clears a destination's backoff. One delivery is enough: the
// destination is evidently willing again, and holding a pause after that would
// slow a queue for no reason.
func (s *Shaper) ReportSuccess(domain string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.stateFor(domain, time.Now())
	state.failures = 0
	state.deferUntil = time.Time{}
	state.delivered++
}

// BackingOff reports how much longer a destination is paused for, if it is.
// It lets a caller refuse before doing work (a DNS lookup) that would only
// find out the same thing.
func (s *Shaper) BackingOff(domain string) (time.Duration, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.domains[domain]
	if !ok {
		return 0, false
	}
	now := time.Now()
	if now.Before(state.deferUntil) {
		return state.deferUntil.Sub(now), true
	}
	return 0, false
}

// ReportThrottle records that a destination said, in so many words, that it
// is rate limiting or reputation limiting this sender. That is a stronger
// statement than a generic 4xx, so it gets a longer pause (from initial,
// doubling to max) and a lasting penalty on the send rate afterwards: the
// pace that caused the throttle is not the pace to resume at.
func (s *Shaper) ReportThrottle(domain string, initial, maxBackoff time.Duration) time.Duration {
	if s == nil {
		return 0
	}
	if initial <= 0 {
		initial = s.config.BackoffInitial
	}
	if maxBackoff < initial {
		maxBackoff = initial
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	state := s.stateFor(domain, now)
	state.failures++
	state.deferred++
	state.throttled++
	if state.penalty < maxPenalty {
		state.penalty++
	}
	state.penaltyDecayAt = now.Add(penaltyDecay)

	backoff := initial
	for i := 1; i < state.failures && backoff < maxBackoff; i++ {
		backoff *= 2
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	// Never shorten a pause already in force.
	if until := now.Add(backoff); until.After(state.deferUntil) {
		state.deferUntil = until
	}
	return backoff
}

// ReportRecipientDeferral counts a deferral that was about one mailbox (full,
// or receiving too fast) rather than about us. It is not a reason to slow
// down for everyone else at that destination.
func (s *Shaper) ReportRecipientDeferral(domain string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFor(domain, time.Now()).deferred++
}

// ReportPermanentFailure records a bounce against a destination without
// changing how fast we send to it.
//
// Separate from ReportDeferral on purpose. A permanent rejection is about one
// message or one recipient and says nothing about the destination's appetite;
// backing off on those would slow a whole queue because one address does not
// exist. It is still worth counting, because a domain that accepts everything
// and bounces most of it is exactly what a deliverability problem looks like.
func (s *Shaper) ReportPermanentFailure(domain string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFor(domain, time.Now()).bounced++
}

// ReportDeferral records that a destination asked us to slow down, doubling the
// pause each consecutive time.
//
// Only for temporary failures. A permanent rejection is about the message or
// the recipient and says nothing about how fast the destination wants to be
// sent to — backing off on those would slow a queue because one address does
// not exist.
func (s *Shaper) ReportDeferral(domain string) time.Duration {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	state := s.stateFor(domain, now)
	state.failures++
	state.deferred++

	backoff := s.config.BackoffInitial
	for i := 1; i < state.failures && backoff < s.config.BackoffMax; i++ {
		backoff *= 2
	}
	if backoff > s.config.BackoffMax {
		backoff = s.config.BackoffMax
	}
	state.deferUntil = now.Add(backoff)
	return backoff
}

// Status describes what is being applied to a destination, for the dashboard.
type Status struct {
	Domain string `json:"domain"`
	// Provider names the provider profile when Domain is a provider key
	// rather than a single domain.
	Provider string `json:"provider,omitempty"`
	// SourceIP is the pool address these limits apply to. Empty for unpooled
	// mail, which is shaped per destination alone.
	SourceIP       string    `json:"source_ip,omitempty"`
	InUse          int       `json:"in_use"`
	MaxConnections int       `json:"max_connections"`
	Failures       int       `json:"failures"`
	BackingOffFor  string    `json:"backing_off_for,omitempty"`
	LastUsed       time.Time `json:"last_used"`

	// Recent outcomes for this destination. See domainState: these are not
	// totals for all time.
	Delivered uint64 `json:"delivered"`
	Deferred  uint64 `json:"deferred"`
	Bounced   uint64 `json:"bounced"`
	// Throttled counts deferrals the destination explained as rate or
	// reputation limiting; Penalty is how many halvings of the send rate are
	// in force because of them, and RatePerMinute the resulting cap (0 for
	// none).
	Throttled     uint64 `json:"throttled"`
	Penalty       int    `json:"penalty,omitempty"`
	RatePerMinute int    `json:"rate_per_minute,omitempty"`
}

// Statuses reports every destination currently being tracked.
func (s *Shaper) Statuses() []Status {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	out := make([]Status, 0, len(s.domains))
	for key, state := range s.domains {
		domain, sourceIP, _ := strings.Cut(key, shapingKeySep)
		maxConn := s.config.MaxConnectionsPerDomain
		if state.slots != nil {
			maxConn = cap(state.slots)
		}
		status := Status{
			Provider:       providerOfKey(domain),
			Throttled:      state.throttled,
			Penalty:        state.penalty,
			RatePerMinute:  s.effectiveRate(state),
			Domain:         domain,
			SourceIP:       sourceIP,
			MaxConnections: maxConn,
			Failures:       state.failures,
			LastUsed:       state.lastUsed,
			Delivered:      state.delivered,
			Deferred:       state.deferred,
			Bounced:        state.bounced,
		}
		if state.slots != nil {
			status.InUse = len(state.slots)
		}
		if now.Before(state.deferUntil) {
			status.BackingOffFor = state.deferUntil.Sub(now).Round(time.Second).String()
		}
		out = append(out, status)
	}
	return out
}

// stateFor returns a destination's state, creating it if needed. Callers hold
// the lock.
func (s *Shaper) stateFor(domain string, now time.Time) *domainState {
	return s.stateForLimits(domain, now, nil)
}

func (s *Shaper) stateForLimits(domain string, now time.Time, limits *Limits) *domainState {
	if state, ok := s.domains[domain]; ok {
		state.lastUsed = now
		return state
	}

	// Idle destinations are dropped before a new one is added. Mail goes to an
	// unbounded set of domains, so a map keyed by destination that only ever
	// grows is a slow memory leak on any busy relay.
	if len(s.domains) >= maxTrackedDomains {
		s.evictIdleLocked(now)
	}

	state := &domainState{lastUsed: now}
	maxConn := s.config.MaxConnectionsPerDomain
	if limits != nil && limits.MaxConnections > 0 {
		maxConn = limits.MaxConnections
	}
	if maxConn > 0 {
		state.slots = make(chan struct{}, maxConn)
	}
	s.domains[domain] = state
	return state
}

// maxTrackedDomains bounds the destination table.
const maxTrackedDomains = 10000

// idleEvictionAge is how long a destination must be untouched to be forgotten.
// Long enough that a backoff is never dropped early, since forgetting one means
// resuming full speed at a destination that asked us not to.
const idleEvictionAge = time.Hour

func (s *Shaper) evictIdleLocked(now time.Time) {
	for domain, state := range s.domains {
		// Never evict a destination that is still backing off or in use: both
		// would resume traffic the state exists to prevent.
		// len() on a nil channel is zero, so the nil check the compiler would
		// otherwise want here is redundant.
		if now.Before(state.deferUntil) || len(state.slots) > 0 {
			continue
		}
		if now.Sub(state.lastUsed) > idleEvictionAge {
			delete(s.domains, domain)
		}
	}
}

func (s *Shaper) sendInterval(state *domainState) time.Duration {
	rate := s.effectiveRate(state)
	if rate <= 0 {
		return 0
	}
	return time.Minute / time.Duration(rate)
}

// effectiveRate is a destination's current messages-per-minute cap, or 0 for
// none. Callers hold the lock.
func (s *Shaper) effectiveRate(state *domainState) int {
	rate := s.config.MaxMessagesPerMinute
	if state.rate > 0 {
		rate = state.rate
	}
	if state.penalty == 0 {
		return rate
	}
	throttled := state.throttledRate
	if throttled <= 0 {
		throttled = DefaultThrottledRate
	}
	if rate <= 0 || rate > throttled {
		rate = throttled
	}
	rate >>= state.penalty - 1
	if rate < 1 {
		rate = 1
	}
	return rate
}
