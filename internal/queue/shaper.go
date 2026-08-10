package queue

import (
	"context"
	"fmt"
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
	if s == nil {
		return func() {}, nil
	}

	now := time.Now()
	s.mu.Lock()
	state := s.stateFor(domain, now)

	if now.Before(state.deferUntil) {
		wait := state.deferUntil.Sub(now)
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s for another %s", ErrDestinationBackingOff, domain, wait.Round(time.Second))
	}

	// Reserve this send's place in the rate limit while holding the lock, so
	// concurrent workers space out rather than all reading the same nextSend.
	var wait time.Duration
	if interval := s.sendInterval(); interval > 0 {
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
	Domain         string    `json:"domain"`
	InUse          int       `json:"in_use"`
	MaxConnections int       `json:"max_connections"`
	Failures       int       `json:"failures"`
	BackingOffFor  string    `json:"backing_off_for,omitempty"`
	LastUsed       time.Time `json:"last_used"`
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
	for domain, state := range s.domains {
		status := Status{
			Domain:         domain,
			MaxConnections: s.config.MaxConnectionsPerDomain,
			Failures:       state.failures,
			LastUsed:       state.lastUsed,
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
	if s.config.MaxConnectionsPerDomain > 0 {
		state.slots = make(chan struct{}, s.config.MaxConnectionsPerDomain)
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
		if now.Before(state.deferUntil) || (state.slots != nil && len(state.slots) > 0) {
			continue
		}
		if now.Sub(state.lastUsed) > idleEvictionAge {
			delete(s.domains, domain)
		}
	}
}

func (s *Shaper) sendInterval() time.Duration {
	if s.config.MaxMessagesPerMinute <= 0 {
		return 0
	}
	return time.Minute / time.Duration(s.config.MaxMessagesPerMinute)
}
