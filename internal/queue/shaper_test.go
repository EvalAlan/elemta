package queue

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// Shaping decides how hard to push at a destination, so the tests are about the
// ways that goes wrong: punishing everyone for one destination's mood, and
// holding a worker while a destination sulks.

func TestConnectionLimitIsPerDestination(t *testing.T) {
	shaper := NewShaper(ShapingConfig{MaxConnectionsPerDomain: 2})
	ctx := context.Background()

	first, err := shaper.Acquire(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := shaper.Acquire(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	// The third must wait, so a short context expires rather than proceeding.
	brief, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := shaper.Acquire(brief, "example.com"); err == nil {
		t.Error("a third connection to a destination limited to two should wait")
	}

	// A different destination is unaffected: that is the whole point of the
	// limit being per destination.
	other, err := shaper.Acquire(ctx, "other.example")
	if err != nil {
		t.Errorf("a busy destination must not block a different one: %v", err)
	}
	other()

	first()
	// With a slot free the third can proceed.
	third, err := shaper.Acquire(ctx, "example.com")
	if err != nil {
		t.Errorf("releasing a slot should admit the next delivery: %v", err)
	}
	third()
	second()
}

// TestBackoffRefusesImmediatelyRatherThanBlocking is the important one.
//
// Sleeping until a destination is ready would hold a delivery worker for
// minutes while every other domain waits behind it — one slow receiver becomes
// a stalled queue. A backed-off destination must refuse at once so the message
// is deferred and the worker moves on.
func TestBackoffRefusesImmediatelyRatherThanBlocking(t *testing.T) {
	shaper := NewShaper(ShapingConfig{
		MaxConnectionsPerDomain: 5,
		BackoffInitial:          time.Minute,
		BackoffMax:              time.Hour,
	})
	shaper.ReportDeferral("slow.example")

	start := time.Now()
	_, err := shaper.Acquire(context.Background(), "slow.example")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrDestinationBackingOff) {
		t.Fatalf("err = %v, want ErrDestinationBackingOff", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("took %v; a backed-off destination must refuse immediately, not wait", elapsed)
	}

	// And only that destination: everyone else still flows.
	release, err := shaper.Acquire(context.Background(), "fine.example")
	if err != nil {
		t.Errorf("an unrelated destination should be unaffected: %v", err)
	} else {
		release()
	}
}

func TestBackoffGrowsAndIsClearedByASuccess(t *testing.T) {
	shaper := NewShaper(ShapingConfig{
		BackoffInitial: time.Second,
		BackoffMax:     8 * time.Second,
	})

	first := shaper.ReportDeferral("example.com")
	second := shaper.ReportDeferral("example.com")
	third := shaper.ReportDeferral("example.com")
	if !(first < second && second < third) {
		t.Errorf("backoff should grow: %v, %v, %v", first, second, third)
	}

	// Bounded, or a destination that defers all day ends up parked for weeks.
	for i := 0; i < 20; i++ {
		shaper.ReportDeferral("example.com")
	}
	if capped := shaper.ReportDeferral("example.com"); capped > 8*time.Second {
		t.Errorf("backoff = %v, want it capped at 8s", capped)
	}

	// One delivery is enough to clear it: the destination is evidently willing
	// again, and holding the pause slows the queue for no reason.
	shaper.ReportSuccess("example.com")
	if _, err := shaper.Acquire(context.Background(), "example.com"); err != nil {
		t.Errorf("a success should clear the backoff, got %v", err)
	}
}

func TestRateLimitSpacesSends(t *testing.T) {
	// 600/minute is 100ms apart, fast enough to test without being slow.
	shaper := NewShaper(ShapingConfig{MaxMessagesPerMinute: 600})
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 3; i++ {
		release, err := shaper.Acquire(ctx, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	elapsed := time.Since(start)

	// Three sends at 100ms apart: the first is free, so at least 200ms.
	if elapsed < 150*time.Millisecond {
		t.Errorf("three sends took %v; the rate limit does not appear to apply", elapsed)
	}
}

// TestNoLimitsMeansNoWaiting keeps the default cheap: a deployment delivering to
// one internal mailbox server should not be slowed by machinery it did not ask
// for.
func TestNoLimitsMeansNoWaiting(t *testing.T) {
	shaper := NewShaper(ShapingConfig{})
	start := time.Now()
	for i := 0; i < 50; i++ {
		release, err := shaper.Acquire(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("50 unshaped acquisitions took %v", elapsed)
	}
}

// TestDestinationTableIsBounded: mail goes to an unbounded set of domains, so a
// map keyed by destination that only grows is a slow leak on a busy relay.
func TestDestinationTableIsBounded(t *testing.T) {
	shaper := NewShaper(ShapingConfig{MaxConnectionsPerDomain: 1})
	now := time.Now()

	shaper.mu.Lock()
	for i := 0; i < maxTrackedDomains+50; i++ {
		// Idle long enough to be evictable.
		shaper.domains[string(rune('a'+i%26))+string(rune('a'+i/26))+".example"] = &domainState{
			lastUsed: now.Add(-2 * time.Hour),
		}
	}
	shaper.mu.Unlock()

	release, err := shaper.Acquire(context.Background(), "new.example")
	if err != nil {
		t.Fatal(err)
	}
	release()

	shaper.mu.Lock()
	size := len(shaper.domains)
	shaper.mu.Unlock()
	if size > maxTrackedDomains {
		t.Errorf("tracking %d destinations, want no more than %d", size, maxTrackedDomains)
	}
}

// TestEvictionKeepsBackingOffDestinations: forgetting one means resuming full
// speed at a destination that just asked us not to.
func TestEvictionKeepsBackingOffDestinations(t *testing.T) {
	shaper := NewShaper(ShapingConfig{BackoffInitial: time.Hour, BackoffMax: time.Hour})
	shaper.ReportDeferral("angry.example")

	shaper.mu.Lock()
	// Make it look ancient, so only the backoff protects it.
	shaper.domains["angry.example"].lastUsed = time.Now().Add(-24 * time.Hour)
	shaper.evictIdleLocked(time.Now())
	_, stillThere := shaper.domains["angry.example"]
	shaper.mu.Unlock()

	if !stillThere {
		t.Error("a destination that is still backing off must not be forgotten")
	}
}

func TestShaperIsSafeUnderConcurrency(t *testing.T) {
	shaper := NewShaper(ShapingConfig{MaxConnectionsPerDomain: 4})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			domain := "example.com"
			if i%3 == 0 {
				domain = "other.example"
			}
			release, err := shaper.Acquire(context.Background(), domain)
			if err != nil {
				return
			}
			shaper.ReportSuccess(domain)
			release()
		}(i)
	}
	wg.Wait()
	_ = shaper.Statuses()
}

// TestDeliveryRefusesABackedOffDestinationWithoutTouchingTheNetwork proves the
// shaper is actually wired into delivery, not merely correct on its own.
//
// The resolver and dialer are replaced with ones that fail the test if they are
// called: a destination in backoff must be refused before any DNS lookup or
// connection, or the "don't hammer them" property is only a slogan.
func TestDeliveryRefusesABackedOffDestinationWithoutTouchingTheNetwork(t *testing.T) {
	handler := NewSMTPDeliveryHandler(0)
	shaper := NewShaper(ShapingConfig{
		MaxConnectionsPerDomain: 5,
		BackoffInitial:          time.Minute,
		BackoffMax:              time.Hour,
	})
	handler.SetShaper(shaper)

	handler.resolver = resolverFunc(func(ctx context.Context, name string) ([]*net.MX, error) {
		t.Errorf("MX lookup for %q: a backed-off destination must be refused before DNS", name)
		return nil, errors.New("should not be called")
	})
	handler.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		t.Errorf("dialled %s: a backed-off destination must be refused before connecting", address)
		return nil, errors.New("should not be called")
	}

	shaper.ReportDeferral("slow.example")

	_, _, _, err := handler.deliverToDomainWithMetadata(
		context.Background(), Message{From: "a@example.com", To: []string{"b@slow.example"}},
		"slow.example", []string{"b@slow.example"}, []byte("Subject: x\r\n\r\nhi\r\n"), false)

	if !errors.Is(err, ErrDestinationBackingOff) {
		t.Fatalf("err = %v, want ErrDestinationBackingOff", err)
	}
}

// resolverFunc adapts a function to the resolver the handler uses.
type resolverFunc func(context.Context, string) ([]*net.MX, error)

func (f resolverFunc) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return f(ctx, name)
}
