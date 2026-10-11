package metrics

import (
	"context"
	"testing"
	"time"
)

func withSenderClock(t *testing.T, at time.Time) *time.Time {
	t.Helper()
	now := at
	old := senderNow
	senderNow = func() time.Time { return now }
	t.Cleanup(func() { senderNow = old })
	return &now
}

func findSender(stats []SenderStats, dimension, key string) (SenderStats, bool) {
	for _, s := range stats {
		if s.Dimension == dimension && s.Key == key {
			return s, true
		}
	}
	return SenderStats{}, false
}

func TestSenderOutcomesRoundTripThroughValkey(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := withSenderClock(t, time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))

	incr := func(dimension, key, outcome string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.IncrSenderOutcome(ctx, dimension, key, outcome); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Three days ago: a bad day for the bulk pool.
	*now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	incr("pool", "bulk", OutcomeDelivered, 10)
	incr("pool", "bulk", OutcomeComplained, 5)
	// Today.
	*now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	incr("pool", "bulk", OutcomeDelivered, 100)
	incr("pool", "bulk", OutcomeDeferred, 4)
	incr("pool", "bulk", OutcomeThrottled, 3)
	incr("ip", "203.0.113.20", OutcomeBounced, 2)
	incr("provider", "Gmail", OutcomeDelivered, 7)

	today, err := store.GetSenderStats(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	bulk, ok := findSender(today, "pool", "bulk")
	if !ok || bulk.Delivered != 100 || bulk.Deferred != 4 || bulk.Throttled != 3 || bulk.Complained != 0 {
		t.Errorf("today's bulk = %+v; the bad day three days ago must not leak into today", bulk)
	}
	if g, ok := findSender(today, "provider", "gmail"); !ok || g.Delivered != 7 {
		t.Errorf("provider keys are not normalised: %+v", today)
	}
	if ip, ok := findSender(today, "ip", "203.0.113.20"); !ok || ip.Bounced != 2 {
		t.Errorf("ip row = %+v", ip)
	}

	week, err := store.GetSenderStats(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if bulk, _ := findSender(week, "pool", "bulk"); bulk.Delivered != 110 || bulk.Complained != 5 {
		t.Errorf("7-day bulk = %+v, want 110 delivered and 5 complaints", bulk)
	}

	// Junk never becomes a key: a complaint report's Source-IP is written by
	// whoever sent the report.
	for _, bad := range []struct{ dimension, key, outcome string }{
		{"pool", "", OutcomeDelivered},
		{"pool", "has space", OutcomeDelivered},
		{"pool", "bulk", "exploded"},
		{"campaign", "x", OutcomeDelivered},
		{"ip", string(make([]byte, 200)), OutcomeDelivered},
	} {
		if err := store.IncrSenderOutcome(ctx, bad.dimension, bad.key, bad.outcome); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := store.GetSenderStats(ctx, 7)
	if len(after) != len(week) {
		t.Errorf("invalid input created rows: %+v", after)
	}

	// Past retention the counters have expired; the member goes too.
	*now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	later, err := store.GetSenderStats(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 0 {
		t.Errorf("rows outside the retention window are still reported: %+v", later)
	}
	members, _ := store.client.Do(ctx, store.client.B().Smembers().Key(store.senderSetKey("pool")).Build()).AsStrSlice()
	if len(members) != 0 {
		t.Errorf("expired members left in the set: %v", members)
	}
}

func TestSenderCountersExpire(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	withSenderClock(t, time.Now())
	if err := store.IncrSenderOutcome(ctx, "pool", "bulk", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}
	key := store.senderCounterKey("pool", "bulk", senderDay(senderNow(), 0), OutcomeDelivered)
	ttl, err := store.client.Do(ctx, store.client.B().Ttl().Key(key).Build()).AsInt64()
	if err != nil || ttl <= 0 || ttl > int64((SenderRetentionDays+1)*24*3600) {
		t.Errorf("ttl = %d, %v; a sender counter must expire", ttl, err)
	}
}
