package metrics

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// These are the first tests in this package, and they exist because the
// per-destination report was shipped with none.
//
// Both sides of that feature were tested against stubs — the queue stubbed the
// recorder, the API stubbed the store — so the only code that actually had to
// be right, the key names and the commands, was exercised by nothing. A typo in
// a key would have left every other test passing and the report empty.
//
// They talk to a real Valkey because that is the point. There is no useful way
// to assert that a TTL was set or that a set was pruned against a fake.

func testStore(t *testing.T) *ValkeyStore {
	t.Helper()

	addr := os.Getenv("ELEMTA_TEST_VALKEY")
	if addr == "" {
		addr = "localhost:6379"
	}
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		t.Skipf("no Valkey at %s: %v", addr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		t.Skipf("Valkey at %s is not answering: %v", addr, err)
	}

	// A prefix of its own, so a test never reads or deletes the running
	// stack's metrics.
	store := &ValkeyStore{
		client: client,
		prefix: fmt.Sprintf("elemta:test:%d:%s:", time.Now().UnixNano(), t.Name()),
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		keys, err := client.Do(cleanupCtx, client.B().Keys().Pattern(store.prefix+"*").Build()).AsStrSlice()
		if err == nil && len(keys) > 0 {
			_ = client.Do(cleanupCtx, client.B().Del().Key(keys...).Build()).Error()
		}
		client.Close()
	})
	return store
}

func TestDomainOutcomesRoundTripThroughValkey(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := store.IncrDomainOutcome(ctx, "gmail.com", OutcomeDelivered); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.IncrDomainOutcome(ctx, "gmail.com", OutcomeDeferred); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrDomainOutcome(ctx, "other.example", OutcomeBounced); err != nil {
		t.Fatal(err)
	}

	stats, err := store.GetDomainStats(ctx)
	if err != nil {
		t.Fatal(err)
	}

	byDomain := map[string]DomainStats{}
	for _, s := range stats {
		byDomain[s.Domain] = s
	}
	if got := byDomain["gmail.com"]; got.Delivered != 3 || got.Deferred != 1 || got.Bounced != 0 {
		t.Errorf("gmail.com = %+v; want delivered 3, deferred 1, bounced 0", got)
	}
	if got := byDomain["other.example"]; got.Bounced != 1 {
		t.Errorf("other.example = %+v; want bounced 1", got)
	}
	// Busiest first.
	if len(stats) >= 2 && stats[0].Domain != "gmail.com" {
		t.Errorf("stats are not ordered by volume: %+v", stats)
	}
}

// TestCountersAreGivenALifetime is the regression this whole fix is about. The
// aggregate hourly counters expire after a day; these were shipped with no TTL
// at all, so on a relay sending to a long tail of destinations they grew for as
// long as the process ran.
func TestCountersAreGivenALifetime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if err := store.IncrDomainOutcome(ctx, "example.com", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}

	key := store.prefix + domainKeyPrefix + "example.com:" + OutcomeDelivered
	ttl, err := store.client.Do(ctx, store.client.B().Ttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	// -1 means the key exists with no expiry, which is exactly the bug.
	if ttl < 0 {
		t.Fatalf("counter has TTL %d; it will never expire", ttl)
	}
	if ttl > int64(domainRetention.Seconds()) {
		t.Errorf("TTL %ds exceeds the retention window of %ds", ttl, int64(domainRetention.Seconds()))
	}
}

// TestActivityRefreshesTheLifetime: a destination we still send to must not
// expire out from under the report.
func TestActivityRefreshesTheLifetime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	key := store.prefix + domainKeyPrefix + "busy.example:" + OutcomeDelivered

	if err := store.IncrDomainOutcome(ctx, "busy.example", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}
	// Shorten it, then write again and confirm the write pushed it back out.
	if err := store.client.Do(ctx, store.client.B().Expire().Key(key).Seconds(5).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrDomainOutcome(ctx, "busy.example", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}

	ttl, err := store.client.Do(ctx, store.client.B().Ttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 5 {
		t.Errorf("TTL is %ds after a fresh write; activity is not refreshing it", ttl)
	}
}

// TestExpiredDestinationsLeaveTheSet. The TTL handles the counters; nothing but
// the report handles the set that names them, and a set that only grows is the
// leak this change exists to remove.
func TestExpiredDestinationsLeaveTheSet(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if err := store.IncrDomainOutcome(ctx, "gone.example", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrDomainOutcome(ctx, "here.example", OutcomeDelivered); err != nil {
		t.Fatal(err)
	}

	// Expire one destination's counters the way the TTL eventually would.
	gone := store.prefix + domainKeyPrefix + "gone.example:" + OutcomeDelivered
	if err := store.client.Do(ctx, store.client.B().Del().Key(gone).Build()).Error(); err != nil {
		t.Fatal(err)
	}

	stats, err := store.GetDomainStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		if s.Domain == "gone.example" {
			t.Error("a destination with no counters was reported as a row of zeros")
		}
	}

	members, err := store.client.Do(ctx,
		store.client.B().Smembers().Key(store.prefix+"domains").Build()).AsStrSlice()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m == "gone.example" {
			t.Error("the expired destination is still in the set; it will accumulate forever")
		}
	}
}

// TestDestinationNamesAreNormalized, or one domain becomes several rows that
// each look fine on their own.
func TestDestinationNamesAreNormalized(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for _, name := range []string{"Example.COM", "example.com", "  example.com  ", "example.com."} {
		if err := store.IncrDomainOutcome(ctx, name, OutcomeDelivered); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.GetDomainStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 {
		t.Fatalf("one destination written four ways produced %d rows: %+v", len(stats), stats)
	}
	if stats[0].Domain != "example.com" || stats[0].Delivered != 4 {
		t.Errorf("stats = %+v; want example.com with 4 delivered", stats[0])
	}
}

// TestUnusableInputIsNotRecorded. A row attributed to an empty destination, or
// counted under an outcome nothing reads, is worse than no row: it is a key
// that accumulates and never appears.
func TestUnusableInputIsNotRecorded(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for _, bad := range []struct{ domain, outcome string }{
		{"", OutcomeDelivered},
		{"   ", OutcomeDelivered},
		{"example.com", "invented"},
		{"example.com", ""},
	} {
		if err := store.IncrDomainOutcome(ctx, bad.domain, bad.outcome); err != nil {
			t.Errorf("IncrDomainOutcome(%q, %q) errored: %v", bad.domain, bad.outcome, err)
		}
	}

	stats, err := store.GetDomainStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 0 {
		t.Errorf("unusable input produced rows: %+v", stats)
	}
}

// TestAnEmptyStoreReportsNothingRatherThanFailing: the reporting page must load
// on a server that has not sent anything yet.
func TestAnEmptyStoreReportsNothingRatherThanFailing(t *testing.T) {
	store := testStore(t)
	stats, err := store.GetDomainStats(context.Background())
	if err != nil {
		t.Fatalf("an empty store errored: %v", err)
	}
	if len(stats) != 0 {
		t.Errorf("an empty store reported %d destinations", len(stats))
	}
}
