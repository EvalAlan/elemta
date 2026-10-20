package metrics

import (
	"context"
	"testing"
	"time"
)

// The Reports chart's daily, weekly and monthly views read daily buckets;
// they used to regroup the 24 hourly ones, whose labels didn't even parse,
// so those views were always empty.
func TestCountersFeedHourlyAndDailyBuckets(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.IncrDelivered(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.IncrDeferred(ctx); err != nil {
		t.Fatal(err)
	}

	days, err := s.GetDailyStats(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	today := days[len(days)-1]
	if len(days) != 30 || today.Hour != time.Now().UTC().Format("2006-01-02") || today.Delivered != 3 || today.Deferred != 1 || today.Failed != 0 {
		t.Fatalf("daily = %d buckets, today %+v", len(days), today)
	}
	if days[0].Delivered != 0 {
		t.Errorf("a month ago = %+v", days[0])
	}

	hours, err := s.GetHourlyStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last := hours[len(hours)-1]
	start, err := time.Parse(time.RFC3339, last.Hour)
	if err != nil || !start.Equal(time.Now().UTC().Truncate(time.Hour)) || last.Delivered != 3 {
		t.Fatalf("this hour = %+v (%v)", last, err)
	}

	ttl, err := s.client.Do(ctx, s.client.B().Ttl().Key(s.prefix+"daily:"+today.Hour+":delivered").Build()).AsInt64()
	if err != nil || time.Duration(ttl)*time.Second < 365*24*time.Hour {
		t.Errorf("daily bucket TTL = %ds, want over a year (%v)", ttl, err)
	}
}
