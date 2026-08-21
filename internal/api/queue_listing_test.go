package api

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/queue"
)

// The listing endpoint used to return the whole queue as a bare array — 21 MB
// at 40k messages — with each entry carrying its attempt history and the
// server-local file path. These tests pin the envelope contract that replaced
// it: bounded pages, filter-aware totals, stable ordering, and summaries that
// do not leak server paths.

func listingMessages(n int) []queue.Message {
	base := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	msgs := make([]queue.Message, 0, n)
	for i := 0; i < n; i++ {
		msgs = append(msgs, queue.Message{
			ID:        time.Duration(i).String() + "-id",
			QueueType: queue.Active,
			FilePath:  "/app/queue/active/secret-path",
			From:      "sender@example.com",
			To:        []string{"rcpt@example.net"},
			Subject:   "message",
			Priority:  queue.PriorityNormal,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			Attempts:  []queue.Attempt{{Result: "deferred"}},
		})
	}
	return msgs
}

func queryFor(t *testing.T, rawQuery string) queueListQuery {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/queue/active?"+rawQuery, nil)
	return parseQueueListQuery(r)
}

func TestListingIsBoundedByDefault(t *testing.T) {
	resp := listQueuePage(listingMessages(1000), queryFor(t, ""))

	if len(resp.Messages) != defaultQueueListLimit {
		t.Errorf("default page = %d messages, want %d", len(resp.Messages), defaultQueueListLimit)
	}
	if resp.Total != 1000 {
		t.Errorf("total = %d, want 1000", resp.Total)
	}
}

func TestListingCapsRequestedLimit(t *testing.T) {
	resp := listQueuePage(listingMessages(1000), queryFor(t, "limit=999999"))
	if len(resp.Messages) != maxQueueListLimit {
		t.Errorf("page = %d, want cap %d — an unbounded request must not return the whole queue", len(resp.Messages), maxQueueListLimit)
	}
}

func TestListingOrdersNewestFirstAndPagesWithoutOverlap(t *testing.T) {
	msgs := listingMessages(250)

	seen := map[string]bool{}
	var prev time.Time
	first := true
	for offset := 0; offset < 250; offset += 100 {
		resp := listQueuePage(msgs, queryFor(t, "limit=100&offset="+strconv.Itoa(offset)))
		for _, m := range resp.Messages {
			if seen[m.ID] {
				t.Fatalf("message %s appeared on two pages", m.ID)
			}
			seen[m.ID] = true
			if !first && m.CreatedAt.After(prev) {
				t.Fatal("ordering is not newest-first across pages")
			}
			prev, first = m.CreatedAt, false
		}
	}
	if len(seen) != 250 {
		t.Errorf("paging visited %d of 250 messages", len(seen))
	}
}

func TestListingSearchFiltersAndCountsMatchesOnly(t *testing.T) {
	msgs := listingMessages(50)
	msgs[7].Subject = "the needle in the haystack"
	msgs[31].From = "needle@example.org"

	resp := listQueuePage(msgs, queryFor(t, "search=NEEDLE"))
	if resp.Total != 2 {
		t.Errorf("total = %d, want 2 (search must be case-insensitive and total filter-aware)", resp.Total)
	}
	if len(resp.Messages) != 2 {
		t.Errorf("page = %d messages, want 2", len(resp.Messages))
	}
}

func TestListingPriorityAndSinceFilters(t *testing.T) {
	msgs := listingMessages(20)
	msgs[3].Priority = queue.PriorityCritical
	msgs[4].Priority = queue.PriorityCritical

	resp := listQueuePage(msgs, queryFor(t, "priority=4"))
	if resp.Total != 2 {
		t.Errorf("priority filter: total = %d, want 2", resp.Total)
	}

	cutoff := time.Date(2026, 8, 9, 0, 0, 10, 0, time.UTC)
	resp = listQueuePage(msgs, queryFor(t, "since="+cutoff.Format(time.RFC3339)))
	if resp.Total != 10 {
		t.Errorf("since filter: total = %d, want 10", resp.Total)
	}
}

// TestSummaryOmitsServerInternals pins that neither the queue file path nor the
// attempt history reaches the wire. The path is a server implementation detail
// and the attempts were most of the 21 MB.
func TestSummaryOmitsServerInternals(t *testing.T) {
	resp := listQueuePage(listingMessages(1), queryFor(t, ""))

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"file_path", "secret-path", "attempts", "annotations"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("listing response contains %q, which must not leave the server", forbidden)
		}
	}
}

func TestListingOffsetPastEndIsEmptyNotError(t *testing.T) {
	resp := listQueuePage(listingMessages(5), queryFor(t, "offset=50"))
	if len(resp.Messages) != 0 || resp.Total != 5 {
		t.Errorf("offset past end: got %d messages total %d, want 0 and 5", len(resp.Messages), resp.Total)
	}
}
