package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

// Queue listings used to return every message in the queue as a bare JSON
// array, with each message carrying its full attempt history, annotations and
// server file path. At 40k queued messages that was a 21 MB response,
// re-fetched by every open dashboard on each auto-refresh tick — and the file
// path had no business leaving the server.
//
// Listings now return a paged envelope of summaries. Filtering, sorting and
// slicing happen here; the storage backends still list whole queues, so the
// server-side cost is unchanged until pagination is pushed into the backends.

const (
	// defaultQueueListLimit is applied when the client does not ask for a
	// specific page size.
	defaultQueueListLimit = 100
	// maxQueueListLimit caps a single page. A client wanting everything pages
	// through; nothing gets the whole queue in one response.
	maxQueueListLimit = 500
)

// MessageSummary is the list view of a queued message: enough to render a
// queue table and decide which message to inspect, without the attempt
// history, annotations, or the server-local file path.
type MessageSummary struct {
	ID         string          `json:"id"`
	QueueType  queue.QueueType `json:"queue_type"`
	From       string          `json:"from"`
	To         []string        `json:"to"`
	Domain     string          `json:"domain,omitempty"`
	Subject    string          `json:"subject"`
	Size       int64           `json:"size"`
	Priority   queue.Priority  `json:"priority"`
	ReceivedAt time.Time       `json:"received_at"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	NextRetry  *time.Time      `json:"next_retry,omitempty"`
	RetryCount int             `json:"retry_count"`
	LastError  string          `json:"last_error,omitempty"`
	HoldReason string          `json:"hold_reason,omitempty"`
}

// QueueListResponse is the paged envelope for queue listings. Total counts
// everything that matched the filters, not just this page, so a client can
// build a pager without a second request.
type QueueListResponse struct {
	Messages []MessageSummary `json:"messages"`
	Total    int              `json:"total"`
	Offset   int              `json:"offset"`
	Limit    int              `json:"limit"`
}

// queueListQuery is the parsed filter/page state of a listing request.
type queueListQuery struct {
	limit    int
	offset   int
	search   string
	priority *queue.Priority
	since    time.Time
}

// parseQueueListQuery reads paging and filter parameters. Unusable values fall
// back to defaults rather than erroring: a listing endpoint that refuses to
// list because a filter was malformed helps nobody during an incident.
func parseQueueListQuery(r *http.Request) queueListQuery {
	q := queueListQuery{limit: defaultQueueListLimit}
	params := r.URL.Query()

	if v, err := strconv.Atoi(params.Get("limit")); err == nil && v > 0 {
		q.limit = v
		if q.limit > maxQueueListLimit {
			q.limit = maxQueueListLimit
		}
	}
	if v, err := strconv.Atoi(params.Get("offset")); err == nil && v > 0 {
		q.offset = v
	}
	q.search = strings.ToLower(strings.TrimSpace(params.Get("search")))
	if v, err := strconv.Atoi(params.Get("priority")); err == nil {
		p := queue.Priority(v)
		q.priority = &p
	}
	if v, err := time.Parse(time.RFC3339, params.Get("since")); err == nil {
		q.since = v
	}
	return q
}

// matches reports whether a message survives the query's filters.
func (q queueListQuery) matches(msg *queue.Message) bool {
	if q.priority != nil && msg.Priority != *q.priority {
		return false
	}
	if !q.since.IsZero() && msg.CreatedAt.Before(q.since) {
		return false
	}
	if q.search != "" {
		if !strings.Contains(strings.ToLower(msg.ID), q.search) &&
			!strings.Contains(strings.ToLower(msg.From), q.search) &&
			!strings.Contains(strings.ToLower(msg.Subject), q.search) &&
			!anyContains(msg.To, q.search) {
			return false
		}
	}
	return true
}

func anyContains(values []string, needle string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

// listQueuePage filters, orders and slices messages into a response envelope.
//
// Ordering is newest-first by CreatedAt with ID as the tiebreak. The backends
// return messages in whatever order their storage happens to produce, and an
// unstable order makes pages overlap or skip as the client walks them.
func listQueuePage(messages []queue.Message, q queueListQuery) QueueListResponse {
	filtered := messages[:0:0]
	for i := range messages {
		if q.matches(&messages[i]) {
			filtered = append(filtered, messages[i])
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if !filtered[i].CreatedAt.Equal(filtered[j].CreatedAt) {
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		}
		return filtered[i].ID > filtered[j].ID
	})

	total := len(filtered)
	start := q.offset
	if start > total {
		start = total
	}
	end := start + q.limit
	if end > total {
		end = total
	}

	page := make([]MessageSummary, 0, end-start)
	for i := start; i < end; i++ {
		page = append(page, summarize(&filtered[i]))
	}

	return QueueListResponse{
		Messages: page,
		Total:    total,
		Offset:   q.offset,
		Limit:    q.limit,
	}
}

func summarize(msg *queue.Message) MessageSummary {
	s := MessageSummary{
		ID:         msg.ID,
		QueueType:  msg.QueueType,
		From:       msg.From,
		To:         msg.To,
		Domain:     msg.Domain,
		Subject:    msg.Subject,
		Size:       msg.Size,
		Priority:   msg.Priority,
		ReceivedAt: msg.ReceivedAt,
		CreatedAt:  msg.CreatedAt,
		UpdatedAt:  msg.UpdatedAt,
		RetryCount: msg.RetryCount,
		LastError:  msg.LastError,
		HoldReason: msg.HoldReason,
	}
	if !msg.NextRetry.IsZero() {
		t := msg.NextRetry
		s.NextRetry = &t
	}
	return s
}
