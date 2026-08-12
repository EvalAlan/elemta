package metrics

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// DomainStats is how one destination has been treating our mail.
//
// Aggregate delivery numbers say whether the queue is moving. They do not say
// that Gmail has been deferring everything for an hour while the rest of the
// world is fine, which is the question an operator actually has — and the one
// that decides whether to change something or wait.
type DomainStats struct {
	Domain    string `json:"domain"`
	Delivered int64  `json:"delivered"`
	Deferred  int64  `json:"deferred"`
	Bounced   int64  `json:"bounced"`
}

// Total is every outcome recorded for the destination.
func (d DomainStats) Total() int64 { return d.Delivered + d.Deferred + d.Bounced }

// The outcomes a destination can produce. Kept as constants because they are
// used to build Valkey keys, and a typo would silently create a new counter
// nobody reads rather than failing.
const (
	OutcomeDelivered = "delivered"
	OutcomeDeferred  = "deferred"
	OutcomeBounced   = "bounced"
)

// domainKeyPrefix namespaces per-destination counters.
const domainKeyPrefix = "domain:"

// domainRetention is how long a destination's counters survive without
// traffic.
//
// Every write refreshes it, so an active destination never expires and a
// destination we have stopped sending to disappears on its own. The aggregate
// hourly counters do the same thing with a 24-hour TTL; a report that describes
// recent behaviour has no business keeping a year of it.
const domainRetention = 30 * 24 * time.Hour

// maxReportedDomains caps what one report returns. This is a limit on the
// response, not on the store — the store is bounded by the TTL above.
const maxReportedDomains = 5000

// IncrDomainOutcome records one outcome against one destination.
//
// The destination is added to a set as well as counted, because Valkey has no
// cheap way to enumerate keys by pattern in production, and KEYS on a busy
// instance is exactly the kind of thing that turns a reporting page into an
// outage.
func (s *ValkeyStore) IncrDomainOutcome(ctx context.Context, domain, outcome string) error {
	domain = normalizeDomain(domain)
	if domain == "" || !validOutcome(outcome) {
		// Nothing usable to attribute this to. Recording it under an empty
		// domain would produce a row that means nothing and cannot be acted on.
		return nil
	}

	// Every key written here gets its lifetime refreshed. Without that the
	// counters and the destination set grow for as long as the server runs,
	// which on a relay that sends to a long tail of domains is an unbounded
	// leak in a store nobody prunes.
	counter := s.prefix + domainKeyPrefix + domain + ":" + outcome
	cmds := []valkey.Completed{
		s.client.B().Incr().Key(counter).Build(),
		s.client.B().Expire().Key(counter).Seconds(int64(domainRetention.Seconds())).Build(),
		s.client.B().Sadd().Key(s.prefix + "domains").Member(domain).Build(),
	}
	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetDomainStats reports every destination with recorded outcomes, busiest
// first.
func (s *ValkeyStore) GetDomainStats(ctx context.Context) ([]DomainStats, error) {
	members, err := s.client.Do(ctx, s.client.B().Smembers().Key(s.prefix+"domains").Build()).AsStrSlice()
	if err != nil {
		return nil, err
	}
	out := make([]DomainStats, 0, len(members))
	var expired []string
	for _, domain := range members {
		stats := DomainStats{Domain: domain}
		stats.Delivered = s.domainCounter(ctx, domain, OutcomeDelivered)
		stats.Deferred = s.domainCounter(ctx, domain, OutcomeDeferred)
		stats.Bounced = s.domainCounter(ctx, domain, OutcomeBounced)
		if stats.Total() == 0 {
			// The counters have aged out. Drop the destination from the set as
			// well, or the set is the one thing here that still grows forever.
			// Reporting it as a row of zeros would also read as "healthy"
			// rather than "no longer tracked".
			expired = append(expired, domain)
			continue
		}
		out = append(out, stats)
	}
	s.forgetDomains(ctx, expired)

	// Busiest first: a destination we barely use is rarely the one causing the
	// problem being investigated.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total() != out[j].Total() {
			return out[i].Total() > out[j].Total()
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > maxReportedDomains {
		out = out[:maxReportedDomains]
	}
	return out, nil
}

// forgetDomains removes destinations whose counters have expired.
//
// The TTL takes care of the counters; nothing but this takes care of the set
// that names them, and a set that only grows is the leak this whole change
// exists to avoid.
func (s *ValkeyStore) forgetDomains(ctx context.Context, domains []string) {
	if len(domains) == 0 {
		return
	}
	cmd := s.client.B().Srem().Key(s.prefix + "domains").Member(domains...).Build()
	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		// Losing this pass is harmless: the next report tries again.
		return
	}
}

// domainCounter reads one counter, treating anything unreadable as zero. A
// reporting page must not fail because one key is missing.
func (s *ValkeyStore) domainCounter(ctx context.Context, domain, outcome string) int64 {
	key := s.prefix + domainKeyPrefix + domain + ":" + outcome
	value, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
}

func validOutcome(outcome string) bool {
	switch outcome {
	case OutcomeDelivered, OutcomeDeferred, OutcomeBounced:
		return true
	}
	return false
}
