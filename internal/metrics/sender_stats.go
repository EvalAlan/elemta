package metrics

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/valkey-io/valkey-go"
)

// Sender reputation telemetry.
//
// Per-destination stats answer "how is Gmail treating our mail". Once mail
// leaves from several pools and addresses, the question that decides what to
// do is "how is Gmail treating *this* pool": one stream drawing complaints
// should be visible as that stream, not averaged into everyone else's. So
// outcomes are also counted per sending pool, per source address, and per
// mailbox provider.
//
// The counts are kept in daily (UTC) buckets rather than as running totals,
// because the thresholds that matter are rates over a recent window: Google
// and Yahoo's bulk-sender rules are written against a daily spam-complaint
// rate, and a total since the counters were created would let a bad day hide
// behind a good month.

// The outcomes counted per sender, in addition to the per-destination ones.
const (
	// OutcomeThrottled is a deferral the provider explained as rate or
	// reputation limiting. It is counted alongside the deferral, not instead.
	OutcomeThrottled = "throttled"
	// OutcomeComplained is a spam complaint received through a feedback loop.
	OutcomeComplained = "complained"
)

// SenderStats is one pool, address or provider over a window of days.
type SenderStats struct {
	Dimension  string `json:"dimension"`
	Key        string `json:"key"`
	Delivered  int64  `json:"delivered"`
	Deferred   int64  `json:"deferred"`
	Bounced    int64  `json:"bounced"`
	Throttled  int64  `json:"throttled"`
	Complained int64  `json:"complained"`
}

// Attempts is every outcome a receiver gave, which is what rates are of.
// Complaints and throttles are not added: a complaint is about a message
// already counted as delivered, and a throttle is a kind of deferral.
func (s SenderStats) Attempts() int64 { return s.Delivered + s.Deferred + s.Bounced }

// senderOutcomes are the counters kept per sender, in report order.
var senderOutcomes = []string{OutcomeDelivered, OutcomeDeferred, OutcomeBounced, OutcomeThrottled, OutcomeComplained}

// SenderDimensions are the axes sender telemetry is kept along.
var SenderDimensions = []string{"pool", "ip", "provider"}

// SenderRetentionDays is the longest window a report can cover. Buckets
// live a day longer, so a window that starts at midnight is never short.
const SenderRetentionDays = 7

const senderKeyPrefix = "sender:"

// senderNow is swappable so day boundaries can be tested.
var senderNow = time.Now

// maxSenderKeyLength bounds a key. Pool names, addresses and provider names
// are short; anything longer did not come from them.
const maxSenderKeyLength = 128

// IncrSenderOutcome counts one outcome for one pool, address or provider.
func (s *ValkeyStore) IncrSenderOutcome(ctx context.Context, dimension, key, outcome string) error {
	key, ok := normalizeSenderKey(key)
	if !ok || !validSenderDimension(dimension) || !validSenderOutcome(outcome) {
		// Nothing usable to attribute this to. A complaint report's Source-IP
		// is written by whoever sent the report, so junk is expected here and
		// must not become a key.
		return nil
	}
	counter := s.senderCounterKey(dimension, key, senderDay(senderNow(), 0), outcome)
	ttl := int64((SenderRetentionDays + 1) * 24 * 60 * 60)
	cmds := []valkey.Completed{
		s.client.B().Incr().Key(counter).Build(),
		s.client.B().Expire().Key(counter).Seconds(ttl).Build(),
		s.client.B().Sadd().Key(s.senderSetKey(dimension)).Member(key).Build(),
	}
	for _, cmd := range cmds {
		if err := s.client.Do(ctx, cmd).Error(); err != nil {
			return err
		}
	}
	return nil
}

// GetSenderStats reports every pool, address and provider with outcomes in
// the last days days (today counts as one), busiest first within each
// dimension.
func (s *ValkeyStore) GetSenderStats(ctx context.Context, days int) ([]SenderStats, error) {
	if days < 1 {
		days = 1
	}
	if days > SenderRetentionDays {
		days = SenderRetentionDays
	}
	now := senderNow()
	var out []SenderStats
	for _, dimension := range SenderDimensions {
		members, err := s.client.Do(ctx, s.client.B().Smembers().Key(s.senderSetKey(dimension)).Build()).AsStrSlice()
		if err != nil {
			return nil, err
		}
		var rows []SenderStats
		var expired []string
		for _, key := range members {
			// Read the whole retention window so a member with nothing left
			// in it can be dropped from the set, then sum the part asked for.
			var keys []string
			for d := 0; d <= SenderRetentionDays; d++ {
				day := senderDay(now, d)
				for _, outcome := range senderOutcomes {
					keys = append(keys, s.senderCounterKey(dimension, key, day, outcome))
				}
			}
			values, err := s.client.Do(ctx, s.client.B().Mget().Key(keys...).Build()).ToArray()
			if err != nil {
				return nil, err
			}
			row := SenderStats{Dimension: dimension, Key: key}
			var anyLeft bool
			for i, v := range values {
				n := parseCount(v)
				if n == 0 {
					continue
				}
				anyLeft = true
				if i/len(senderOutcomes) >= days {
					continue
				}
				switch senderOutcomes[i%len(senderOutcomes)] {
				case OutcomeDelivered:
					row.Delivered += n
				case OutcomeDeferred:
					row.Deferred += n
				case OutcomeBounced:
					row.Bounced += n
				case OutcomeThrottled:
					row.Throttled += n
				case OutcomeComplained:
					row.Complained += n
				}
			}
			if !anyLeft {
				expired = append(expired, key)
				continue
			}
			if row.Attempts()+row.Complained > 0 {
				rows = append(rows, row)
			}
		}
		if len(expired) > 0 {
			// As for destinations: the TTL clears the counters, and only this
			// clears the set that names them.
			_ = s.client.Do(ctx, s.client.B().Srem().Key(s.senderSetKey(dimension)).Member(expired...).Build()).Error()
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Attempts() != rows[j].Attempts() {
				return rows[i].Attempts() > rows[j].Attempts()
			}
			return rows[i].Key < rows[j].Key
		})
		out = append(out, rows...)
	}
	return out, nil
}

func (s *ValkeyStore) senderSetKey(dimension string) string {
	return s.prefix + "senders:" + dimension
}

func (s *ValkeyStore) senderCounterKey(dimension, key, day, outcome string) string {
	return s.prefix + senderKeyPrefix + dimension + ":" + key + ":" + day + ":" + outcome
}

// senderDay is the UTC day daysAgo days before now, as a bucket name.
func senderDay(now time.Time, daysAgo int) string {
	return now.UTC().AddDate(0, 0, -daysAgo).Format("20060102")
}

func parseCount(v valkey.ValkeyMessage) int64 {
	str, err := v.ToString()
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func normalizeSenderKey(key string) (string, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" || len(key) > maxSenderKeyLength {
		return "", false
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return "", false
		}
	}
	return key, true
}

func validSenderDimension(dimension string) bool {
	for _, d := range SenderDimensions {
		if d == dimension {
			return true
		}
	}
	return false
}

func validSenderOutcome(outcome string) bool {
	for _, o := range senderOutcomes {
		if o == outcome {
			return true
		}
	}
	return false
}
