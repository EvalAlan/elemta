package abuse

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// What the console graphs. Connections are refused on the hot path, so a
// service only counts in memory there and flushes on its background sync: a
// flood of refusals must not become a flood of Valkey writes. Buckets are kept
// at two sizes, so a week doesn't mean reading two thousand keys.
const (
	keyStats5m = "elemta:abuse:stats:5m:"
	keyStats1h = "elemta:abuse:stats:1h:"
	keyTop     = "elemta:abuse:top:"

	bucket5m  = int64(300)
	bucket1h  = int64(3600)
	retain5m  = 26 * time.Hour
	retain1h  = 8 * 24 * time.Hour
	topHolder = 2 * time.Hour

	fieldFailure = "fail:"
	fieldRefused = "refused:"
	fieldBlocks  = "blocks"
)

// Reasons a connection or sign-in was turned away.
const (
	RefusedBlocked = "blocked"
	RefusedLimit   = "limit"
	RefusedRate    = "rate"
)

var (
	metricFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elemta_abuse_failed_logins_total", Help: "Failed sign-ins reported to abuse protection.",
	}, []string{"service", "source"})
	metricRefused = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elemta_abuse_refused_total", Help: "Connections and sign-ins refused by abuse protection.",
	}, []string{"service", "reason"})
	metricBlocks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "elemta_abuse_blocks_total", Help: "Addresses and networks blocked.",
	}, []string{"service"})
	metricActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "elemta_abuse_blocks_active", Help: "Blocks in force, as this service sees them.",
	}, []string{"service"})
)

// Bucket is one step of a graph.
type Bucket struct {
	Time     time.Time      `json:"time"`
	Failures map[string]int `json:"failures"`
	Refused  map[string]int `json:"refused"`
	Blocks   int            `json:"blocks"`
}

// Offender is an address with the most failures lately.
type Offender struct {
	Network  string `json:"network"`
	Failures int    `json:"failures"`
}

// Stats is what the console shows for a range.
type Stats struct {
	Range    string         `json:"range"`
	Step     int64          `json:"step_seconds"`
	Buckets  []Bucket       `json:"buckets"`
	Failures int            `json:"failures"`
	Refused  int            `json:"refused"`
	Blocks   int            `json:"blocks"`
	Services map[string]int `json:"services"`
	Top      []Offender     `json:"top"`
}

// note adds to a counter that the next sync flushes.
func (e *Engine) note(field string, n int) {
	e.seen.mu.Lock()
	e.seen.pending[field] += n
	e.seen.mu.Unlock()
}

// Refuse reports whether a blocked address should be turned away, and counts
// it. Gates use this; Blocked only asks.
func (e *Engine) Refuse(addr string) bool {
	if e == nil {
		return false
	}
	if _, blocked := e.Blocked(addr); !blocked {
		return false
	}
	e.Refused(RefusedBlocked)
	return true
}

// Refused counts something turned away for reason.
func (e *Engine) Refused(reason string) {
	if e == nil {
		return
	}
	metricRefused.WithLabelValues(e.service, reason).Inc()
	e.note(fieldRefused+reason, 1)
}

func (e *Engine) flushStats(ctx context.Context) {
	e.seen.mu.Lock()
	pending := e.seen.pending
	e.seen.pending = map[string]int{}
	e.seen.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	now := time.Now()
	client := e.valkey()
	if client == nil {
		e.keepLocal(now, pending)
		return
	}
	five := keyStats5m + strconv.FormatInt(now.Unix()/bucket5m, 10)
	hour := keyStats1h + strconv.FormatInt(now.Unix()/bucket1h, 10)
	for field, n := range pending {
		for _, key := range []string{five, hour} {
			if err := client.Do(ctx, client.B().Hincrby().Key(key).Field(field).Increment(int64(n)).Build()).Error(); err != nil {
				e.keepLocal(now, map[string]int{field: n})
				break
			}
		}
	}
	_ = client.Do(ctx, client.B().Expire().Key(five).Seconds(int64(retain5m.Seconds())).Build()).Error()
	_ = client.Do(ctx, client.B().Expire().Key(hour).Seconds(int64(retain1h.Seconds())).Build()).Error()
}

// keepLocal holds counts when Valkey is away, so a lone service still has
// numbers to show. They are this service's alone, which the page says.
func (e *Engine) keepLocal(now time.Time, counts map[string]int) {
	id := now.Unix() / bucket5m
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	if e.seen.series[id] == nil {
		e.seen.series[id] = map[string]int{}
	}
	for field, n := range counts {
		e.seen.series[id][field] += n
	}
	for old := range e.seen.series {
		if old < id-int64(retain5m/time.Second)/bucket5m {
			delete(e.seen.series, old)
		}
	}
}

// Ranges the console offers: how far back, the step shown, and the stored
// bucket read.
func rangeSpec(name string) (string, int64, int64, int, string) {
	switch name {
	case "1h":
		return "1h", bucket5m, bucket5m, 12, keyStats5m
	case "7d":
		return "7d", 6 * bucket1h, bucket1h, 28, keyStats1h
	default:
		return "24h", bucket1h, bucket1h, 24, keyStats1h
	}
}

// Stats returns graphs for "1h", "24h" or "7d".
func (e *Engine) Stats(ctx context.Context, name string) Stats {
	label, step, stored, steps, prefix := rangeSpec(name)
	now := time.Now().Unix()
	last := now / step
	out := Stats{Range: label, Step: step, Services: map[string]int{}, Top: e.topOffenders(ctx)}
	byStep := make(map[int64]*Bucket, steps)
	for i := steps - 1; i >= 0; i-- {
		id := last - int64(i)
		b := &Bucket{Time: time.Unix(id*step, 0).UTC(), Failures: map[string]int{}, Refused: map[string]int{}}
		byStep[id] = b
		out.Buckets = append(out.Buckets, Bucket{})
		out.Buckets[len(out.Buckets)-1] = *b
	}
	add := func(storedID int64, fields map[string]int) {
		b := byStep[storedID*stored/step]
		if b == nil {
			return
		}
		for field, n := range fields {
			switch {
			case strings.HasPrefix(field, fieldFailure):
				service := strings.TrimPrefix(field, fieldFailure)
				b.Failures[service] += n
				out.Services[service] += n
				out.Failures += n
			case strings.HasPrefix(field, fieldRefused):
				b.Refused[strings.TrimPrefix(field, fieldRefused)] += n
				out.Refused += n
			case field == fieldBlocks:
				b.Blocks += n
				out.Blocks += n
			}
		}
	}
	first := (last - int64(steps-1)) * step / stored
	final := (last+1)*step/stored - 1
	if client := e.valkey(); client != nil {
		for id := first; id <= final; id++ {
			fields, err := client.Do(ctx, client.B().Hgetall().Key(prefix+strconv.FormatInt(id, 10)).Build()).AsIntMap()
			if err != nil {
				continue
			}
			counts := make(map[string]int, len(fields))
			for field, n := range fields {
				counts[field] = int(n)
			}
			add(id, counts)
		}
	}
	e.seen.mu.Lock()
	local := make(map[int64]map[string]int, len(e.seen.series))
	for id, fields := range e.seen.series {
		copied := make(map[string]int, len(fields))
		for field, n := range fields {
			copied[field] = n
		}
		local[id] = copied
	}
	e.seen.mu.Unlock()
	for id, fields := range local {
		add(id*bucket5m/stored, fields)
	}
	for i := range out.Buckets {
		id := out.Buckets[i].Time.Unix() / step
		out.Buckets[i] = *byStep[id]
	}
	return out
}

func (e *Engine) noteOffender(ctx context.Context, network string) {
	id := time.Now().Unix() / bucket1h
	if client := e.valkey(); client != nil {
		key := keyTop + strconv.FormatInt(id, 10)
		if client.Do(ctx, client.B().Zincrby().Key(key).Increment(1).Member(network).Build()).Error() == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(topHolder.Seconds())).Build()).Error()
			return
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	e.seen.add(e.seen.top, network, time.Hour, time.Now())
}

// topOffenders covers this hour and the last, so the list doesn't empty on the
// hour.
func (e *Engine) topOffenders(ctx context.Context) []Offender {
	totals := map[string]int{}
	id := time.Now().Unix() / bucket1h
	if client := e.valkey(); client != nil {
		for _, hour := range []int64{id, id - 1} {
			key := keyTop + strconv.FormatInt(hour, 10)
			rows, err := client.Do(ctx, client.B().Zrevrange().Key(key).Start(0).Stop(49).Withscores().Build()).AsZScores()
			if err != nil {
				continue
			}
			for _, row := range rows {
				totals[row.Member] += int(row.Score)
			}
		}
	}
	now := time.Now()
	e.seen.mu.Lock()
	for network, t := range e.seen.top {
		if now.Before(t.reset) {
			totals[network] += t.count
		}
	}
	e.seen.mu.Unlock()
	out := make([]Offender, 0, len(totals))
	for network, n := range totals {
		out = append(out, Offender{Network: network, Failures: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failures != out[j].Failures {
			return out[i].Failures > out[j].Failures
		}
		return out[i].Network < out[j].Network
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
