package abuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

const (
	keyFailures = "elemta:abuse:fail:"
	keyStrikes  = "elemta:abuse:strikes:"
	keyBlocks   = "elemta:abuse:blocks"
	keyEvents   = "elemta:abuse:events"
	keyAccounts = "elemta:abuse:accounts:"
	maxEvents   = 200
	// strikeMemory is how long a block counts towards a longer next one.
	strikeMemory = 7 * 24 * time.Hour
	// escalation multiplies each repeat block: 15 minutes, 1 hour, 4 hours.
	escalation = 4
)

// Block is an address refused on every client protocol. Port 25 isn't one of
// them: a block for guessing passwords must not stop that network's mail
// arriving, and a sending server shares its address with nothing it can fix.
type Block struct {
	Network  string    `json:"network"`
	Reason   string    `json:"reason"`
	Service  string    `json:"service"`
	Failures int       `json:"failures"`
	Strikes  int       `json:"strikes"`
	Created  time.Time `json:"created"`
	Until    time.Time `json:"until"`
	Manual   bool      `json:"manual,omitempty"`
}

// Event is one line of the history the console shows.
type Event struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Network string    `json:"network"`
	Service string    `json:"service,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	By      string    `json:"by,omitempty"`
}

// AccountCount is an account being guessed at, from any number of addresses.
type AccountCount struct {
	Account  string `json:"account"`
	Failures int    `json:"failures"`
}

// local is what a service knows on its own: its fallback when Valkey is
// unreachable, and the copy of the blocks consulted on every connection.
type local struct {
	mu       sync.Mutex
	blocks   map[string]Block
	counts   map[string]*tally
	accounts map[string]*tally
	top      map[string]*tally
	events   []Event
	// pending waits for the next flush; series holds what couldn't be sent.
	pending map[string]int
	series  map[int64]map[string]int
}

type tally struct {
	count int
	reset time.Time
}

func (l *local) add(table map[string]*tally, key string, window time.Duration, now time.Time) int {
	t, ok := table[key]
	if !ok || now.After(t.reset) {
		t = &tally{reset: now.Add(window)}
		table[key] = t
	}
	t.count++
	if len(table) > 100000 {
		for k, v := range table {
			if now.After(v.reset) {
				delete(table, k)
			}
		}
	}
	return t.count
}

// Blocked reports whether an address is refused. It is called on every
// connection, so it reads only memory: sync keeps that current.
func (e *Engine) Blocked(addr string) (Block, bool) {
	if e == nil {
		return Block{}, false
	}
	network := Network(addr)
	if network == "" || e.Policy().Mode != ModeEnforce || e.Exempt(addr) {
		return Block{}, false
	}
	now := time.Now()
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	for _, key := range []string{network, Subnet(network)} {
		if b, ok := e.seen.blocks[key]; ok && now.Before(b.Until) {
			return b, true
		}
	}
	return Block{}, false
}

// Failure records a failed sign-in, and blocks the address once it has failed
// too often across all services. It never blocks by account: that would hand
// anyone a way to lock a user out. Accounts are only counted, for the console.
func (e *Engine) Failure(ctx context.Context, addr, service, account string) {
	if e == nil {
		return
	}
	p := e.Policy()
	network := Network(addr)
	if p.Mode == ModeOff || network == "" || e.Exempt(addr) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	window := time.Duration(p.WindowMinutes) * time.Minute
	failures := e.count(ctx, keyFailures+network, network, window)
	e.countAccount(ctx, account, window)
	e.noteOffender(ctx, network)
	e.note(fieldFailure+service, 1)
	metricFailures.WithLabelValues(e.service, service).Inc()
	if failures >= p.FailuresPerAddress {
		e.trip(ctx, p, network, service, failures)
	}
	// Many addresses in one network add up to the network, which is how a
	// rented block stays under the per-address limit.
	if p.FailuresPerNetwork > 0 {
		subnet := Subnet(network)
		if n := e.count(ctx, keyFailures+subnet, subnet, window); n >= p.FailuresPerNetwork {
			e.trip(ctx, p, subnet, service, n)
		}
	}
}

// count increments a shared counter, or this service's own if Valkey is away.
func (e *Engine) count(ctx context.Context, key, name string, window time.Duration) int {
	if client := e.valkey(); client != nil {
		n, err := client.Do(ctx, client.B().Incr().Key(key).Build()).AsInt64()
		if err == nil {
			if n == 1 {
				_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(window.Seconds())).Build()).Error()
			}
			return int(n)
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	return e.seen.add(e.seen.counts, name, window, time.Now())
}

func (e *Engine) countAccount(ctx context.Context, account string, window time.Duration) {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" || len(account) > 320 {
		return
	}
	if client := e.valkey(); client != nil {
		key := accountKey(time.Now(), window)
		err := client.Do(ctx, client.B().Zincrby().Key(key).Increment(1).Member(account).Build()).Error()
		if err == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64((2 * window).Seconds())).Build()).Error()
			return
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	e.seen.add(e.seen.accounts, account, window, time.Now())
}

func accountKey(now time.Time, window time.Duration) string {
	return keyAccounts + strconv.FormatInt(now.Unix()/int64(window.Seconds()), 10)
}

func (e *Engine) trip(ctx context.Context, p Policy, network, service string, failures int) {
	e.seen.mu.Lock()
	existing, blocked := e.seen.blocks[network]
	e.seen.mu.Unlock()
	if blocked && time.Now().Before(existing.Until) {
		return
	}
	strikes := e.strike(ctx, network)
	duration := blockDuration(p, strikes)
	if client := e.valkey(); client != nil {
		// Start the count again: a blocked address can't add to it, and in
		// log mode this keeps one address from logging every failure.
		_ = client.Do(ctx, client.B().Del().Key(keyFailures+network).Build()).Error()
	}
	e.seen.mu.Lock()
	delete(e.seen.counts, network)
	e.seen.mu.Unlock()
	if p.Mode != ModeEnforce {
		e.record(ctx, Event{Action: "would-block", Network: network, Service: service, Detail: fmt.Sprintf("%d failures; would block for %s", failures, duration)})
		return
	}
	now := time.Now().UTC()
	e.note(fieldBlocks, 1)
	metricBlocks.WithLabelValues(e.service).Inc()
	e.apply(ctx, Block{Network: network, Reason: "too many failed sign-ins", Service: service, Failures: failures, Strikes: strikes, Created: now, Until: now.Add(duration)})
	e.record(ctx, Event{Action: "blocked", Network: network, Service: service, Detail: fmt.Sprintf("%d failures; blocked for %s", failures, duration)})
	e.log.Warn("Address blocked", "address", network, "service", service, "failures", failures, "for", duration.String())
}

func (e *Engine) strike(ctx context.Context, network string) int {
	if client := e.valkey(); client != nil {
		key := keyStrikes + network
		n, err := client.Do(ctx, client.B().Incr().Key(key).Build()).AsInt64()
		if err == nil {
			_ = client.Do(ctx, client.B().Expire().Key(key).Seconds(int64(strikeMemory.Seconds())).Build()).Error()
			return int(n)
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	return e.seen.add(e.seen.counts, "strike:"+network, strikeMemory, time.Now())
}

// blockDuration grows with repeat offences, up to the policy's ceiling.
func blockDuration(p Policy, strikes int) time.Duration {
	d := time.Duration(p.BlockMinutes) * time.Minute
	ceiling := time.Duration(p.MaxBlockHours) * time.Hour
	for i := 1; i < strikes && d < ceiling; i++ {
		d *= escalation
	}
	if d > ceiling {
		return ceiling
	}
	return d
}

func (e *Engine) apply(ctx context.Context, b Block) {
	e.seen.mu.Lock()
	e.seen.blocks[b.Network] = b
	e.seen.mu.Unlock()
	if client := e.valkey(); client != nil {
		raw, err := json.Marshal(b)
		if err == nil {
			_ = client.Do(ctx, client.B().Hset().Key(keyBlocks).FieldValue().FieldValue(b.Network, string(raw)).Build()).Error()
		}
	}
}

func (e *Engine) record(ctx context.Context, ev Event) {
	ev.Time = time.Now().UTC()
	if client := e.valkey(); client != nil {
		raw, err := json.Marshal(ev)
		if err == nil && client.Do(ctx, client.B().Lpush().Key(keyEvents).Element(string(raw)).Build()).Error() == nil {
			_ = client.Do(ctx, client.B().Ltrim().Key(keyEvents).Start(0).Stop(maxEvents-1).Build()).Error()
			return
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	e.seen.events = append([]Event{ev}, e.seen.events...)
	if len(e.seen.events) > maxEvents {
		e.seen.events = e.seen.events[:maxEvents]
	}
}

// BlockAddress blocks an address or /64 by hand. It refuses an exempt address:
// the allowlist is what stands between an operator and locking themselves out.
func (e *Engine) BlockAddress(ctx context.Context, addr, reason, by string, duration time.Duration) (Block, error) {
	network := Target(addr)
	if network == "" {
		return Block{}, fmt.Errorf("%q is not an address or a network of /16 or smaller", addr)
	}
	if e.overlapsExempt(network) {
		return Block{}, fmt.Errorf("%s is on the allowlist", network)
	}
	if duration <= 0 {
		return Block{}, errors.New("a block needs a duration")
	}
	if reason == "" {
		reason = "blocked by an administrator"
	}
	now := time.Now().UTC()
	b := Block{Network: network, Reason: reason, Service: "admin", Created: now, Until: now.Add(duration), Manual: true}
	e.note(fieldBlocks, 1)
	metricBlocks.WithLabelValues(e.service).Inc()
	e.apply(ctx, b)
	e.record(ctx, Event{Action: "blocked", Network: network, Service: "admin", Detail: fmt.Sprintf("%s; for %s", reason, duration), By: by})
	return b, nil
}

// Unblock lifts a block and forgets the address's history, so its next
// mistake doesn't land it straight back in a long one.
func (e *Engine) Unblock(ctx context.Context, addr, by string) error {
	network := Target(addr)
	if network == "" {
		return fmt.Errorf("%q is not an address", addr)
	}
	e.seen.mu.Lock()
	delete(e.seen.blocks, network)
	delete(e.seen.counts, network)
	delete(e.seen.counts, "strike:"+network)
	e.seen.mu.Unlock()
	if client := e.valkey(); client != nil {
		_ = client.Do(ctx, client.B().Hdel().Key(keyBlocks).Field(network).Build()).Error()
		_ = client.Do(ctx, client.B().Del().Key(keyFailures+network, keyStrikes+network).Build()).Error()
	}
	e.record(ctx, Event{Action: "unblocked", Network: network, By: by})
	return nil
}

// Blocks lists current blocks, soonest to expire first.
func (e *Engine) Blocks() []Block {
	now := time.Now()
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	out := make([]Block, 0, len(e.seen.blocks))
	for _, b := range e.seen.blocks {
		if now.Before(b.Until) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// Events returns the recent history, newest first.
func (e *Engine) Events(ctx context.Context) []Event {
	if client := e.valkey(); client != nil {
		rows, err := client.Do(ctx, client.B().Lrange().Key(keyEvents).Start(0).Stop(maxEvents-1).Build()).AsStrSlice()
		if err == nil {
			out := make([]Event, 0, len(rows))
			for _, row := range rows {
				var ev Event
				if json.Unmarshal([]byte(row), &ev) == nil {
					out = append(out, ev)
				}
			}
			return out
		}
	}
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	return append([]Event{}, e.seen.events...)
}

// Accounts returns the accounts with the most failures in this window.
func (e *Engine) Accounts(ctx context.Context) []AccountCount {
	window := time.Duration(e.Policy().WindowMinutes) * time.Minute
	if client := e.valkey(); client != nil {
		rows, err := client.Do(ctx, client.B().Zrevrange().Key(accountKey(time.Now(), window)).Start(0).Stop(19).Withscores().Build()).AsZScores()
		if err == nil {
			out := make([]AccountCount, 0, len(rows))
			for _, row := range rows {
				out = append(out, AccountCount{Account: row.Member, Failures: int(row.Score)})
			}
			return out
		}
	}
	now := time.Now()
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	out := []AccountCount{}
	for account, t := range e.seen.accounts {
		if now.Before(t.reset) {
			out = append(out, AccountCount{Account: account, Failures: t.count})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Failures > out[j].Failures })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// syncBlocks replaces the local copy with the shared one, and clears out what
// has expired. A failed read keeps the copy: Valkey going away must not lift
// blocks, or put back ones already lifted.
func (e *Engine) syncBlocks(ctx context.Context, client valkey.Client) {
	rows, err := client.Do(ctx, client.B().Hgetall().Key(keyBlocks).Build()).AsStrMap()
	if err != nil {
		e.pruneLocal()
		return
	}
	now := time.Now()
	current := make(map[string]Block, len(rows))
	for network, raw := range rows {
		var b Block
		if json.Unmarshal([]byte(raw), &b) != nil || !now.Before(b.Until) {
			_ = client.Do(ctx, client.B().Hdel().Key(keyBlocks).Field(network).Build()).Error()
			continue
		}
		current[network] = b
	}
	e.seen.mu.Lock()
	e.seen.blocks = current
	e.seen.mu.Unlock()
	metricActive.WithLabelValues(e.service).Set(float64(len(current)))
}

func (e *Engine) pruneLocal() {
	now := time.Now()
	e.seen.mu.Lock()
	defer e.seen.mu.Unlock()
	for network, b := range e.seen.blocks {
		if !now.Before(b.Until) {
			delete(e.seen.blocks, network)
		}
	}
}

// overlapsExempt reports whether a block target touches the allowlist.
func (e *Engine) overlapsExempt(target string) bool {
	if !strings.Contains(target, "/") {
		return e.Exempt(target)
	}
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	if network.Contains(net.IPv4(127, 0, 0, 1)) || network.Contains(net.IPv6loopback) {
		return true
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, n := range e.exempt {
		if network.Contains(n.IP) || n.Contains(network.IP) {
			return true
		}
	}
	return false
}
