package abuse

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

const (
	keyPolicy = "elemta:abuse:policy"
	// syncInterval is how quickly a change in the console reaches a service.
	syncInterval = 5 * time.Second
	// valkeyTimeout bounds what a service waits for Valkey. It runs beside
	// sign-ins, which must not stall because the abuse store did.
	valkeyTimeout = 500 * time.Millisecond
)

// Engine is one service's view.
type Engine struct {
	service string
	addr    string
	log     *slog.Logger

	mu        sync.RWMutex
	client    valkey.Client
	policy    Policy
	exempt    []*net.IPNet
	published bool
	source    *Policy // set on the service that owns the policy
	onPolicy  []func(Policy)
	conns     map[string]int
	seen      local
}

// New returns an engine for service. An empty addr means there is no Valkey:
// the service then works alone, with the default policy.
func New(service, addr string, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{service: service, addr: addr, log: log.With("component", "abuse"), conns: map[string]int{},
		seen: local{blocks: map[string]Block{}, counts: map[string]*tally{}, accounts: map[string]*tally{}}}
	e.setPolicy(DefaultPolicy())
	return e
}

// Own makes this service the one that publishes p, whenever Valkey lacks it.
// Only the admin console does: the configuration file is its to edit.
func (e *Engine) Own(p Policy) {
	p = p.WithDefaults()
	e.mu.Lock()
	e.source = &p
	e.mu.Unlock()
	e.setPolicy(p)
}

// OnPolicy registers fn to run whenever a published policy is received, and
// runs it now if one has been.
func (e *Engine) OnPolicy(fn func(Policy)) {
	e.mu.Lock()
	e.onPolicy = append(e.onPolicy, fn)
	published, p := e.published, e.policy
	e.mu.Unlock()
	if published {
		fn(p)
	}
}

// Policy returns the policy in force.
func (e *Engine) Policy() Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// Shared reports whether this service can reach Valkey.
func (e *Engine) Shared(ctx context.Context) bool {
	client := e.valkey()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	return client.Do(ctx, client.B().Ping().Build()).Error() == nil
}

func (e *Engine) setPolicy(p Policy) {
	exempt, err := parseNetworks(p.Allowlist)
	if err != nil {
		e.log.Error("Ignoring an invalid abuse policy", "error", err)
		return
	}
	e.mu.Lock()
	e.policy, e.exempt = p, exempt
	e.mu.Unlock()
}

// Exempt reports whether an address is never limited: loopback, and anything
// on the allowlist. Private networks aren't assumed safe: on a shared network,
// or behind a NAT, they are ordinary clients.
func (e *Engine) Exempt(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, n := range e.exempt {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Run keeps the engine current until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	e.sync(ctx)
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			client := e.client
			e.client = nil
			e.mu.Unlock()
			if client != nil {
				client.Close()
			}
			return
		case <-ticker.C:
			e.sync(ctx)
		}
	}
}

// valkey returns the client if there is one. It never connects: this runs
// beside sign-ins, and an unreachable Valkey can take seconds to fail.
func (e *Engine) valkey() valkey.Client {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.client
}

// connect makes the client, from the background sync or an administrator's
// save. Failing here is normal and quiet: Valkey may simply not be up yet, and
// the next sync tries again.
func (e *Engine) connect() valkey.Client {
	if client := e.valkey(); client != nil || e.addr == "" {
		return client
	}
	created, err := valkeyaddr.NewClient(e.addr, nil)
	if err != nil {
		e.log.Debug("Valkey unavailable; working alone", "error", err)
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != nil {
		created.Close()
		return e.client
	}
	e.client = created
	return created
}

func (e *Engine) sync(ctx context.Context) {
	client := e.connect()
	if client == nil {
		e.pruneLocal()
		return
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	e.syncPolicy(ctx, client)
	e.syncBlocks(ctx, client)
}

func (e *Engine) syncPolicy(ctx context.Context, client valkey.Client) {
	raw, err := client.Do(ctx, client.B().Get().Key(keyPolicy).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		e.mu.RLock()
		source := e.source
		e.mu.RUnlock()
		if source != nil {
			_ = e.Publish(ctx, *source)
		}
		return
	}
	if err != nil {
		return
	}
	var p Policy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		e.log.Error("Ignoring an unreadable abuse policy", "error", err)
		return
	}
	p = p.WithDefaults()
	if err := p.Validate(); err != nil {
		e.log.Error("Ignoring an invalid abuse policy", "error", err)
		return
	}
	e.receive(p)
}

func (e *Engine) receive(p Policy) {
	e.mu.RLock()
	same := e.published && samePolicy(e.policy, p)
	e.mu.RUnlock()
	if same {
		return
	}
	e.setPolicy(p)
	e.mu.Lock()
	e.published = true
	callbacks := append([]func(Policy){}, e.onPolicy...)
	e.mu.Unlock()
	e.log.Info("Abuse policy in force", "service", e.service, "mode", p.Mode, "connections_per_address", p.ConnectionsPerAddress)
	for _, fn := range callbacks {
		fn(p)
	}
}

func samePolicy(a, b Policy) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Publish makes p the policy for every service.
func (e *Engine) Publish(ctx context.Context, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.source != nil {
		e.source = &p
	}
	e.mu.Unlock()
	client := e.connect()
	if client == nil {
		e.receive(p)
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := client.Do(ctx, client.B().Set().Key(keyPolicy).Value(string(raw)).Build()).Error(); err != nil {
		e.receive(p)
		return err
	}
	e.receive(p)
	return nil
}

// Acquire takes a connection slot for an address. It returns false when the
// address has its limit, and otherwise a function that gives the slot back.
// Counted per instance: it stops one host exhausting a service, and asking
// Valkey on every connection would make accepting mail depend on it.
func (e *Engine) Acquire(addr string) (func(), bool) {
	p := e.Policy()
	network := Network(addr)
	if p.Mode == ModeOff || network == "" || e.Exempt(addr) {
		return func() {}, true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conns[network] >= p.ConnectionsPerAddress {
		if p.Mode == ModeEnforce {
			return nil, false
		}
		e.log.Info("Connection limit reached; logging only", "address", network)
	}
	e.conns[network]++
	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.conns[network]--; e.conns[network] <= 0 {
				delete(e.conns, network)
			}
		})
	}, true
}
