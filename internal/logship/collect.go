package logship

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/EvalAlan/elemta/internal/logging"
	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

const (
	collectQueue = 8192
	collectBatch = 500
	// A line bigger than this is cut as it is copied, so a huge one costs
	// the logging goroutine nothing.
	collectLineCopy = 16 << 10
	collectEvery    = time.Second
	policyEvery     = 5 * time.Second
	valkeyTimeout   = 5 * time.Second
)

// collector is one process's end: from its log to the stream. It never logs:
// what it logged would be the next thing it collected.
type collector struct {
	service, host string
	addr          string
	lines         chan []byte
	// off is only true once a policy said so, so start-up is kept until
	// the first answer.
	off     atomic.Bool
	dropped atomic.Int64
	client  valkey.Client
	policy  policy
	known   bool
}

// Collect copies this process's log to the stream, whenever shipping is on,
// until ctx ends. Without Valkey it does nothing.
func Collect(ctx context.Context, service, addr string) {
	if addr == "" {
		// Nothing will ever read them, so don't keep start-up's lines.
		logging.SetTap(func([]byte) {})
		return
	}
	c := newCollector(service, addr)
	logging.SetTap(c.offer)
	defer logging.SetTap(nil)
	c.run(ctx)
}

func newCollector(service, addr string) *collector {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &collector{service: service, host: host, addr: addr, lines: make(chan []byte, collectQueue)}
}

// offer is called from the logging path, and never waits.
func (c *collector) offer(p []byte) {
	if c.off.Load() {
		return
	}
	if len(c.lines) == cap(c.lines) {
		c.dropped.Add(1)
		return
	}
	line := append([]byte(nil), p[:min(len(p), collectLineCopy)]...)
	select {
	case c.lines <- line:
	default:
		c.dropped.Add(1)
	}
}

func (c *collector) run(ctx context.Context) {
	defer func() {
		if c.client != nil {
			c.client.Close()
		}
	}()
	c.readPolicy(ctx)
	policyTick, flushTick := time.NewTicker(policyEvery), time.NewTicker(collectEvery)
	defer policyTick.Stop()
	defer flushTick.Stop()
	for {
		select {
		case <-ctx.Done():
			// What the process said as it stopped.
			last, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			c.flush(last)
			cancel()
			return
		case <-policyTick.C:
			c.readPolicy(ctx)
		case <-flushTick.C:
			c.flush(ctx)
		}
	}
}

func (c *collector) readPolicy(ctx context.Context) {
	if c.client == nil {
		client, err := valkeyaddr.NewClient(c.addr, nil)
		if err != nil {
			return
		}
		c.client = client
	}
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	raw, err := c.client.Do(ctx, c.client.B().Get().Key(keyPolicy).Build()).ToString()
	var p policy
	switch {
	case valkey.IsValkeyNil(err):
	case err != nil:
		return // keep the last answer
	case json.Unmarshal([]byte(raw), &p) != nil:
		return
	}
	if _, ok := levels[p.MinLevel]; !ok {
		p.MinLevel = "info"
	}
	c.policy, c.known = p, true
	c.off.Store(!p.Enabled)
	if !p.Enabled {
		c.dropped.Store(0)
		for len(c.lines) > 0 {
			<-c.lines
		}
	}
}

func (c *collector) flush(ctx context.Context) {
	if !c.known || !c.policy.Enabled {
		return
	}
	for {
		var batch [][]byte
		for len(batch) < collectBatch && len(c.lines) > 0 {
			if out := prepare(<-c.lines, c.policy, time.Now()); out != nil {
				batch = append(batch, out)
			}
		}
		if len(batch) == 0 && c.dropped.Load() == 0 {
			return
		}
		if !c.push(ctx, batch) || len(c.lines) < collectBatch {
			return
		}
	}
}

func (c *collector) push(ctx context.Context, batch [][]byte) bool {
	ctx, cancel := context.WithTimeout(ctx, valkeyTimeout)
	defer cancel()
	b := c.client.B
	cmds := make(valkey.Commands, 0, len(batch)+1)
	cmds = append(cmds, b().Xlen().Key(keyStream).Build())
	limit := strconv.Itoa(maxStreamLines)
	for _, line := range batch {
		cmds = append(cmds, b().Xadd().Key(keyStream).Maxlen().Exact().Threshold(limit).Id("*").
			FieldValue().FieldValue("s", c.service).FieldValue("h", c.host).FieldValue("e", string(line)).Build())
	}
	results := c.client.DoMulti(ctx, cmds...)
	var added, lost int64
	for _, r := range results[1:] {
		if r.Error() != nil {
			lost++
		} else {
			added++
		}
	}
	if waiting, err := results[0].AsInt64(); err == nil && waiting+added > maxStreamLines {
		// The oldest went to make room.
		lost += waiting + added - maxStreamLines
	}
	if lost += c.dropped.Swap(0); lost > 0 {
		err := c.client.Do(ctx, b().Hincrby().Key(keyStatus).Field("dropped").Increment(lost).Build()).Error()
		if err != nil {
			c.dropped.Add(lost) // told when Valkey is back
			return false
		}
		_ = c.client.Do(ctx, b().Hset().Key(keyStatus).FieldValue().FieldValue("last_dropped", time.Now().UTC().Format(time.RFC3339)).Build()).Error()
	}
	return len(batch) == 0 || added > 0
}
