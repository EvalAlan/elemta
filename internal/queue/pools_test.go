package queue

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustPoolRouter(t *testing.T, cfg PoolsConfig) *PoolRouter {
	t.Helper()
	r, err := NewPoolRouter(cfg, nil)
	if err != nil {
		t.Fatalf("NewPoolRouter: %v", err)
	}
	return r
}

func TestPoolRouterSelectsBySender(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{
		Pools: []PoolConfig{
			{Name: "transactional", Senders: []string{"example.com", "alerts@news.example.com"}, IPs: []PoolIPConfig{{Address: "192.0.2.1"}}},
			{Name: "bulk", Senders: []string{"news.example.com", ".promo.example"}, IPs: []PoolIPConfig{{Address: "192.0.2.2"}}},
			{Name: "system", IPs: []PoolIPConfig{{Address: "192.0.2.3"}}},
		},
		DefaultPool: "system",
	})

	for sender, want := range map[string]string{
		"user@example.com":        "transactional",
		"<User@Example.COM>":      "transactional",
		"daily@news.example.com":  "bulk",
		"alerts@news.example.com": "transactional", // address beats domain
		"x@deals.promo.example":   "bulk",          // leading dot covers subdomains
		"x@a.b.promo.example":     "bulk",
		"x@promo.example":         "system", // ...but not the parent itself
		"x@unrelated.test":        "system",
		"":                        "system", // null sender (DSNs) goes to the default
		"x@sub.example.com":       "system", // a bare domain does not cover subdomains
	} {
		if got := r.poolFor(sender); got != want {
			t.Errorf("poolFor(%q) = %q, want %q", sender, got, want)
		}
	}
}

func TestPoolRouterWithoutDefaultLeavesUnmatchedMailUnpooled(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{
		{Name: "bulk", Senders: []string{"news.example.com"}, IPs: []PoolIPConfig{{Address: "192.0.2.2"}}},
	}})
	src, release, err := r.acquire("someone@elsewhere.test")
	if err != nil || src != nil {
		t.Fatalf("acquire for unmatched sender = %v, %v; want unpooled", src, err)
	}
	release()
}

func TestNewPoolRouterRejectsBadConfig(t *testing.T) {
	ip := func(a string) []PoolIPConfig { return []PoolIPConfig{{Address: a}} }
	for name, cfg := range map[string]PoolsConfig{
		"unnamed":            {Pools: []PoolConfig{{IPs: ip("192.0.2.1")}}},
		"duplicate name":     {Pools: []PoolConfig{{Name: "a", IPs: ip("192.0.2.1")}, {Name: "a", IPs: ip("192.0.2.2")}}},
		"no ips":             {Pools: []PoolConfig{{Name: "a"}}},
		"not an ip":          {Pools: []PoolConfig{{Name: "a", IPs: ip("mta1.example.com")}}},
		"unspecified":        {Pools: []PoolConfig{{Name: "a", IPs: ip("0.0.0.0")}}},
		"shared address":     {Pools: []PoolConfig{{Name: "a", IPs: ip("192.0.2.1")}, {Name: "b", IPs: ip("192.0.2.1")}}},
		"shared sender":      {Pools: []PoolConfig{{Name: "a", Senders: []string{"x.test"}, IPs: ip("192.0.2.1")}, {Name: "b", Senders: []string{"X.test"}, IPs: ip("192.0.2.2")}}},
		"unknown default":    {Pools: []PoolConfig{{Name: "a", IPs: ip("192.0.2.1")}}, DefaultPool: "b"},
		"default, no pools":  {DefaultPool: "a"},
		"zero warmup day":    {Pools: []PoolConfig{{Name: "a", IPs: ip("192.0.2.1"), WarmupSchedule: []int{50, 0}}}},
		"bad warmup date":    {Pools: []PoolConfig{{Name: "a", IPs: []PoolIPConfig{{Address: "192.0.2.1", WarmupStart: "10/01/2026"}}, WarmupSchedule: []int{50}}}},
		"start, no schedule": {Pools: []PoolConfig{{Name: "a", IPs: []PoolIPConfig{{Address: "192.0.2.1", WarmupStart: "2026-10-01"}}}}},
	} {
		if _, err := NewPoolRouter(cfg, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if r, err := NewPoolRouter(PoolsConfig{}, nil); r != nil || err != nil {
		t.Errorf("empty config = %v, %v; want nil, nil (unpooled)", r, err)
	}
}

func TestPoolRouterRotatesAcrossAddresses(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "p", Senders: []string{"example.com"},
		IPs: []PoolIPConfig{{Address: "192.0.2.1"}, {Address: "192.0.2.2"}, {Address: "192.0.2.3"}},
	}}})
	counts := map[string]int{}
	for i := 0; i < 30; i++ {
		src, _, err := r.acquire("a@example.com")
		if err != nil {
			t.Fatal(err)
		}
		counts[src.addr]++
	}
	for _, addr := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if counts[addr] != 10 {
			t.Errorf("%s got %d of 30, want an even 10: %v", addr, counts[addr], counts)
		}
	}
}

// warmupRouter is a pool with one warm and one warming address, the shape a
// real warmup takes: the new address carries what its schedule allows and
// the warm one carries the rest.
func warmupRouter(t *testing.T, now *time.Time) *PoolRouter {
	t.Helper()
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "p", Senders: []string{"example.com"},
		WarmupSchedule: []int{48, 96, 480},
		IPs: []PoolIPConfig{
			{Address: "192.0.2.1"},
			{Address: "192.0.2.2", WarmupStart: "2026-10-01"},
		},
	}}})
	r.now = func() time.Time { return *now }
	return r
}

func TestWarmupCapIsPacedAcrossTheDay(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // day 1: cap 48
	r := warmupRouter(t, &now)

	sendFromNew := func(n int) int {
		got := 0
		for i := 0; i < n; i++ {
			src, _, err := r.acquire("a@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if src.addr == "192.0.2.2" {
				got++
			}
		}
		return got
	}

	// At midnight one hour's worth (48/24 = 2) is available up front; the
	// rest of a burst goes to the warm address instead of blowing the cap.
	if got := sendFromNew(100); got != 2 {
		t.Errorf("at 00:00 the warming address sent %d, want 2", got)
	}
	// By noon half the day plus the hour is released: ceil(48*13/24) = 26.
	now = now.Add(12 * time.Hour)
	if got := sendFromNew(100); got != 24 {
		t.Errorf("by 12:00 the warming address sent %d more, want 24 (26 total)", got)
	}
	// Late in the day the full cap and no more.
	now = now.Add(11*time.Hour + 30*time.Minute)
	if got := sendFromNew(100); got != 22 {
		t.Errorf("by 23:30 the warming address sent %d more, want 22 (48 total)", got)
	}

	// The next UTC day starts a fresh count against day 2's cap (96).
	now = time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC)
	if got := sendFromNew(200); got != 96 {
		t.Errorf("day 2 sent %d from the warming address, want its cap of 96", got)
	}

	// Past the end of the schedule the address is warm: no cap.
	now = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	if got := sendFromNew(200); got != 100 {
		t.Errorf("after the schedule the address sent %d of 200, want an even split of 100", got)
	}
}

func TestPoolAtCapacityDefersWithoutBlamingTheDestination(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "new", Senders: []string{"example.com"}, WarmupSchedule: []int{24},
		IPs: []PoolIPConfig{{Address: "192.0.2.9", WarmupStart: "2026-10-01"}},
	}}})
	r.now = func() time.Time { return now }

	if _, _, err := r.acquire("a@example.com"); err != nil {
		t.Fatalf("first message: %v", err)
	}
	_, _, err := r.acquire("a@example.com")
	if !errors.Is(err, ErrPoolAtCapacity) {
		t.Fatalf("err = %v, want ErrPoolAtCapacity", err)
	}
	if !(&Processor{}).isTemporaryFailure(err) {
		t.Error("a warmup cap was classified as permanent; it would bounce mail")
	}

	// Through the handler: the message defers, nothing is dialled, and the
	// destination is not put into backoff for a limit that is ours.
	h := NewSMTPDeliveryHandler(0)
	h.SetPoolRouter(r)
	shaper := NewShaper(ShapingConfig{BackoffInitial: time.Hour, BackoffMax: time.Hour})
	h.SetShaper(shaper)
	h.resolver = resolverFunc(func(context.Context, string) ([]*net.MX, error) {
		t.Error("looked up MX for a message the pool cannot send")
		return nil, errors.New("unreachable")
	})
	res, err := h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "a@example.com", To: []string{"b@dest.example"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if err == nil || res.Success {
		t.Fatalf("delivered past the warmup cap: %+v", res)
	}
	if !(&Processor{}).isTemporaryFailure(err) {
		t.Errorf("handler error %v is not temporary", err)
	}
	for _, s := range shaper.Statuses() {
		if s.BackingOffFor != "" || s.Deferred != 0 {
			t.Errorf("destination %s/%s was backed off for our own cap: %+v", s.Domain, s.SourceIP, s)
		}
	}
}

func TestPoolReservationIsRefundedWhenNothingWasSent(t *testing.T) {
	now := time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC)
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "new", Senders: []string{"example.com"}, WarmupSchedule: []int{5},
		IPs: []PoolIPConfig{{Address: "192.0.2.9", WarmupStart: "2026-10-01"}},
	}}})
	r.now = func() time.Time { return now }

	for i := 0; i < 20; i++ {
		_, release, err := r.acquire("a@example.com")
		if err != nil {
			t.Fatalf("attempt %d: %v; failed connections used up the allowance", i, err)
		}
		release()
		release() // idempotent: a double refund must not mint allowance
	}
	if st := r.Statuses()[0]; st.SentToday != 0 {
		t.Errorf("sent_today = %d after only refunded attempts, want 0", st.SentToday)
	}
}

func TestWarmupCountsSurviveRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "pool-state.json")
	now := time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC)
	cfg := PoolsConfig{StateFile: state, Pools: []PoolConfig{{
		Name: "new", Senders: []string{"example.com"}, WarmupSchedule: []int{10},
		IPs: []PoolIPConfig{{Address: "192.0.2.9", WarmupStart: "2026-10-01"}},
	}}}

	first := mustPoolRouter(t, cfg)
	first.now = func() time.Time { return now }
	first.Start(time.Hour)
	for i := 0; i < 7; i++ {
		if _, _, err := first.acquire("a@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	first.Close() // flushes

	second := mustPoolRouter(t, cfg)
	second.now = func() time.Time { return now }
	if st := second.Statuses()[0]; st.SentToday != 7 {
		t.Fatalf("after restart sent_today = %d, want 7", st.SentToday)
	}
	sent := 0
	for {
		if _, _, err := second.acquire("a@example.com"); err != nil {
			break
		}
		sent++
	}
	if sent != 3 {
		t.Errorf("after restart %d more were allowed, want 3 (cap 10, 7 already sent)", sent)
	}

	// A saved count from an earlier day is not carried into today.
	now = now.Add(2 * time.Hour)
	if st := second.Statuses()[0]; st.SentToday != 0 {
		t.Errorf("yesterday's count leaked into today: %d", st.SentToday)
	}
}

func TestPoolRouterIsSafeUnderConcurrency(t *testing.T) {
	now := time.Date(2026, 10, 1, 23, 59, 0, 0, time.UTC)
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "new", Senders: []string{"example.com"}, WarmupSchedule: []int{100},
		IPs: []PoolIPConfig{{Address: "192.0.2.9", WarmupStart: "2026-10-01"}},
	}}})
	r.now = func() time.Time { return now }

	var mu sync.Mutex
	granted := 0
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, _, err := r.acquire("a@example.com"); err == nil {
					mu.Lock()
					granted++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if granted != 100 {
		t.Errorf("granted %d under contention, want exactly the cap of 100", granted)
	}
}

func TestShapingAndSessionKeysSeparateSourceAddresses(t *testing.T) {
	a := &sourceIP{addr: "192.0.2.1"}
	b := &sourceIP{addr: "192.0.2.2"}
	if shapingKey(a, "gmail.com") == shapingKey(b, "gmail.com") {
		t.Error("two source addresses share one shaping state: a deferral on one would slow the other")
	}
	if shapingKey(nil, "gmail.com") != "gmail.com" {
		t.Error("unpooled shaping key changed; existing per-domain behaviour must be unchanged")
	}
	if sessionKey(a, "mx:25") == sessionKey(b, "mx:25") || sessionKey(nil, "mx:25") != "mx:25" {
		t.Error("session cache keys do not separate source addresses")
	}

	shaper := NewShaper(ShapingConfig{BackoffInitial: time.Hour, BackoffMax: time.Hour})
	shaper.ReportDeferral(shapingKey(a, "gmail.com"))
	if _, err := shaper.Acquire(context.Background(), shapingKey(b, "gmail.com")); err != nil {
		t.Errorf("a deferral from one address backed off another: %v", err)
	}
	for _, s := range shaper.Statuses() {
		if s.Domain != "gmail.com" || (s.SourceIP != a.addr && s.SourceIP != b.addr) {
			t.Errorf("status = %+v; want domain and source address split back out", s)
		}
	}
}

// TestPooledDeliveryBindsSourceAndAnnouncesItsName delivers through a real
// socket from a loopback alias, so it checks what a receiver actually sees:
// the connection comes from the pool address and EHLO carries that
// address's name. A session parked from one address must not be reused for
// mail from another.
func TestPooledDeliveryBindsSourceAndAnnouncesItsName(t *testing.T) {
	const poolAddr = "127.0.0.2"
	if ln, err := net.Listen("tcp", poolAddr+":0"); err != nil {
		t.Skipf("cannot bind %s here: %v", poolAddr, err)
	} else {
		_ = ln.Close()
	}

	type seen struct{ remote, ehlo string }
	var mu sync.Mutex
	var sessions []seen
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				r, w := bufio.NewReader(c), bufio.NewWriter(c)
				fmt.Fprint(w, "220 fake ESMTP\r\n")
				w.Flush()
				inData := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if strings.TrimSpace(line) == "." {
							fmt.Fprint(w, "250 2.0.0 queued\r\n")
							w.Flush()
							inData = false
						}
						continue
					}
					u := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(u, "EHLO"):
						mu.Lock()
						sessions = append(sessions, seen{remote: host, ehlo: strings.TrimSpace(line[5:])})
						mu.Unlock()
						fmt.Fprint(w, "250 fake\r\n")
					case u == "DATA":
						fmt.Fprint(w, "354 send\r\n")
						inData = true
					case u == "QUIT":
						fmt.Fprint(w, "221 bye\r\n")
						w.Flush()
						return
					default:
						fmt.Fprint(w, "250 ok\r\n")
					}
					w.Flush()
				}
			}(conn)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "bulk", Senders: []string{"news.example.com"},
		IPs: []PoolIPConfig{{Address: poolAddr, Helo: "bulk1.example.com"}},
	}}})
	if err := r.CheckLocalAddresses(); err != nil {
		t.Fatalf("CheckLocalAddresses: %v", err)
	}

	h := NewSMTPDeliveryHandler(0)
	h.SetHeloHostname("mta.example.com")
	h.SetPoolRouter(r)
	h.SetShaper(NewShaper(DefaultShapingConfig()))
	h.resolver = resolverFunc(func(context.Context, string) ([]*net.MX, error) {
		return []*net.MX{{Host: "127.0.0.1", Pref: 0}}, nil
	})
	h.mtastsManager = allowMTASTS{}
	h.mxPort = port
	defer h.CloseIdleSessions()

	deliver := func(from string) {
		t.Helper()
		if _, err := h.DeliverMessageWithMetadata(context.Background(),
			Message{From: from, To: []string{"rcpt@dest.example"}}, []byte("Subject: x\r\n\r\nhi\r\n")); err != nil {
			t.Fatalf("deliver from %s: %v", from, err)
		}
	}
	deliver("daily@news.example.com")
	deliver("daily@news.example.com") // reuses the parked pooled session
	deliver("ceo@example.com")        // unpooled: must not ride the pooled session

	mu.Lock()
	defer mu.Unlock()
	if len(sessions) != 2 {
		t.Fatalf("receiver saw %d sessions %+v, want 2 (one reused, one separate for unpooled mail)", len(sessions), sessions)
	}
	if sessions[0] != (seen{remote: poolAddr, ehlo: "bulk1.example.com"}) {
		t.Errorf("pooled session = %+v, want from %s announcing bulk1.example.com", sessions[0], poolAddr)
	}
	if sessions[1] != (seen{remote: "127.0.0.1", ehlo: "mta.example.com"}) {
		t.Errorf("unpooled session = %+v, want the default source and hostname", sessions[1])
	}
	if st := r.Statuses()[0]; st.SentToday != 2 {
		t.Errorf("pool address sent_today = %d, want 2", st.SentToday)
	}
}

func TestCheckLocalAddressesRefusesForeignAddress(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "p", IPs: []PoolIPConfig{{Address: "192.0.2.77"}}, // TEST-NET-1, never local
	}}})
	if err := r.CheckLocalAddresses(); err == nil || !strings.Contains(err.Error(), "192.0.2.77") {
		t.Errorf("CheckLocalAddresses = %v, want a refusal naming 192.0.2.77", err)
	}
}
