package queue

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// reuseServer is a fake receiver that counts connections and commands. delay
// is added before every reply to stand in for network round trips.
type reuseServer struct {
	addr     string
	conns    atomic.Int32
	rsets    atomic.Int32
	noops    atomic.Int32
	messages atomic.Int32
	delay    time.Duration
	// dropAfterDATA closes the connection instead of replying to the end of
	// data, the way a crashing or timed-out receiver does.
	dropAfterDATA atomic.Bool
	refuseRcpt    atomic.Bool
	// cert, when set, makes the server offer STARTTLS with it.
	cert *tls.Certificate
	mu   sync.Mutex
	live []net.Conn
}

func startReuseServer(t testing.TB, delay time.Duration) *reuseServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &reuseServer{addr: ln.Addr().String(), delay: delay}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		s.dropAll()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.mu.Lock()
			s.live = append(s.live, c)
			s.mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); s.serve(c) }()
		}
	}()
	return s
}

// dropAll closes every open connection without a word, as a receiver's idle
// timer does.
func (s *reuseServer) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.live {
		_ = c.Close()
	}
	s.live = nil
}

func (s *reuseServer) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	reply := func(line string) {
		time.Sleep(s.delay)
		fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}
	reply("220 fake ESMTP")
	inData, secure := false, false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if strings.TrimRight(line, "\r\n") == "." {
				inData = false
				if s.dropAfterDATA.Load() {
					return
				}
				s.messages.Add(1)
				reply("250 2.0.0 queued")
			}
			continue
		}
		u := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(u, "EHLO") && s.cert != nil && !secure:
			reply("250-fake")
			reply("250 STARTTLS")
		case u == "STARTTLS" && s.cert != nil && !secure:
			reply("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*s.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			r, w, secure = bufio.NewReader(tc), bufio.NewWriter(tc), true
		case strings.HasPrefix(u, "EHLO"), strings.HasPrefix(u, "HELO"):
			reply("250 fake")
		case strings.HasPrefix(u, "RCPT") && s.refuseRcpt.Load():
			reply("550 5.1.1 no such user")
		case u == "DATA":
			reply("354 send")
			inData = true
		case u == "RSET":
			s.rsets.Add(1)
			reply("250 ok")
		case u == "NOOP":
			s.noops.Add(1)
			reply("250 ok")
		case u == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func reuseHandler(srv *reuseServer) *SMTPDeliveryHandler {
	h := NewSMTPDeliveryHandler(0)
	h.resolver = staticMXResolver{}
	h.mtastsManager = allowMTASTS{}
	h.maxMXLookups = 1
	h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.addr)
	}
	return h
}

func deliverOne(t testing.TB, h *SMTPDeliveryHandler, to string) {
	t.Helper()
	res, err := h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "sender@example.com", To: []string{to}}, []byte("Subject: x\r\n\r\nbody\r\n"))
	if err != nil || !res.Success {
		t.Fatalf("deliver to %s: res=%+v err=%v", to, res, err)
	}
}

// Consecutive messages to one MX ride one session, including messages for
// different domains that share it.
func TestSessionReuseAcrossMessagesAndDomains(t *testing.T) {
	srv := startReuseServer(t, 0)
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)

	deliverOne(t, h, "a@one.test")
	deliverOne(t, h, "b@two.test")
	deliverOne(t, h, "c@one.test")

	if got := srv.conns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}
	if got := srv.messages.Load(); got != 3 {
		t.Errorf("messages = %d, want 3", got)
	}
	// Completed transactions leave the session ready for MAIL FROM, so
	// reuse costs no extra round trips.
	if got := srv.rsets.Load() + srv.noops.Load(); got != 0 {
		t.Errorf("RSET+NOOP = %d after clean transactions, want 0", got)
	}
	st, _ := h.SessionCacheStats()
	if st.Hits != 2 || st.Misses != 1 || st.Idle != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// A receiver that dropped the parked session costs a reconnect, not a
// deferred message.
func TestSessionReuseRecoversFromDroppedSession(t *testing.T) {
	srv := startReuseServer(t, 0)
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)

	deliverOne(t, h, "a@one.test")
	srv.dropAll()
	deliverOne(t, h, "b@one.test")

	if got := srv.conns.Load(); got != 2 {
		t.Errorf("connections = %d, want 2 (the dropped one replaced)", got)
	}
	if got := srv.messages.Load(); got != 2 {
		t.Errorf("messages = %d, want 2", got)
	}
}

// A transaction that ended without a reply leaves the session in an unknown
// state, so it is closed rather than parked.
func TestSessionNotParkedAfterLostReply(t *testing.T) {
	srv := startReuseServer(t, 0)
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)

	srv.dropAfterDATA.Store(true)
	_, _ = h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "sender@example.com", To: []string{"a@one.test"}}, []byte("Subject: x\r\n\r\nbody\r\n"))
	if st, _ := h.SessionCacheStats(); st.Idle != 0 || st.Parked != 0 {
		t.Fatalf("session parked after lost DATA reply: %+v", st)
	}
	srv.dropAfterDATA.Store(false)
	deliverOne(t, h, "b@one.test")
	if got := srv.conns.Load(); got != 2 {
		t.Errorf("connections = %d, want 2", got)
	}
}

// A transaction that ended without DATA (every recipient refused) is still
// open on the receiver's side, so the session is RSET before it is parked.
func TestSessionResetAfterAbandonedTransaction(t *testing.T) {
	srv := startReuseServer(t, 0)
	srv.refuseRcpt.Store(true)
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)

	_, _ = h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "sender@example.com", To: []string{"gone@one.test"}}, []byte("Subject: x\r\n\r\nbody\r\n"))
	if got := srv.rsets.Load(); got != 1 {
		t.Errorf("RSETs = %d, want 1 before parking an abandoned transaction", got)
	}
	srv.refuseRcpt.Store(false)
	deliverOne(t, h, "b@one.test")
	if got := srv.conns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}
}

func TestSessionReuseCanBeDisabled(t *testing.T) {
	srv := startReuseServer(t, 0)
	h := reuseHandler(srv)
	h.SetConnectionReuse(false)

	deliverOne(t, h, "a@one.test")
	deliverOne(t, h, "b@one.test")
	if got := srv.conns.Load(); got != 2 {
		t.Errorf("connections = %d, want 2 with reuse off", got)
	}
	if _, ok := h.SessionCacheStats(); ok {
		t.Error("stats reported with reuse off")
	}
}

// Cache policy, without a network: expiry, use limits, per-host cap, and
// REQUIRETLS matching.
func TestSessionCachePolicy(t *testing.T) {
	srv := startReuseServer(t, 0)
	dial := func(tls outboundTLS, requireTLS bool) *outboundSession {
		h := reuseHandler(srv)
		h.SetConnectionReuse(false)
		s, _, err := h.acquireSession(context.Background(), srv.addr, false, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.tls, s.requireTLS = tls, requireTLS
		return s
	}

	now := time.Unix(1_000_000, 0)
	c := newSessionCache()
	c.now = func() time.Time { return now }

	t.Run("idle timeout", func(t *testing.T) {
		s := dial(tlsVerified, false)
		s.created = now
		c.put("mx:25", s, false)
		now = now.Add(c.idleTimeout + time.Second)
		if got := c.get("mx:25", false, false); got != nil {
			t.Error("expired session handed out")
		}
	})

	t.Run("max uses", func(t *testing.T) {
		s := dial(tlsVerified, false)
		s.created = now
		s.uses = c.maxUses - 1
		c.put("mx:25", s, false) // this use reaches the limit
		if got := c.get("mx:25", false, false); got != nil {
			t.Error("session past its use limit handed out")
		}
	})

	t.Run("REQUIRETLS only on verified sessions with next-hop support", func(t *testing.T) {
		weak := dial(tlsUnverified, true)
		weak.created = now
		c.put("mx:25", weak, false)
		if got := c.get("mx:25", true, false); got != nil {
			t.Error("unverified session handed to a REQUIRETLS message")
		}
		if got := c.get("mx:25", false, false); got != weak {
			t.Error("unverified session not available to an ordinary message")
		} else {
			closeSession(got)
		}
		strong := dial(tlsVerified, true)
		strong.created = now
		c.put("mx:25", strong, false)
		if got := c.get("mx:25", true, false); got != strong {
			t.Error("verified REQUIRETLS session not reused")
		} else {
			closeSession(got)
		}
	})

	t.Run("per-host cap", func(t *testing.T) {
		for i := 0; i < c.maxPerHost+2; i++ {
			s := dial(tlsVerified, false)
			s.created = now
			c.put("busy:25", s, false)
		}
		if n := len(c.idle["busy:25"]); n != c.maxPerHost {
			t.Errorf("parked %d sessions to one host, cap is %d", n, c.maxPerHost)
		}
		c.closeAll()
		if st := c.stats(); st.Idle != 0 {
			t.Errorf("closeAll left %d idle", st.Idle)
		}
	})
}

// BenchmarkSessionReuse delivers sequentially to a receiver that takes 1ms per
// reply, which stands in for a round trip to a nearby provider. Real round
// trips are longer and include a TLS handshake, so reuse gains more in
// production than here.
func BenchmarkSessionReuse(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprintf("reuse=%v", reuse), func(b *testing.B) {
			srv := startReuseServer(b, time.Millisecond)
			h := reuseHandler(srv)
			h.SetConnectionReuse(reuse)
			b.Cleanup(h.CloseIdleSessions)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				deliverOne(b, h, "r@bench.test")
			}
			b.ReportMetric(float64(srv.conns.Load())/float64(b.N), "conns/msg")
		})
	}
}
