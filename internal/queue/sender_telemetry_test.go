package queue

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"
)

type senderCapture struct {
	metricCapture
	senders []string // "dimension:key:outcome"
}

func (s *senderCapture) IncrSenderOutcome(_ context.Context, dimension, key, outcome string) error {
	s.senders = append(s.senders, dimension+":"+key+":"+outcome)
	return nil
}

func TestOutcomesAreAttributedToPoolAddressAndProvider(t *testing.T) {
	addr, stop := startSMTPServer(t, "421 4.7.28 Our system has detected an unusual rate of unsolicited mail originating from your IP address.")
	defer stop()

	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "bulk", Senders: []string{"news.example.com"},
		IPs: []PoolIPConfig{{Address: "192.0.2.20"}},
	}}})

	h := NewSMTPDeliveryHandler(0)
	h.mtastsManager = allowMTASTS{}
	h.maxMXLookups = 1
	h.SetConnectionReuse(false)
	h.SetPoolRouter(r)
	h.SetProviderRouter(mustProviders(t))
	h.SetShaper(NewShaper(ShapingConfig{BackoffInitial: time.Second, BackoffMax: time.Second}))
	h.resolver = resolverFunc(func(context.Context, string) ([]*net.MX, error) {
		return mxHosts("gmail-smtp-in.l.google.com."), nil
	})
	// The dialer is replaced, so 192.0.2.20 never has to exist here; what is
	// under test is the bookkeeping, not the bind.
	h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	res, _ := h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "daily@news.example.com", To: []string{"a@gmail.com"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if len(res.RecipientOutcomes) != 1 {
		t.Fatalf("outcomes = %+v", res.RecipientOutcomes)
	}
	o := res.RecipientOutcomes[0]
	if o.Pool != "bulk" || o.SourceIP != "192.0.2.20" || o.Provider != "gmail" || !o.Throttled {
		t.Errorf("outcome = %+v; want pool bulk, ip 192.0.2.20, provider gmail, throttled", o)
	}

	// The next attempt is refused by our own backoff. The receiver never saw
	// it, so it says nothing about the sender and is not attributed.
	res, _ = h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "daily@news.example.com", To: []string{"b@gmail.com"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if o := res.RecipientOutcomes[0]; o.Pool != "" || o.SourceIP != "" || o.Provider != "" || o.Throttled {
		t.Errorf("a self-inflicted deferral was attributed: %+v", o)
	}
}

func TestProcessorRecordsSenderOutcomesAndComplaints(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "bulk", IPs: []PoolIPConfig{{Address: "192.0.2.20"}},
	}}})
	h := NewSMTPDeliveryHandler(0)
	h.SetPoolRouter(r)
	providers := mustProviders(t)
	providers.matchMX("yahoo.com", mxHosts("mta5.am0.yahoodns.net"))
	h.SetProviderRouter(providers)

	capture := &senderCapture{}
	p := &Processor{ctx: context.Background(), handler: h}
	p.SetMetricsRecorder(capture)

	p.recordDomainOutcomes(&DeliveryResult{RecipientOutcomes: []RecipientOutcome{
		{Recipient: "a@yahoo.com", Status: RecipientDelivered, Pool: "bulk", SourceIP: "192.0.2.20", Provider: "yahoo"},
		{Recipient: "b@yahoo.com", Status: RecipientTemporaryFailure, Pool: "bulk", SourceIP: "192.0.2.20", Provider: "yahoo", Throttled: true},
		{Recipient: "c@elsewhere.example", Status: RecipientPermanentFailure},
	}})
	// A complaint from Yahoo's feedback loop about mail from our pool
	// address, and one whose Source-IP is not ours at all.
	p.RecordComplaint("192.0.2.20", []string{"a@yahoo.com"})
	p.RecordComplaint("198.51.100.9", []string{"someone@unknown.example"})

	sort.Strings(capture.senders)
	want := []string{
		"ip:192.0.2.20:complained",
		"ip:192.0.2.20:deferred",
		"ip:192.0.2.20:delivered",
		"ip:192.0.2.20:throttled",
		"pool:bulk:complained",
		"pool:bulk:deferred",
		"pool:bulk:delivered",
		"pool:bulk:throttled",
		"provider:yahoo:complained",
		"provider:yahoo:deferred",
		"provider:yahoo:delivered",
		"provider:yahoo:throttled",
	}
	if len(capture.senders) != len(want) {
		t.Fatalf("recorded %v\nwant %v", capture.senders, want)
	}
	for i := range want {
		if capture.senders[i] != want[i] {
			t.Fatalf("recorded %v\nwant %v", capture.senders, want)
		}
	}
	// Per-destination counting is unchanged.
	if len(capture.domains) != 3 {
		t.Errorf("domain outcomes = %v", capture.domains)
	}
}

func TestSplitHandlerPassesComplaintAttributionThrough(t *testing.T) {
	r := mustPoolRouter(t, PoolsConfig{Pools: []PoolConfig{{
		Name: "bulk", IPs: []PoolIPConfig{{Address: "2001:db8::20"}},
	}}})
	remote := NewSMTPDeliveryHandler(0)
	remote.SetPoolRouter(r)
	split := NewSplitDeliveryHandler(NewMockDeliveryHandler(0), remote, []string{"local.example"}, nil)
	a := split.AttributeComplaint("2001:DB8:0:0::20", nil)
	if a.Pool != "bulk" || a.SourceIP != "2001:db8::20" {
		t.Errorf("attribution = %+v; IPv6 must be compared in canonical form", a)
	}
}
