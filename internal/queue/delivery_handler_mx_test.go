package queue

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

type stubMXResolver struct {
	records []*net.MX
	err     error
	calls   int
}

func (r *stubMXResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	r.calls++
	return r.records, r.err
}

func TestAggregateDomainFailuresDeterministicClassification(t *testing.T) {
	permanent := &PermanentError{msg: "550 rejected"}
	temporary := &TemporaryError{msg: "451 try later"}
	orders := [][]domainFailure{
		{{domain: "z.example", err: permanent}, {domain: "a.example", err: temporary}},
		{{domain: "a.example", err: temporary}, {domain: "z.example", err: permanent}},
	}
	for i := 0; i < 100; i++ {
		err := aggregateDomainFailures(orders[i%len(orders)])
		if !(&Processor{}).isTemporaryFailure(err) {
			t.Fatalf("mixed aggregate iteration %d classified permanent: %v", i, err)
		}
		if got := err.Error(); !strings.Contains(got, "a.example: 451 try later; z.example: 550 rejected") {
			t.Fatalf("iteration %d error order is not deterministic: %q", i, got)
		}
	}

	err := aggregateDomainFailures([]domainFailure{{domain: "z.example", err: permanent}, {domain: "a.example", err: &PermanentError{msg: "554 denied"}}})
	if (&Processor{}).isTemporaryFailure(err) {
		t.Fatalf("all-permanent aggregate classified temporary: %v", err)
	}
}

func TestPartialDeliveryPreservesAggregateClassification(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	tests := []struct {
		name       string
		failureErr error
		temporary  bool
	}{
		{"permanent", aggregateDomainFailures([]domainFailure{{domain: "bad.example", err: &PermanentError{msg: "550 rejected"}}}), false},
		{"temporary", aggregateDomainFailures([]domainFailure{{domain: "slow.example", err: &TemporaryError{msg: "451 later"}}}), true},
		{"mixed", aggregateDomainFailures([]domainFailure{{domain: "bad.example", err: &PermanentError{msg: "550 rejected"}}, {domain: "slow.example", err: &TemporaryError{msg: "451 later"}}}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.buildDeliveryResult([]string{"ok@example", "failed@example"}, 1, "", "", tt.failureErr)
			if err == nil || result.Error != err {
				t.Fatalf("partial result error = %v, returned error = %v", result.Error, err)
			}
			if got := (&Processor{}).isTemporaryFailure(err); got != tt.temporary {
				t.Fatalf("temporary = %v, want %v: %T %v", got, tt.temporary, err, err)
			}
		})
	}
}

func TestLookupMXImplicitFallbackAndPreferenceOrder(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		records []*net.MX
		want    []string
	}{
		{name: "successful empty answer falls back to domain", domain: "nomx.example", want: []string{"nomx.example"}},
		{name: "MX preference order is stable", domain: "example.test", records: []*net.MX{
			{Host: "backup.example.test.", Pref: 20},
			{Host: "primary.example.test.", Pref: 10},
			{Host: "backup2.example.test.", Pref: 20},
		}, want: []string{"primary.example.test.", "backup.example.test.", "backup2.example.test."}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &stubMXResolver{records: tt.records}
			h := NewSMTPDeliveryHandler(0)
			h.resolver = resolver
			h.maxMXLookups = 1

			got, err := h.lookupMX(context.Background(), tt.domain)
			if err != nil {
				t.Fatalf("lookupMX: %v", err)
			}
			hosts := make([]string, len(got))
			for i, mx := range got {
				hosts[i] = mx.Host
			}
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Fatalf("hosts = %v, want %v", hosts, tt.want)
			}
		})
	}
}

func TestLookupMXNullMXIsPermanent(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.resolver = &stubMXResolver{records: []*net.MX{{Host: ".", Pref: 0}}}
	h.maxMXLookups = 1

	_, err := h.lookupMX(context.Background(), "no-mail.example")
	if err == nil {
		t.Fatal("expected Null MX failure")
	}
	var permanent interface{ Permanent() bool }
	if !errors.As(err, &permanent) || !permanent.Permanent() {
		t.Fatalf("error %T (%v) is not typed permanent", err, err)
	}
	if (&Processor{}).isTemporaryFailure(err) {
		t.Fatal("Null MX must be classified permanent")
	}
}

func TestLookupMXDNSFailureClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		temp bool
	}{
		{name: "NXDOMAIN is permanent", err: &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true}},
		{name: "timeout is temporary", err: &net.DNSError{Err: "i/o timeout", Name: "slow.example", IsTimeout: true, IsTemporary: true}, temp: true},
		{name: "SERVFAIL is temporary", err: &net.DNSError{Err: "server misbehaving", Name: "broken.example", IsTemporary: true}, temp: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewSMTPDeliveryHandler(0)
			h.resolver = &stubMXResolver{err: tt.err}
			h.maxMXLookups = 1
			_, err := h.lookupMX(context.Background(), "example")
			if err == nil {
				t.Fatal("expected DNS error")
			}
			if got := (&Processor{}).isTemporaryFailure(err); got != tt.temp {
				t.Fatalf("temporary = %v, want %v: %v", got, tt.temp, err)
			}
		})
	}
}

func TestNullMXCausesZeroDialAttempts(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.resolver = &stubMXResolver{records: []*net.MX{{Host: ".", Pref: 0}}}
	h.maxMXLookups = 1
	dials := 0
	h.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("unexpected dial")
	}

	_, _, _, err := h.deliverToDomainWithMetadata(context.Background(), Message{}, "no-mail.example", nil, nil, false)
	if err == nil {
		t.Fatal("expected Null MX failure")
	}
	if dials != 0 {
		t.Fatalf("dial attempts = %d, want 0", dials)
	}
}

func TestLookupMXDotRecordSemantics(t *testing.T) {
	tests := []struct {
		name      string
		records   []*net.MX
		want      []string
		temporary bool
	}{
		{"mixed null and normal ignores dot", []*net.MX{{Host: ".", Pref: 0}, {Host: "mx.example.", Pref: 10}}, []string{"mx.example."}, false},
		{"nonzero dot alone is malformed temporary failure", []*net.MX{{Host: ".", Pref: 10}}, nil, true},
		{"mixed nonzero dot and normal ignores dot", []*net.MX{{Host: ".", Pref: 10}, {Host: "mx.example.", Pref: 20}}, []string{"mx.example."}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewSMTPDeliveryHandler(0)
			h.resolver = &stubMXResolver{records: tt.records}
			h.maxMXLookups = 1
			got, err := h.lookupMX(context.Background(), "example")
			if tt.temporary {
				if err == nil || !(&Processor{}).isTemporaryFailure(err) {
					t.Fatalf("error = %v, want temporary", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var hosts []string
			for _, mx := range got {
				hosts = append(hosts, mx.Host)
			}
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Fatalf("hosts=%v want=%v", hosts, tt.want)
			}
		})
	}
}

func TestLookupMXDoesNotMutateResolverSlice(t *testing.T) {
	records := []*net.MX{{Host: "backup.", Pref: 20}, {Host: "primary.", Pref: 10}}
	h := NewSMTPDeliveryHandler(0)
	h.resolver = &stubMXResolver{records: records}
	h.maxMXLookups = 1
	if _, err := h.lookupMX(context.Background(), "example"); err != nil {
		t.Fatal(err)
	}
	if records[0].Host != "backup." {
		t.Fatalf("resolver slice mutated: %v", records)
	}
}

type scriptedMXResolver struct {
	records [][]*net.MX
	errs    []error
	calls   int
}

func (r *scriptedMXResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	i := r.calls
	r.calls++
	return r.records[i], r.errs[i]
}

func TestLookupMXRetryControl(t *testing.T) {
	transient := &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	t.Run("transient then success", func(t *testing.T) {
		r := &scriptedMXResolver{records: [][]*net.MX{nil, {{Host: "mx.", Pref: 0}}}, errs: []error{transient, nil}}
		h := NewSMTPDeliveryHandler(0)
		h.resolver = r
		h.maxMXLookups = 3
		sleeps := 0
		h.mxRetrySleep = func(context.Context, time.Duration) error { sleeps++; return nil }
		if _, err := h.lookupMX(context.Background(), "example"); err != nil {
			t.Fatal(err)
		}
		if r.calls != 2 || sleeps != 1 {
			t.Fatalf("calls=%d sleeps=%d", r.calls, sleeps)
		}
	})
	t.Run("NXDOMAIN immediate", func(t *testing.T) {
		r := &stubMXResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}
		h := NewSMTPDeliveryHandler(0)
		h.resolver = r
		h.maxMXLookups = 3
		h.mxRetrySleep = func(context.Context, time.Duration) error { t.Fatal("unexpected sleep"); return nil }
		_, err := h.lookupMX(context.Background(), "missing")
		var permanent interface{ Permanent() bool }
		if r.calls != 1 || !errors.As(err, &permanent) {
			t.Fatalf("calls=%d error=%v", r.calls, err)
		}
	})
	t.Run("exhaustion", func(t *testing.T) {
		r := &stubMXResolver{err: transient}
		h := NewSMTPDeliveryHandler(0)
		h.resolver = r
		h.maxMXLookups = 3
		h.mxRetrySleep = func(context.Context, time.Duration) error { return nil }
		if _, err := h.lookupMX(context.Background(), "example"); !errors.Is(err, transient) || r.calls != 3 {
			t.Fatalf("calls=%d error=%v", r.calls, err)
		}
	})
	t.Run("context cancellation", func(t *testing.T) {
		r := &stubMXResolver{err: transient}
		h := NewSMTPDeliveryHandler(0)
		h.resolver = r
		h.maxMXLookups = 3
		ctx, cancel := context.WithCancel(context.Background())
		h.mxRetrySleep = func(context.Context, time.Duration) error { cancel(); return ctx.Err() }
		if _, err := h.lookupMX(ctx, "example"); !errors.Is(err, context.Canceled) || r.calls != 1 {
			t.Fatalf("calls=%d error=%v", r.calls, err)
		}
	})
}
