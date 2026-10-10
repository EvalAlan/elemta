package authresult

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver answers TXT lookups from a fixed zone, counts the queries that
// reach it, and can be told to hang until the caller gives up — which is what
// an overloaded resolver looks like from here.
type fakeResolver struct {
	zone    map[string][]string
	err     error
	hang    bool
	release chan struct{}
	queries atomic.Int64
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.queries.Add(1)
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.hang {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	if f.err != nil {
		return nil, f.err
	}
	if records, ok := f.zone[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return f.hangOrNotFound(ctx, name)
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	_, err := f.hangOrNotFound(ctx, host)
	return nil, err
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	_, err := f.hangOrNotFound(ctx, addr)
	return nil, err
}

func (f *fakeResolver) hangOrNotFound(ctx context.Context, name string) ([]*net.MX, error) {
	if f.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestCachedAnswerIsNotAskedForAgain(t *testing.T) {
	upstream := &fakeResolver{zone: map[string][]string{"example.com": {"v=spf1 -all"}}}
	r := newCachingResolver(upstream)
	for range 5 {
		records, err := r.LookupTXT(t.Context(), "example.com")
		if err != nil || len(records) != 1 {
			t.Fatalf("LookupTXT = %v, %v", records, err)
		}
	}
	if got := upstream.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1", got)
	}
}

func TestCachedAnswerExpires(t *testing.T) {
	upstream := &fakeResolver{zone: map[string][]string{"example.com": {"v=spf1 -all"}}}
	r := newCachingResolver(upstream)
	now := time.Now()
	r.now = func() time.Time { return now }
	_, _ = r.LookupTXT(t.Context(), "example.com")
	now = now.Add(txtCacheTTL)
	_, _ = r.LookupTXT(t.Context(), "example.com")
	if got := upstream.queries.Load(); got != 2 {
		t.Errorf("upstream saw %d queries, want 2 once the answer expired", got)
	}
}

// TestMissingRecordIsCachedButFailureIsNot: "no such record" is an answer and
// can be remembered; a timeout is not, and remembering it would turn one slow
// moment into a minute of temperrors.
func TestMissingRecordIsCachedButFailureIsNot(t *testing.T) {
	upstream := &fakeResolver{}
	r := newCachingResolver(upstream)
	for range 3 {
		if _, err := r.LookupTXT(t.Context(), "_dmarc.nowhere.example"); !isNotFound(err) {
			t.Fatalf("err = %v, want not found", err)
		}
	}
	if got := upstream.queries.Load(); got != 1 {
		t.Errorf("not-found was asked %d times, want 1", got)
	}

	failing := &fakeResolver{err: &net.DNSError{Err: "server misbehaving", Name: "x", IsTemporary: true}}
	r = newCachingResolver(failing)
	for range 3 {
		_, _ = r.LookupTXT(t.Context(), "example.com")
	}
	if got := failing.queries.Load(); got != 3 {
		t.Errorf("a failed lookup was asked %d times, want 3 (never cached)", got)
	}
}

// TestConcurrentLookupsShareOneQuery is the burst case: fifty sessions reach
// end-of-DATA together and all want the same record.
func TestConcurrentLookupsShareOneQuery(t *testing.T) {
	upstream := &fakeResolver{
		zone:    map[string][]string{"example.com": {"v=spf1 -all"}},
		release: make(chan struct{}),
	}
	r := newCachingResolver(upstream)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Go(func() {
			if _, err := r.LookupTXT(t.Context(), "example.com"); err != nil {
				errs <- err
			}
		})
	}
	// Give every caller time to join the in-flight lookup before it answers.
	time.Sleep(50 * time.Millisecond)
	close(upstream.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := upstream.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1", got)
	}
}

// TestCallerStopsWaitingAtItsOwnDeadline: a shared lookup must not hold a
// caller past its own deadline, nor be cancelled because one caller left.
func TestCallerStopsWaitingAtItsOwnDeadline(t *testing.T) {
	upstream := &fakeResolver{
		zone:    map[string][]string{"example.com": {"v=spf1 -all"}},
		release: make(chan struct{}),
	}
	r := newCachingResolver(upstream)

	short, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.LookupTXT(short, "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("caller waited %v past its deadline", elapsed)
	}

	// The lookup the first caller started is still running; a second caller
	// joins it and gets the answer once it arrives.
	close(upstream.release)
	if records, err := r.LookupTXT(t.Context(), "example.com"); err != nil || len(records) != 1 {
		t.Fatalf("second caller got %v, %v", records, err)
	}
}
