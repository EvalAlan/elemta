package abuse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAlertEmailIsValidated(t *testing.T) {
	p := DefaultPolicy()
	p.AlertEmail = []string{"security@example.com", "ops@example.org"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"nobody"}, {"a@b"}, {"a b@example.com"}, {"<a@example.com>"}, make([]string, 11)} {
		p.AlertEmail = bad
		if p.Validate() == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Notices queued on one service are sent by another, once each, at most
// noticesPerHour and then one saying there are more; one that fails to send
// waits for the next round.
func TestNoticesThroughValkey(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("ELEMTA_TEST_VALKEY_ADDR not set")
	}
	ctx := context.Background()
	p := DefaultPolicy()
	p.AlertEmail = []string{"security@example.com"}
	console, mta := New("admin", addr, nil), New("mta", addr, nil)
	for _, e := range []*Engine{console, mta} {
		if err := e.Publish(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	client := console.valkey()
	hour := keyNoticeBudget + fmt.Sprint(time.Now().Unix()/3600)
	_ = client.Do(ctx, client.B().Del().Key(keyNotices, hour).Build()).Error()
	t.Cleanup(func() { _ = client.Do(ctx, client.B().Del().Key(keyNotices, hour).Build()).Error() })

	account := fmt.Sprintf("notice-%d@example.com", time.Now().UnixNano())
	console.raise(ctx, Alert{Time: time.Now().UTC(), Account: account, Kind: AlertTravel, Address: "192.0.2.1", Service: "imap", Detail: "Paris, then Sydney."})

	failing := func(context.Context, []string, Notice) error { return errors.New("queue full") }
	mta.deliverQueued(ctx, failing)
	var sent []Notice
	var to []string
	mta.deliverQueued(ctx, func(_ context.Context, recipients []string, n Notice) error {
		to = recipients
		sent = append(sent, n)
		return nil
	})
	if len(sent) != 1 || !strings.Contains(sent[0].Subject, account) || !strings.Contains(sent[0].Body, "Paris, then Sydney.") || to[0] != "security@example.com" {
		t.Fatalf("sent %+v to %v", sent, to)
	}

	for i := 0; i < noticesPerHour+5; i++ {
		console.notify(ctx, fmt.Sprintf("n%d", i), "x")
	}
	sent = nil
	mta.deliverQueued(ctx, func(_ context.Context, _ []string, n Notice) error { sent = append(sent, n); return nil })
	// One was already used by the alert above.
	if len(sent) != noticesPerHour || sent[len(sent)-1].Subject != "More abuse alerts this hour" {
		t.Fatalf("sent %d, last %q", len(sent), sent[len(sent)-1].Subject)
	}
}

func TestNoticesNeedAnAddress(t *testing.T) {
	e := testEngine(t, DefaultPolicy())
	e.notify(context.Background(), "s", "b") // no Valkey, no address: nothing to do, nothing to panic over
	called := false
	e.deliverQueued(context.Background(), func(context.Context, []string, Notice) error { called = true; return nil })
	if called {
		t.Fatal("sent with no address and no Valkey")
	}
}
