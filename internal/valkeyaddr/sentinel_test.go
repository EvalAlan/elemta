package valkeyaddr

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// TestSentinelFailover needs a Sentinel watching a primary with one replica,
// set as ELEMTA_TEST_VALKEY_SENTINEL (for example
// valkey://127.0.0.1:26379?master_set=elemta). It forces a failover and
// checks the same client keeps writing to whichever server is primary.
func TestSentinelFailover(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY_SENTINEL")
	if addr == "" {
		t.Skip("ELEMTA_TEST_VALKEY_SENTINEL not set")
	}
	client, err := NewClient(addr, func(o *valkey.ClientOption) { o.DisableCache = true })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := client.Do(ctx, client.B().Set().Key("elemta:test:failover").Value("before").Build()).Error(); err != nil {
		t.Fatalf("write before failover: %v", err)
	}
	opt, _ := Options(addr)
	sentinel, err := valkey.NewClient(valkey.ClientOption{InitAddress: opt.InitAddress[:1], DisableCache: true, ForceSingleClient: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()
	primary := func() string {
		addr, err := sentinel.Do(ctx, sentinel.B().Arbitrary("SENTINEL", "GET-MASTER-ADDR-BY-NAME", opt.Sentinel.MasterSet).Build()).AsStrSlice()
		if err != nil {
			t.Fatalf("ask Sentinel for the primary: %v", err)
		}
		return strings.Join(addr, ":")
	}
	before := primary()
	if err := sentinel.Do(ctx, sentinel.B().Arbitrary("SENTINEL", "FAILOVER", opt.Sentinel.MasterSet).Build()).Error(); err != nil {
		t.Fatalf("SENTINEL FAILOVER: %v", err)
	}
	// FAILOVER returns before the promotion; wait for it to happen.
	deadline := time.Now().Add(30 * time.Second)
	for primary() == before {
		if time.Now().After(deadline) {
			t.Fatalf("Sentinel still reports %s as primary", before)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Writes fail briefly while the old primary is demoted; the client
	// must reconnect to the new one on its own.
	for {
		err = client.Do(ctx, client.B().Set().Key("elemta:test:failover").Value("after").Build()).Error()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no write after failover: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	got, err := client.Do(ctx, client.B().Get().Key("elemta:test:failover").Build()).ToString()
	if err != nil || got != "after" {
		t.Fatalf("read after failover = %q, %v", got, err)
	}
}
