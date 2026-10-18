package webmail

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValkeyRecoveryAndRevocation(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY")
	if addr == "" {
		t.Skip("set ELEMTA_TEST_VALKEY for real Valkey integration")
	}
	shared, err := NewValkeySessionStore(addr)
	if err != nil {
		t.Fatal(err)
	}
	v := shared.(*valkeySessions)
	defer v.client.Close()
	suffix, err := randomToken(16)
	if err != nil {
		t.Fatal(err)
	}
	v.prefix += "test:" + suffix + ":"
	ctx := context.Background()
	key := make([]byte, 32)
	a, err := NewSharedSessionManager(time.Hour, key, v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSharedSessionManager(time.Hour, key, v)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := a.Create("dana", "dana@example.com", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy(sess.ID)
	if _, ok := b.Get(sess.ID); !ok {
		t.Fatal("second instance could not load session")
	}
	if err := a.RevokeUser(ctx, "dana@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Get(sess.ID); ok {
		t.Fatal("cached session survived account reset")
	}
	fresh, err := b.Create("dana", "dana@example.com", "new secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy(fresh.ID)
	if _, ok := a.Get(fresh.ID); !ok {
		t.Fatal("new session rejected after reset")
	}
	defer func() {
		_ = v.client.Do(ctx, v.client.B().Del().Key(v.prefix+"revoked:"+accountKey("dana@example.com")).Build()).Error()
	}()
	recovery := valkeyRecovery{client: v.client}
	token := "test:" + suffix
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			ok, err := recovery.Claim(ctx, token, "claimed", time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("atomic claim winners: %d", winners.Load())
	}
	value, err := recovery.Take(ctx, token)
	if err != nil || value != "claimed" {
		t.Fatalf("take: %q %v", value, err)
	}
	value, err = recovery.Take(ctx, token)
	if err != nil || value != "" {
		t.Fatal("consumed token survived")
	}
}
