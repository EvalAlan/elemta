package webmail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValkeyPendingLoginAcrossReplicas(t *testing.T) {
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
	manager, err := NewSharedSessionManager(time.Hour, make([]byte, 32), v)
	if err != nil {
		t.Fatal(err)
	}
	a := pendingLogins{shared: v, aead: manager.aead}
	b := pendingLogins{shared: v, aead: manager.aead}
	token, err := a.put("dana", "secret-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := v.pendingGet(context.Background(), token)
	if err != nil || bytes.Contains(sealed, []byte("secret-password")) {
		t.Fatal("pending credential was not sealed")
	}
	got, ok := b.get(token, time.Now())
	if !ok || got.user != "dana" || got.password != "secret-password" {
		t.Fatal("second replica could not load pending login")
	}
	for range maxPendingAttempt - 1 {
		if !b.fail(token) {
			t.Fatal("pending login expired early")
		}
	}
	if a.fail(token) {
		t.Fatal("attempt limit was not shared")
	}
	if _, ok := b.get(token, time.Now()); ok {
		t.Fatal("attempt limit retained pending login")
	}
	token, err = a.put("dana", "secret-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !b.drop(token) || a.drop(token) {
		t.Fatal("pending login was not consumed once")
	}
	if err := v.pendingPut(context.Background(), "expires", []byte("opaque"), 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if data, err := v.pendingGet(context.Background(), "expires"); err != nil || data != nil {
		t.Fatal("pending login survived expiry")
	}
}

func TestValkeySessionRefreshesRealExpiry(t *testing.T) {
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
	key := make([]byte, 32)
	a, err := NewSharedSessionManager(2*time.Second, key, v)
	if err != nil {
		t.Fatal(err)
	}
	a.touchInterval = 500 * time.Millisecond
	b, err := NewSharedSessionManager(2*time.Second, key, v)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := a.Create("dana", "dana@example.com", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy(sess.ID)
	time.Sleep(1100 * time.Millisecond)
	if _, ok := a.Get(sess.ID); !ok {
		t.Fatal("touch failed")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := b.Get(sess.ID); !ok {
		t.Fatal("renewed session expired at original Valkey TTL")
	}
	old := sess.record()
	old.LastSeen = old.LastSeen.Add(-time.Minute)
	old.SeenNanos = "1"
	if err := v.Save(context.Background(), old, time.Minute); err != nil {
		t.Fatal(err)
	}
	stored, err := v.Load(context.Background(), sess.ID)
	if err != nil || stored == nil || stored.LastSeen.Equal(old.LastSeen) {
		t.Fatal("stale replica replaced newer session record")
	}
}

func TestValkeyDAVWriteLockAcrossReplicas(t *testing.T) {
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
	owner := "object-test-" + suffix
	base := newFakeStore()
	if err := base.PutObject(context.Background(), CollCalendar, Object{ID: "event", Data: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	one := coordinatedMailstore{Mailstore: base, owner: owner, coord: &objectCoordinator{valkey: v}}
	two := coordinatedMailstore{Mailstore: base, owner: owner, coord: &objectCoordinator{valkey: v}}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, st := range []coordinatedMailstore{one, two} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.DAVTransaction(context.Background(), CollCalendar, func(store ObjectStore) error {
				objects, err := store.Objects(context.Background(), CollCalendar)
				if err != nil {
					return err
				}
				if string(objects[0].Data) != "old" {
					return errors.New("stale version")
				}
				time.Sleep(30 * time.Millisecond)
				return store.PutObject(context.Background(), CollCalendar, Object{ID: "event", Data: []byte("new")})
			})
			results <- err == nil
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("conditional write successes: %d", winners)
	}
}

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
