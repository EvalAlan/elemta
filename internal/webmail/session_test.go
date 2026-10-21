package webmail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	m, err := NewSessionManager(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	s, err := m.Create("dana", "dana@example.com", "hunter2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ID) < 40 || s.CSRF == "" || s.ID == s.CSRF {
		t.Fatalf("weak session tokens: id=%q csrf=%q", s.ID, s.CSRF)
	}
	if pw, err := m.password(s); err != nil || pw != "hunter2" {
		t.Fatalf("password = %q, %v", pw, err)
	}
	if string(s.sealed) == "hunter2" {
		t.Fatal("password stored in clear")
	}
	if !s.CheckCSRF(s.CSRF) || s.CheckCSRF("") || s.CheckCSRF("nope") {
		t.Fatal("CSRF check wrong")
	}

	// Activity extends the idle timer.
	now = now.Add(50 * time.Minute)
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("session expired early")
	}
	now = now.Add(50 * time.Minute)
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("activity did not extend the session")
	}
	now = now.Add(61 * time.Minute)
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("idle session still valid")
	}

	s2, _ := m.Create("marcus", "marcus@example.com", "pw", nil)
	now = now.Add(2 * time.Hour)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	if _, ok := m.Get(s2.ID); ok {
		t.Fatal("swept session still valid")
	}
}

func TestAdministratorSessionEndsAtTokenExpiry(t *testing.T) {
	m, err := NewSessionManager(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	expires := now.Add(time.Hour)
	s, err := m.CreateAdmin("dana@example.com", "dana@example.com", "token", nil, "admin", expires)
	if err != nil {
		t.Fatal(err)
	}
	if s.AdminActor != "admin" || !s.AdminExpires.Equal(expires) {
		t.Fatalf("administrator session lost its scope: %+v", s)
	}
	now = expires.Add(-time.Second)
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("administrator session ended before the token")
	}
	now = expires
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("administrator session survived token expiry")
	}
	if _, err := m.CreateAdmin("dana@example.com", "dana@example.com", "token", nil, "admin", expires); err == nil {
		t.Fatal("expired token created a session")
	}
}

func TestAdministratorMailRouteScope(t *testing.T) {
	for _, path := range []string{"/mail", "/mail/body", "/mail/action", "/folders", "/api/counts", "/logout"} {
		if !adminMailRoute(path) {
			t.Errorf("administrator mail route %s refused", path)
		}
	}
	for _, path := range []string{"/mail/switch", "/compose", "/calendar", "/settings", "/contacts", "/api/addresses"} {
		if adminMailRoute(path) {
			t.Errorf("administrator non-mail route %s allowed", path)
		}
	}
}

func TestSealedPasswordIsBoundToSession(t *testing.T) {
	m, _ := NewSessionManager(time.Hour)
	a, _ := m.Create("a", "a@example.com", "pw-a", nil)
	b, _ := m.Create("b", "b@example.com", "pw-b", nil)
	b.sealed, b.nonce = a.sealed, a.nonce
	if _, err := m.password(b); err == nil {
		t.Fatal("a sealed password opened under another session's ID")
	}
}

// countingStore fails its first call with a dead-connection error.
type countingStore struct {
	fakeStore
	failFirst bool
	calls     int
	closed    bool
}

func (c *countingStore) Close() error { c.closed = true; return nil }

func TestWithStoreRedialsDeadConnection(t *testing.T) {
	m, _ := NewSessionManager(time.Hour)
	stale := &countingStore{}
	s, _ := m.Create("dana", "dana@example.com", "pw", stale)
	dials := 0
	fresh := &countingStore{}
	dial := func(ctx context.Context, user, pw string) (Mailstore, error) {
		dials++
		if pw != "pw" {
			t.Errorf("dialled with password %q", pw)
		}
		return fresh, nil
	}
	err := m.withStore(context.Background(), s, dial, func(st Mailstore) error {
		if st == stale {
			return io.EOF
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withStore = %v", err)
	}
	if dials != 1 || !stale.closed || s.store != fresh {
		t.Fatalf("dials=%d staleClosed=%v", dials, stale.closed)
	}

	// A command failure on a healthy connection is returned, not retried.
	err = m.withStore(context.Background(), s, dial, func(st Mailstore) error { return ErrNotFound })
	if !errors.Is(err, ErrNotFound) || dials != 1 {
		t.Fatalf("err=%v dials=%d", err, dials)
	}
}

func TestSharedMailboxSelectionKeepsPersonalStore(t *testing.T) {
	shared := &memSessions{recs: map[string]SessionRecord{}}
	key := make([]byte, 32)
	m, err := NewSharedSessionManager(time.Hour, key, shared)
	if err != nil {
		t.Fatal(err)
	}
	personal := &countingStore{}
	s, err := m.Create("dana@example.com", "dana@example.com", "own-password", personal)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetMailbox(context.Background(), s, "support@example.com"); err != nil {
		t.Fatal(err)
	}
	var dialed string
	temporary := &countingStore{}
	dial := func(_ context.Context, user, password string) (Mailstore, error) {
		dialed = user
		if password != "own-password" {
			t.Errorf("shared mailbox used another password")
		}
		return temporary, nil
	}
	if err := m.withMailStore(context.Background(), s, dial, func(st Mailstore) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialed != "dana@example.com|support@example.com" || !temporary.closed || personal.closed {
		t.Fatalf("shared connection = %q, closed %v; personal closed %v", dialed, temporary.closed, personal.closed)
	}
	other, err := NewSharedSessionManager(time.Hour, key, shared)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := other.Get(s.ID)
	if !ok || other.MailAddress(restored) != "support@example.com" {
		t.Fatal("shared mailbox selection did not survive session reload")
	}
	if err := m.SetMailbox(context.Background(), s, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.withMailStore(context.Background(), s, dial, func(st Mailstore) error {
		if st != personal {
			t.Fatal("personal store not restored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// memSessions is an in-memory SessionStore standing in for Valkey.
type memSessions struct {
	mu   sync.Mutex
	recs map[string]SessionRecord
}

type expiringSessions struct {
	mu      sync.Mutex
	now     func() time.Time
	recs    map[string]SessionRecord
	expires map[string]time.Time
}

func (m *expiringSessions) Load(_ context.Context, id string) (*SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.now().Before(m.expires[id]) {
		delete(m.recs, id)
		return nil, nil
	}
	rec := m.recs[id]
	return &rec, nil
}
func (m *expiringSessions) Save(_ context.Context, rec *SessionRecord, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[rec.ID] = *rec
	m.expires[rec.ID] = m.now().Add(ttl)
	return nil
}
func (m *expiringSessions) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.recs, id)
	delete(m.expires, id)
	return nil
}

func TestFrequentActivityRenewsSharedSession(t *testing.T) {
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	store := &expiringSessions{now: func() time.Time { return now }, recs: map[string]SessionRecord{}, expires: map[string]time.Time{}}
	m, err := NewSharedSessionManager(2*time.Minute, make([]byte, 32), store)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	s, err := m.Create("dana", "dana@example.com", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		now = now.Add(30 * time.Second)
		if _, ok := m.Get(s.ID); !ok {
			t.Fatalf("active session expired after %s", time.Duration(i+1)*30*time.Second)
		}
	}
	if stored, err := store.Load(context.Background(), s.ID); err != nil || stored == nil || !stored.LastSeen.After(s.created) {
		t.Fatalf("shared session was not renewed: %+v %v", stored, err)
	}
}

func (m *memSessions) Load(_ context.Context, id string) (*SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[id]
	if !ok {
		return nil, nil
	}
	return &r, nil
}
func (m *memSessions) Save(_ context.Context, r *SessionRecord, _ time.Duration) error {
	m.mu.Lock()
	m.recs[r.ID] = *r
	m.mu.Unlock()
	return nil
}
func (m *memSessions) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.recs, id)
	m.mu.Unlock()
	return nil
}

func TestSharedSessionsSurviveRestart(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 7
	store := &memSessions{recs: map[string]SessionRecord{}}
	a, err := NewSharedSessionManager(time.Hour, key, store)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Create("dana", "dana@example.com", "s3cret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(store.recs), "s3cret") {
		t.Fatal("password stored unsealed")
	}

	// A second pod (or this one after a restart) with the same key finds it.
	b, _ := NewSharedSessionManager(time.Hour, key, store)
	got, ok := b.Get(s.ID)
	if !ok || got.User != "dana" || got.CSRF != s.CSRF {
		t.Fatalf("other pod: ok=%v %+v", ok, got)
	}
	if pw, err := b.password(got); err != nil || pw != "s3cret" {
		t.Fatalf("password = %q, %v", pw, err)
	}

	// A pod with a different key can't open it.
	other := make([]byte, 32)
	c, _ := NewSharedSessionManager(time.Hour, other, store)
	if got, ok := c.Get(s.ID); ok {
		if _, err := c.password(got); err == nil {
			t.Fatal("password opened with the wrong key")
		}
	}

	// Signing out on one pod signs out everywhere.
	b.Destroy(s.ID)
	a2, _ := NewSharedSessionManager(time.Hour, key, store)
	if _, ok := a2.Get(s.ID); ok {
		t.Fatal("session survived sign-out")
	}
}

func TestLoadSessionKeyCreatesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "webmail.key")
	k1, err := loadSessionKey(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v", info.Mode())
	}
	k2, err := loadSessionKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("key changed on second load")
	}
	_ = os.WriteFile(path, []byte("short"), 0o600)
	if _, err := loadSessionKey(path); err == nil {
		t.Fatal("bad key accepted")
	}
}
