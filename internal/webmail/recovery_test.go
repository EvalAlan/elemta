package webmail

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type recoveryValue struct {
	value   string
	expires time.Time
}
type memoryRecovery struct {
	mu      sync.Mutex
	entries map[string]recoveryValue
	now     time.Time
}

func newMemoryRecovery() *memoryRecovery {
	return &memoryRecovery{entries: map[string]recoveryValue{}, now: time.Now()}
}
func (m *memoryRecovery) live(key string) string {
	v := m.entries[key]
	if !v.expires.IsZero() && !m.now.Before(v.expires) {
		delete(m.entries, key)
		return ""
	}
	return v.value
}
func (m *memoryRecovery) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live(key), nil
}
func (m *memoryRecovery) Put(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := recoveryValue{value: value}
	if ttl > 0 {
		v.expires = m.now.Add(ttl)
	}
	m.entries[key] = v
	return nil
}
func (m *memoryRecovery) Take(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.live(key)
	delete(m.entries, key)
	return v, nil
}
func (m *memoryRecovery) Claim(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live(key) != "" {
		return false, nil
	}
	m.entries[key] = recoveryValue{value, m.now.Add(ttl)}
	return true, nil
}

type fakeResetter struct {
	calls          int
	user, password string
	err            error
}

func (f *fakeResetter) ResetPassword(_ context.Context, user, next string) error {
	f.calls++
	f.user, f.password = user, next
	return f.err
}
func setupRecovery(t *testing.T) (*harness, *memoryRecovery, *fakeResetter) {
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 8)
	store := newMemoryRecovery()
	reset := &fakeResetter{}
	h.server.recovery = store
	h.server.resetter = reset
	h.server.passwords = &fakePasswords{}
	h.server.cfg.RecoveryURL = "https://mail.example.com"
	h.server.cfg.RecoverySender = "no-reply@example.com"
	h.server.cfg.RecoverySMTPUser = "recovery-service"
	return h, store, reset
}
func recoveryCSRF(t *testing.T, h *harness, path string) string {
	t.Helper()
	r, page := h.get(path)
	if r.StatusCode != 200 {
		t.Fatalf("GET %s: %d", path, r.StatusCode)
	}
	m := hiddenRE("csrf").FindStringSubmatch(page)
	if m == nil {
		t.Fatal("missing csrf")
	}
	return m[1]
}
func recoveryMailToken(t *testing.T, h *harness) string {
	t.Helper()
	select {
	case <-h.sub.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("email delivery timed out")
	}
	message, err := parseMessage(h.sub.raw)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(message.Text)
	if m == nil {
		t.Fatal("missing link in email")
	}
	return string(m[1])
}
func redeem(t *testing.T, h *harness, purpose, token string) *http.Response {
	t.Helper()
	path := "/" + purpose
	csrf := recoveryCSRF(t, h, path+"?token="+token)
	return h.post(path, url.Values{"csrf": {csrf}, "token": {token}, "new": {"a strong random passphrase"}, "confirm": {"a strong random passphrase"}})
}

func TestRecoveryEnrollmentAndReset(t *testing.T) {
	h, store, reset := setupRecovery(t)
	csrf := h.login()
	if r := h.post("/settings/recovery", url.Values{"csrf": {csrf}, "current": {"wrong"}, "email": {"backup@elsewhere.example"}}); r.StatusCode != 403 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	if r := h.post("/settings/recovery", url.Values{"csrf": {csrf}, "current": {"secret"}, "email": {"backup@elsewhere.example"}}); r.StatusCode != 303 {
		t.Fatalf("enroll: %d", r.StatusCode)
	}
	verify := recoveryMailToken(t, h)
	rec, _ := h.server.recoveryRecord(context.Background(), "dana@example.com")
	if rec.Email != "" {
		t.Fatal("unverified address became active")
	}
	// A scanner's GET cannot activate the address or consume the link.
	recoveryCSRF(t, h, "/verify-recovery?token="+verify)
	if r := redeem(t, h, "verify-recovery", verify); r.StatusCode != 303 {
		t.Fatalf("verify: %d", r.StatusCode)
	}
	if r := redeem(t, h, "verify-recovery", verify); r.StatusCode != 400 {
		t.Fatalf("verify replay: %d", r.StatusCode)
	}
	h.sub.raw = nil
	token := recoveryCSRF(t, h, "/forgot-password")
	if r := h.post("/forgot-password", url.Values{"csrf": {token}, "user": {"DANA@example.com"}}); r.StatusCode != 200 {
		t.Fatalf("forgot: %d", r.StatusCode)
	}
	link := recoveryMailToken(t, h)
	if len(h.sub.rcpts) != 1 || h.sub.rcpts[0] != "backup@elsewhere.example" {
		t.Fatal("wrong reset recipient")
	}
	// Only a digest of the bearer token is stored.
	for key, value := range store.entries {
		if strings.Contains(key, link) || strings.Contains(value.value, link) {
			t.Fatal("plaintext token stored")
		}
	}
	if r := redeem(t, h, "reset-password", link); r.StatusCode != 303 {
		t.Fatalf("reset: %d", r.StatusCode)
	}
	if reset.calls != 1 || reset.user != "dana@example.com" || reset.password != "a strong random passphrase" {
		t.Fatalf("reset result: %+v", reset)
	}
	if r, _ := h.get("/mail"); r.StatusCode != 302 {
		t.Fatalf("old session survived reset: %d", r.StatusCode)
	}
	if r := redeem(t, h, "reset-password", link); r.StatusCode != 400 {
		t.Fatalf("reset replay: %d", r.StatusCode)
	}
	if reset.calls != 1 {
		t.Fatal("replay changed password")
	}
}

func TestRecoveryExpiredAndSupersededLinks(t *testing.T) {
	h, store, reset := setupRecovery(t)
	ctx := context.Background()
	if err := h.server.saveRecovery(ctx, "dana@example.com", recoveryAddress{Email: "backup@elsewhere.example", Version: "v1"}); err != nil {
		t.Fatal(err)
	}
	makeToken := func() string {
		token, err := h.server.issueRecovery(ctx, recoveryToken{User: "dana@example.com", Address: "dana@example.com", Email: "backup@elsewhere.example", Version: "v1", Purpose: "reset"})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	expired := makeToken()
	store.now = store.now.Add(recoveryTTL + time.Second)
	if r := redeem(t, h, "reset-password", expired); r.StatusCode != 400 {
		t.Fatalf("expired: %d", r.StatusCode)
	}
	old, newer := makeToken(), makeToken()
	if r := redeem(t, h, "reset-password", newer); r.StatusCode != 303 {
		t.Fatalf("valid: %d", r.StatusCode)
	}
	if r := redeem(t, h, "reset-password", old); r.StatusCode != 400 {
		t.Fatalf("superseded: %d", r.StatusCode)
	}
	if reset.calls != 1 {
		t.Fatalf("resets: %d", reset.calls)
	}
}

func TestRecoveryRemoveInvalidatesPendingVerification(t *testing.T) {
	h, _, _ := setupRecovery(t)
	csrf := h.login()
	form := url.Values{"csrf": {csrf}, "current": {"secret"}, "email": {"backup@elsewhere.example"}}
	if r := h.post("/settings/recovery", form); r.StatusCode != 303 {
		t.Fatal(r.StatusCode)
	}
	pending := recoveryMailToken(t, h)
	form.Set("email", "")
	if r := h.post("/settings/recovery", form); r.StatusCode != 303 {
		t.Fatal(r.StatusCode)
	}
	if r := redeem(t, h, "verify-recovery", pending); r.StatusCode != 400 {
		t.Fatalf("removed address reactivated: %d", r.StatusCode)
	}
}

func TestRecoveryCSRFAndGenericResponse(t *testing.T) {
	h, _, reset := setupRecovery(t)
	if r := h.post("/forgot-password", url.Values{"user": {"nobody@example.com"}}); r.StatusCode != 403 {
		t.Fatal(r.StatusCode)
	}
	csrf := recoveryCSRF(t, h, "/forgot-password")
	r := h.post("/forgot-password", url.Values{"csrf": {csrf}, "user": {"nobody@example.com"}})
	if r.StatusCode != 200 || reset.calls != 0 || len(h.sub.raw) != 0 {
		t.Fatal("unknown user response")
	}
	csrf = h.login()
	if r := h.post("/settings/recovery", url.Values{"csrf": {csrf}, "current": {"secret"}, "email": {"DANA@example.com"}}); r.StatusCode != 400 {
		t.Fatal("accepted mailbox as recovery")
	}
}

func TestRecoveryDirectoryFailureConsumesLinks(t *testing.T) {
	h, _, reset := setupRecovery(t)
	ctx := context.Background()
	reset.err = errPolicyRejected
	if err := h.server.saveRecovery(ctx, "dana@example.com", recoveryAddress{Email: "backup@elsewhere.example", Version: "v"}); err != nil {
		t.Fatal(err)
	}
	token, err := h.server.issueRecovery(ctx, recoveryToken{User: "dana@example.com", Address: "dana@example.com", Email: "backup@elsewhere.example", Version: "v", Purpose: "reset"})
	if err != nil {
		t.Fatal(err)
	}
	if r := redeem(t, h, "reset-password", token); r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
	reset.err = errors.New("directory offline")
	if r := redeem(t, h, "reset-password", token); r.StatusCode != 400 || reset.calls != 1 {
		t.Fatal("failed reset link reused")
	}
}

func TestAdminRevocationPreservesOrClearsRecoveryOwnership(t *testing.T) {
	for _, remove := range []bool{false, true} {
		h, store, _ := setupRecovery(t)
		h.login()
		ctx := context.Background()
		err := h.server.saveRecovery(ctx, "dana@example.com", recoveryAddress{Email: "backup@elsewhere.example", Version: "before"})
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Put(ctx, "pending:"+accountKey("dana@example.com"), "pending", recoveryTTL); err != nil {
			t.Fatal(err)
		}
		if remove {
			err = h.server.AdminRemoveAccount(ctx, "dana@example.com")
		} else {
			err = h.server.AdminRevokeAccount(ctx, "dana@example.com")
		}
		if err != nil {
			t.Fatal(err)
		}
		rec, err := h.server.recoveryRecord(ctx, "dana@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Version == "before" {
			t.Fatal("old reset links remain valid")
		}
		if remove && rec.Email != "" {
			t.Fatal("removed address retained recovery ownership")
		}
		if !remove && rec.Email != "backup@elsewhere.example" {
			t.Fatal("disabled account lost recovery email")
		}
		pending, err := store.Get(ctx, "pending:"+accountKey("dana@example.com"))
		if err != nil || pending != "" {
			t.Fatal("pending verification survived revocation")
		}
		if response, _ := h.get("/mail"); response.StatusCode != http.StatusFound {
			t.Fatal("old session survived revocation")
		}
	}
}
