package auth

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// memBackend is a shared backend two managers can use, as two dashboard
// instances would use Valkey.
type memBackend struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func (m *memBackend) Save(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionKey(s.ID)] = *s
	return nil
}

func (m *memBackend) Load(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionKey(id)]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *memBackend) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionKey(id))
	return nil
}

func (m *memBackend) DeleteUser(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, s := range m.sessions {
		if s.Username == username {
			delete(m.sessions, k)
			n++
		}
	}
	return n, nil
}

func TestSharedSessionsAcrossInstances(t *testing.T) {
	shared := &memBackend{sessions: map[string]Session{}}
	a := NewSessionManager(SessionConfig{MaxAge: time.Hour})
	b := NewSessionManager(SessionConfig{MaxAge: time.Hour})
	a.SetBackend(shared)
	b.SetBackend(shared)

	s, err := a.CreateSession("admin", "test", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.ValidateSession(s.ID); err != nil || got.Username != "admin" {
		t.Fatalf("the other instance doesn't know the session: %v %v", got, err)
	}
	for k := range shared.sessions {
		if k == s.ID {
			t.Fatal("the session ID itself is stored as the key")
		}
	}
	if err := b.RevokeSession(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(s.ID); err == nil {
		t.Error("signing out on one instance didn't hold on the other")
	}

	s1, _ := a.CreateSession("dana", "test", "192.0.2.1")
	s2, _ := b.CreateSession("dana", "test", "192.0.2.2")
	if n := a.RevokeUserSessions("dana"); n != 2 {
		t.Errorf("revoked %d sessions, want 2", n)
	}
	for _, id := range []string{s1.ID, s2.ID} {
		if _, err := b.ValidateSession(id); err == nil {
			t.Error("a revoked user's session still validates")
		}
	}
}

func TestValkeySessionBackend(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY")
	if addr == "" {
		t.Skip("set ELEMTA_TEST_VALKEY for real Valkey integration")
	}
	backend, err := NewValkeySessionBackend(addr)
	if err != nil {
		t.Fatal(err)
	}
	a := NewSessionManager(SessionConfig{MaxAge: time.Hour})
	b := NewSessionManager(SessionConfig{MaxAge: time.Hour})
	a.SetBackend(backend)
	b.SetBackend(backend)
	user := "valkey-test-" + time.Now().Format("150405.000000")
	s, err := a.CreateSession(user, "test", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.ValidateSession(s.ID); err != nil || got.Username != user {
		t.Fatalf("validate on the other instance: %v %v", got, err)
	}
	if n := b.RevokeUserSessions(user); n != 1 {
		t.Errorf("revoked %d, want 1", n)
	}
	if _, err := a.ValidateSession(s.ID); err == nil {
		t.Error("a revoked session still validates")
	}
}
