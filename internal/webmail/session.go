package webmail

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Session is one signed-in browser.
//
// The IMAP password has to be kept for the life of the session, because IMAP
// has no token login Dovecot will accept by default. It is held only in this
// process's memory, sealed under a key generated at startup, so a heap dump,
// a log line or a stray %v doesn't print it, and a restart invalidates every
// session. Moving sessions to Valkey for multi-pod deployments will need a
// shared key from a secret; until then a webmail pod's sessions are its own.
type Session struct {
	ID       string
	CSRF     string
	User     string // login name as typed, used for IMAP and submission AUTH
	Address  string // mailbox address the user sends as
	sealed   []byte
	nonce    []byte
	created  time.Time
	lastSeen time.Time

	// mu serialises IMAP use: one request at a time per session, because the
	// selected mailbox is connection state.
	mu    sync.Mutex
	store Mailstore

	// prefs caches the user's settings, read once per session.
	prefsMu sync.Mutex
	prefs   *Settings
}

// SessionManager creates, finds and expires sessions.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	aead     cipher.AEAD
	ttl      time.Duration
	now      func() time.Time
}

// NewSessionManager returns a manager whose sessions expire after ttl idle.
func NewSessionManager(ttl time.Duration) (*SessionManager, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("webmail: session key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("webmail: session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("webmail: session cipher: %w", err)
	}
	return &SessionManager{sessions: make(map[string]*Session), aead: aead, ttl: ttl, now: time.Now}, nil
}

// randomToken returns n random bytes, URL-safe base64 encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create starts a session for a user whose password has already been
// checked against the mail store.
func (m *SessionManager) Create(user, address, password string, store Mailstore) (*Session, error) {
	id, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("webmail: session id: %w", err)
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("webmail: csrf token: %w", err)
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("webmail: session nonce: %w", err)
	}
	now := m.now()
	s := &Session{
		ID: id, CSRF: csrf, User: user, Address: address,
		// The session ID is the additional data, so a sealed password
		// copied into another session won't open.
		sealed: m.aead.Seal(nil, nonce, []byte(password), []byte(id)),
		nonce:  nonce, created: now, lastSeen: now, store: store,
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Get returns the live session with id and extends its idle timer.
func (m *SessionManager) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	now := m.now()
	if now.Sub(s.lastSeen) > m.ttl {
		delete(m.sessions, id)
		go s.closeStore()
		return nil, false
	}
	s.lastSeen = now
	return s, true
}

// Destroy ends a session and closes its IMAP connection.
func (m *SessionManager) Destroy(id string) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if ok {
		s.closeStore()
	}
}

// Sweep removes expired sessions. Run it periodically.
func (m *SessionManager) Sweep() int {
	now := m.now()
	var expired []*Session
	m.mu.Lock()
	for id, s := range m.sessions {
		if now.Sub(s.lastSeen) > m.ttl {
			expired = append(expired, s)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
	for _, s := range expired {
		s.closeStore()
	}
	return len(expired)
}

// Run sweeps expired sessions until ctx ends, then closes every session.
func (m *SessionManager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			all := m.sessions
			m.sessions = make(map[string]*Session)
			m.mu.Unlock()
			for _, s := range all {
				s.closeStore()
			}
			return
		case <-t.C:
			m.Sweep()
		}
	}
}

func (m *SessionManager) password(s *Session) (string, error) {
	pw, err := m.aead.Open(nil, s.nonce, s.sealed, []byte(s.ID))
	if err != nil {
		return "", errors.New("webmail: session credentials unreadable")
	}
	return string(pw), nil
}

// CheckCSRF reports whether token matches the session's CSRF token.
func (s *Session) CheckCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

func (s *Session) closeStore() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		_ = s.store.Close()
		s.store = nil
	}
}

// withStore runs fn with the session's IMAP connection, dialling one if the
// session has none. If fn fails on a connection that has died (Dovecot
// restarted, an idle timeout), it redials once and retries, so a user doesn't
// see an error just because their connection went stale.
func (m *SessionManager) withStore(ctx context.Context, s *Session, dial Dialer, fn func(Mailstore) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if s.store == nil {
			pw, err := m.password(s)
			if err != nil {
				return err
			}
			st, err := dial(ctx, s.User, pw)
			if err != nil {
				return err
			}
			s.store = st
		}
		err := fn(s.store)
		if err == nil || attempt > 0 || !isConnError(err) {
			return err
		}
		_ = s.store.Close()
		s.store = nil
	}
}
