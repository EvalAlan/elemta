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
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session is one signed-in browser.
//
// The IMAP password has to be kept for the life of the session, because IMAP
// has no token login Dovecot will accept by default. It is kept sealed
// (AES-GCM) so a heap dump, a log line or a stray %v doesn't print it.
//
// With the default memory store the key is generated at startup, sessions
// live in this process and a restart signs everyone out. With a shared
// store (Valkey) the sealed records are shared by every webmail pod and
// survive restarts; the sealing key then comes from a file the pods share
// and is never written to the store, so reading the store alone doesn't
// yield passwords.
type Session struct {
	ID            string
	CSRF          string
	User          string // login name as typed, used for IMAP and submission AUTH
	Address       string // mailbox address the user sends as
	Mailbox       string // another mailbox selected by this user, or empty for their own
	sealed        []byte
	nonce         []byte
	created       time.Time
	lastSeen      time.Time
	lastPersisted time.Time

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
	mu            sync.Mutex
	sessions      map[string]*Session // this process's sessions, with their connections
	aead          cipher.AEAD
	ttl           time.Duration
	now           func() time.Time
	touchInterval time.Duration
	// shared, when set, holds every session's record for all pods.
	shared SessionStore
}

// SessionStore keeps session records where every webmail pod can read
// them. Records expire on their own after the TTL they were saved with.
type SessionStore interface {
	Load(ctx context.Context, id string) (*SessionRecord, error) // nil, nil when absent
	Save(ctx context.Context, rec *SessionRecord, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
}

// SessionRecord is a session as stored: everything but the live IMAP
// connection, with the password still sealed.
type SessionRecord struct {
	ID        string    `json:"id"`
	CSRF      string    `json:"csrf"`
	User      string    `json:"user"`
	Address   string    `json:"address"`
	Mailbox   string    `json:"mailbox,omitempty"`
	Sealed    []byte    `json:"sealed"`
	Nonce     []byte    `json:"nonce"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	SeenNanos string    `json:"seen_ns,omitempty"`
}

// touchEvery is how often a request refreshes a shared session's expiry;
// refreshing on every request would cost a store write each time.
const touchEvery = time.Minute

// NewSessionManager returns a manager whose sessions expire after ttl idle,
// held in memory under a key generated now.
func NewSessionManager(ttl time.Duration) (*SessionManager, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("webmail: session key: %w", err)
	}
	return NewSharedSessionManager(ttl, key, nil)
}

// NewSharedSessionManager returns a manager that seals passwords with key
// and, if store is set, keeps sessions there for every pod to share.
func NewSharedSessionManager(ttl time.Duration, key []byte, store SessionStore) (*SessionManager, error) {
	if len(key) != 32 {
		return nil, errors.New("webmail: the session key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("webmail: session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("webmail: session cipher: %w", err)
	}
	interval := min(touchEvery, ttl/2)
	return &SessionManager{sessions: make(map[string]*Session), aead: aead, ttl: ttl, now: time.Now, touchInterval: interval, shared: store}, nil
}

func (s *Session) record() *SessionRecord {
	return &SessionRecord{ID: s.ID, CSRF: s.CSRF, User: s.User, Address: s.Address, Mailbox: s.Mailbox, Sealed: s.sealed, Nonce: s.nonce, Created: s.created, LastSeen: s.lastSeen, SeenNanos: strconv.FormatInt(s.lastSeen.UnixNano(), 10)}
}

func sessionFromRecord(r *SessionRecord) *Session {
	return &Session{ID: r.ID, CSRF: r.CSRF, User: r.User, Address: r.Address, Mailbox: r.Mailbox, sealed: r.Sealed, nonce: r.Nonce, created: r.Created, lastSeen: r.LastSeen, lastPersisted: r.LastSeen}
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
		nonce:  nonce, created: now, lastSeen: now, lastPersisted: now, store: store,
	}
	if m.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.shared.Save(ctx, s.record(), m.ttl); err != nil {
			return nil, fmt.Errorf("webmail: save session: %w", err)
		}
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Get returns the live session with id and extends its idle timer. With a
// shared store, a session this pod hasn't seen (signed in on another pod,
// or before a restart) is loaded from it; its IMAP connection is dialled
// when first needed.
func (m *SessionManager) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	var sharedRec *SessionRecord
	if ok && m.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rec, err := m.shared.Load(ctx, id)
		cancel()
		if err != nil {
			return nil, false
		}
		if rec == nil {
			m.Destroy(id)
			return nil, false
		}
		sharedRec = rec
	}
	if !ok && m.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rec, err := m.shared.Load(ctx, id)
		cancel()
		if err != nil || rec == nil || rec.ID != id {
			return nil, false
		}
		s = sessionFromRecord(rec)
		sharedRec = rec
		m.mu.Lock()
		if existing, raced := m.sessions[id]; raced {
			s = existing
		} else {
			m.sessions[id] = s
		}
		m.mu.Unlock()
		ok = true
	}
	if !ok {
		return nil, false
	}
	now := m.now()
	m.mu.Lock()
	expired := now.Sub(s.lastSeen) > m.ttl
	if sharedRec != nil && sharedRec.LastSeen.After(s.lastSeen) {
		s.lastSeen = sharedRec.LastSeen
		expired = now.Sub(s.lastSeen) > m.ttl
	}
	if sharedRec != nil && sharedRec.LastSeen.After(s.lastPersisted) {
		s.lastPersisted = sharedRec.LastSeen
	}
	if sharedRec != nil {
		s.Mailbox = sharedRec.Mailbox
	}
	m.mu.Unlock()
	m.mu.Lock()
	touch := m.shared != nil && now.Sub(s.lastPersisted) > m.touchInterval
	if expired {
		delete(m.sessions, id)
	} else {
		s.lastSeen = now
	}
	m.mu.Unlock()
	if expired {
		go s.closeStore()
		if m.shared != nil {
			go func() { _ = m.shared.Delete(context.Background(), id) }()
		}
		return nil, false
	}
	if touch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		m.mu.Lock()
		rec := s.record()
		m.mu.Unlock()
		err := m.shared.Save(ctx, rec, m.ttl)
		cancel()
		if err != nil {
			return nil, false
		}
		m.mu.Lock()
		if rec.LastSeen.After(s.lastPersisted) {
			s.lastPersisted = rec.LastSeen
		}
		m.mu.Unlock()
	}
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
	if m.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = m.shared.Delete(ctx, id)
		cancel()
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

// Run sweeps expired sessions until ctx ends, then closes every session's
// connection. Shared records are left in place: another pod, or this one
// after a restart, carries on with them.
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
	m.mu.Lock()
	defer m.mu.Unlock()
	pw, err := m.aead.Open(nil, s.nonce, s.sealed, []byte(s.ID))
	if err != nil {
		return "", errors.New("webmail: session credentials unreadable")
	}
	return string(pw), nil
}

// UpdatePassword reseals a session's password after the user changed it,
// so the session's mail connection can still be redialled.
func (m *SessionManager) UpdatePassword(s *Session, password string) error {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	m.mu.Lock()
	s.nonce = nonce
	s.sealed = m.aead.Seal(nil, nonce, []byte(password), []byte(s.ID))
	s.lastSeen = m.now()
	rec := s.record()
	m.mu.Unlock()
	if m.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.shared.Save(ctx, rec, m.ttl); err != nil {
			return err
		}
		m.mu.Lock()
		s.lastPersisted = rec.LastSeen
		m.mu.Unlock()
		return nil
	}
	return nil
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
	return m.withStoreLocked(ctx, s, dial, fn)
}

func (m *SessionManager) withStoreLocked(ctx context.Context, s *Session, dial Dialer, fn func(Mailstore) error) error {
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

// withMailStore uses a fresh connection for another mailbox. Reauthenticating
// with the member's own password on every request makes a revoked grant stop
// working immediately and keeps personal calendar/contact storage separate.
func (m *SessionManager) withMailStore(ctx context.Context, s *Session, dial Dialer, fn func(Mailstore) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.mu.Lock()
	mailbox := s.Mailbox
	m.mu.Unlock()
	if mailbox == "" {
		return m.withStoreLocked(ctx, s, dial, fn)
	}
	pw, err := m.password(s)
	if err != nil {
		return err
	}
	st, err := dial(ctx, s.User+"|"+mailbox, pw)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return fn(st)
}

func (m *SessionManager) SetMailbox(ctx context.Context, s *Session, mailbox string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.mu.Lock()
	previous := s.Mailbox
	s.Mailbox = mailbox
	s.lastSeen = m.now()
	rec := s.record()
	m.mu.Unlock()
	if m.shared != nil {
		if err := m.shared.Save(ctx, rec, m.ttl); err != nil {
			m.mu.Lock()
			s.Mailbox = previous
			m.mu.Unlock()
			return err
		}
		m.mu.Lock()
		s.lastPersisted = rec.LastSeen
		m.mu.Unlock()
	}
	return nil
}

func (m *SessionManager) SelectedMailbox(s *Session) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return s.Mailbox
}

func (m *SessionManager) MailAddress(s *Session) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Mailbox != "" {
		return s.Mailbox
	}
	return s.Address
}

// RevokeUser ends webmail sessions even when an existing IMAP connection
// would otherwise keep working with the old password.
func (m *SessionManager) RevokeUser(ctx context.Context, address string) error {
	if m.shared != nil {
		revoker, ok := m.shared.(interface {
			RevokeUser(context.Context, string, time.Duration) error
		})
		if !ok {
			return errors.New("webmail: session store cannot revoke accounts")
		}
		if err := revoker.RevokeUser(ctx, strings.ToLower(address), m.ttl); err != nil {
			return err
		}
	}
	m.mu.Lock()
	var ids []string
	for id, s := range m.sessions {
		if strings.EqualFold(s.Address, address) {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Destroy(id)
	}
	return nil
}
