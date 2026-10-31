package webmail

import (
	"sync"
	"time"
)

// pageCache keeps two things a session asks for again within moments, in
// this replica's memory.
//
// The shared-mailbox list goes in every mail page's header, and getting it
// is a call to the mailbox's security API that authenticates the user
// again: a directory bind, the app-password and class-of-service lookups.
// Shares change rarely and the mailbox enforces them on every access, so a
// list up to sharesTTL old is fine for the switcher.
//
// Opening a message loads the page, then the reading pane's frame loads the
// body: the same message, fetched in full twice. The frame's request
// arrives right after, so the page's copy is kept for rawTTL. A UID's
// content never changes, and the key includes the mailbox the session has
// selected, so the copy is only ever the one the session just read.
type pageCache struct {
	mu     sync.Mutex
	shares map[string]cachedShares
	raw    map[string]cachedRaw
	mail   map[string]cachedMail
	sendAs map[string]cachedSendAs
}

type cachedSendAs struct {
	at        time.Time
	addresses []string
}

// The addresses the user may send as, like the shares, for a minute.
func (c *pageCache) getSendAs(session string, now time.Time) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.sendAs[session]
	if !ok || now.Sub(e.at) >= sharesTTL || now.Before(e.at) {
		return nil, false
	}
	return e.addresses, true
}

func (c *pageCache) putSendAs(session string, addresses []string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendAs == nil || len(c.sendAs) >= maxCacheSessions {
		c.sendAs = map[string]cachedSendAs{}
	}
	c.sendAs[session] = cachedSendAs{at: now, addresses: addresses}
}

type cachedMail struct {
	at   time.Time
	mail AccountMail
}

// The user's directory mail settings, like the shares, for a minute.
func (c *pageCache) getMail(session string, now time.Time) (AccountMail, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.mail[session]
	if !ok || now.Sub(e.at) >= sharesTTL || now.Before(e.at) {
		return AccountMail{}, false
	}
	return e.mail, true
}

func (c *pageCache) putMail(session string, m AccountMail, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mail == nil || len(c.mail) >= maxCacheSessions {
		c.mail = map[string]cachedMail{}
	}
	c.mail[session] = cachedMail{at: now, mail: m}
}

func (c *pageCache) forgetMail(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.mail, session)
}

const (
	sharesTTL   = time.Minute
	rawTTL      = 30 * time.Second
	maxRawCache = 2 << 20 // larger messages are fetched each time
	// Entries are per session; past this many the maps start over rather
	// than grow, which costs only a refetch.
	maxCacheSessions = 20000
)

type cachedShares struct {
	at   time.Time
	list []sharedMailbox
}

type cachedRaw struct {
	at     time.Time
	key    string
	folder string
	uid    uint32
	raw    []byte
}

func (c *pageCache) getShares(session string, now time.Time) ([]sharedMailbox, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.shares[session]
	if !ok || now.Sub(e.at) >= sharesTTL || now.Before(e.at) {
		return nil, false
	}
	return e.list, true
}

func (c *pageCache) putShares(session string, list []sharedMailbox, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shares == nil || len(c.shares) >= maxCacheSessions {
		c.shares = map[string]cachedShares{}
	}
	c.shares[session] = cachedShares{at: now, list: list}
}

func (c *pageCache) getRaw(session, mailbox, folder string, uid uint32, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.raw[session]
	if !ok || e.key != mailbox || e.folder != folder || e.uid != uid || now.Sub(e.at) >= rawTTL || now.Before(e.at) {
		return nil, false
	}
	return e.raw, true
}

func (c *pageCache) putRaw(session, mailbox, folder string, uid uint32, raw []byte, now time.Time) {
	if len(raw) > maxRawCache {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw == nil || len(c.raw) >= maxCacheSessions {
		c.raw = map[string]cachedRaw{}
	}
	c.raw[session] = cachedRaw{at: now, key: mailbox, folder: folder, uid: uid, raw: raw}
}

// forget drops a session's entries: on sign-out, on switching mailbox, and
// after any change to messages, so a deleted message can't be reopened from
// the cache.
func (c *pageCache) forget(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.shares, session)
	delete(c.raw, session)
	delete(c.mail, session)
}

func (c *pageCache) forgetRaw(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.raw, session)
}

// rawMessage returns the message, from the cache when this session just
// read it.
func (s *Server) rawMessage(sess *Session, fetch func() ([]byte, error), folder string, uid uint32) ([]byte, error) {
	mailbox := s.sessions.SelectedMailbox(sess)
	if raw, ok := s.pages.getRaw(sess.ID, mailbox, folder, uid, s.now()); ok {
		return raw, nil
	}
	raw, err := fetch()
	if err == nil {
		s.pages.putRaw(sess.ID, mailbox, folder, uid, raw, s.now())
	}
	return raw, err
}
