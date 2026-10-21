package webmail

import (
	"testing"
	"time"
)

func TestPageCacheRaw(t *testing.T) {
	var c pageCache
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	c.putRaw("s1", "", "INBOX", 7, []byte("msg"), now)
	if raw, ok := c.getRaw("s1", "", "INBOX", 7, now.Add(time.Second)); !ok || string(raw) != "msg" {
		t.Fatal("the body frame should reuse the page's copy")
	}
	for name, miss := range map[string]func() bool{
		"other session": func() bool { _, ok := c.getRaw("s2", "", "INBOX", 7, now); return ok },
		"other mailbox": func() bool { _, ok := c.getRaw("s1", "shared@example.com", "INBOX", 7, now); return ok },
		"other folder":  func() bool { _, ok := c.getRaw("s1", "", "Sent", 7, now); return ok },
		"other uid":     func() bool { _, ok := c.getRaw("s1", "", "INBOX", 8, now); return ok },
		"expired":       func() bool { _, ok := c.getRaw("s1", "", "INBOX", 7, now.Add(rawTTL)); return ok },
	} {
		if miss() {
			t.Errorf("%s: served from the cache", name)
		}
	}
	c.forgetRaw("s1")
	if _, ok := c.getRaw("s1", "", "INBOX", 7, now); ok {
		t.Error("a change to messages should drop the copy")
	}
	c.putRaw("s1", "", "INBOX", 9, make([]byte, maxRawCache+1), now)
	if _, ok := c.getRaw("s1", "", "INBOX", 9, now); ok {
		t.Error("large messages aren't kept")
	}
}

func TestPageCacheShares(t *testing.T) {
	var c pageCache
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	c.putShares("s1", []sharedMailbox{{Mailbox: "team@example.com"}}, now)
	if l, ok := c.getShares("s1", now.Add(30*time.Second)); !ok || len(l) != 1 {
		t.Fatal("shares should be cached")
	}
	if _, ok := c.getShares("s1", now.Add(sharesTTL)); ok {
		t.Error("shares should expire")
	}
	c.forget("s1")
	if _, ok := c.getShares("s1", now); ok {
		t.Error("sign-out should drop the shares")
	}
}
