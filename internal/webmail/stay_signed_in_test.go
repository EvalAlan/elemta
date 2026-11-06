package webmail

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func sessionCookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func TestStaySignedInConfig(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.staySignedIn() != 30*24*time.Hour || c.idleTTL() != 30*24*time.Hour {
		t.Errorf("default: stay %v, idle %v; want 30 days for both", c.staySignedIn(), c.idleTTL())
	}
	c.StaySignedIn = "0"
	if c.staySignedIn() != 0 || c.idleTTL() != defaultSessionTTL {
		t.Errorf("off: stay %v, idle %v; want 0 and session_ttl", c.staySignedIn(), c.idleTTL())
	}
	for _, bad := range []string{"a month", "-1h"} {
		c.StaySignedIn = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "stay_signed_in") {
			t.Errorf("stay_signed_in %q: %v, want refused", bad, err)
		}
	}
}

// A sign-in outlives the browser by default, the cookie's 30 days restart
// with every use, and the sign-in page says so.
func TestSignInIsRemembered(t *testing.T) {
	h := newHarness(t)
	_, page := h.get("/login")
	if !strings.Contains(page, "stay signed in on this device for 30 days") {
		t.Error("the sign-in page doesn't say sign-ins are remembered")
	}
	m := hiddenRE("token").FindStringSubmatch(page)
	resp := h.post("/login", url.Values{"token": {m[1]}, "user": {"dana"}, "password": {"secret"}})
	c := sessionCookieOf(resp)
	if c == nil || c.MaxAge != 30*24*3600 {
		t.Fatalf("sign-in cookie = %+v, want one lasting 30 days", c)
	}
	resp, _ = h.get("/mail")
	if c := sessionCookieOf(resp); c == nil || c.MaxAge != 30*24*3600 {
		t.Errorf("a page view didn't renew the cookie: %+v", c)
	}
}

func TestStaySignedInOff(t *testing.T) {
	h := newHarness(t)
	h.server.cfg.StaySignedIn = "0"
	_, page := h.get("/login")
	if strings.Contains(page, "stay signed in") {
		t.Error("the sign-in page promises a remembered sign-in that's off")
	}
	m := hiddenRE("token").FindStringSubmatch(page)
	resp := h.post("/login", url.Values{"token": {m[1]}, "user": {"dana"}, "password": {"secret"}})
	if c := sessionCookieOf(resp); c == nil || c.MaxAge != 0 {
		t.Fatalf("cookie = %+v, want one that ends with the browser", c)
	}
}

// Changing the password ends the account's other sessions, remembered ones
// included, and this browser carries on.
func TestPasswordChangeSignsOutOtherSessions(t *testing.T) {
	h := newHarness(t)
	h.server.passwords = &fakePasswords{current: "secret"}
	csrf := h.login()
	// The same account signed in on another device.
	other := *h
	jar, _ := cookiejar.New(nil)
	other.client = &http.Client{Jar: jar, CheckRedirect: h.client.CheckRedirect}
	other.login()
	if resp, _ := other.get("/mail"); resp.StatusCode != http.StatusOK {
		t.Fatalf("other device: %d", resp.StatusCode)
	}
	resp := h.post("/settings/password", url.Values{"csrf": {csrf}, "current": {"secret"}, "new": {"correct horse battery"}, "confirm": {"correct horse battery"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change = %d", resp.StatusCode)
	}
	if c := sessionCookieOf(resp); c == nil || c.MaxAge != 30*24*3600 {
		t.Errorf("no fresh remembered session after the change: %+v", c)
	}
	// Settings, not mail: the harness's mail server still wants the old
	// password, which a real one wouldn't.
	if resp, _ := h.get("/settings/account"); resp.StatusCode != http.StatusOK {
		t.Errorf("the browser that changed the password was signed out: %d", resp.StatusCode)
	}
	if resp, _ := other.get("/mail"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Errorf("the other device is still signed in: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
