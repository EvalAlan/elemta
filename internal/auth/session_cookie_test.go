package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The session cookie used to hardcode Secure. A Secure cookie is not sent back
// over plain HTTP, so on any HTTP deployment that is not localhost — an
// internal hostname, an IP address — login appeared to succeed and then bounced
// straight back to the login form, with nothing logged to explain it. Browsers
// exempt localhost, which is precisely why that would have passed development
// and failed in production.
//
// Secure now reflects the connection, and must still be set wherever TLS is
// actually in play.

func cookieFor(t *testing.T, r *http.Request) *http.Cookie {
	t.Helper()
	sm := NewSessionManager(SessionConfig{})
	w := httptest.NewRecorder()
	sm.SetCookie(w, r, "session-value")

	result := w.Result()
	defer func() { _ = result.Body.Close() }()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func TestSessionCookieSecureFollowsTheConnection(t *testing.T) {
	t.Run("plain HTTP does not set Secure", func(t *testing.T) {
		c := cookieFor(t, httptest.NewRequest(http.MethodPost, "http://mail.internal:8025/auth/login", nil))
		if c.Secure {
			t.Error("Secure on a plain HTTP connection means the browser never sends the cookie back, " +
				"so the session silently fails to persist")
		}
	})

	t.Run("direct TLS sets Secure", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/auth/login", nil)
		r.TLS = &tls.ConnectionState{}
		if c := cookieFor(t, r); !c.Secure {
			t.Error("a TLS connection must produce a Secure cookie")
		}
	})

	t.Run("behind a TLS-terminating proxy sets Secure", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "http://mail.internal:8025/auth/login", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		if c := cookieFor(t, r); !c.Secure {
			t.Error("X-Forwarded-Proto: https must produce a Secure cookie")
		}
	})

	t.Run("hardening attributes are always present", func(t *testing.T) {
		c := cookieFor(t, httptest.NewRequest(http.MethodPost, "http://mail.internal:8025/auth/login", nil))
		if !c.HttpOnly {
			t.Error("session cookie must be HttpOnly so scripts cannot read it")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("Path = %q, want /", c.Path)
		}
	})
}

// TestClearCookieMatchesSetCookie pins that logout can actually remove the
// cookie: a browser only replaces a cookie when the attributes match.
func TestClearCookieMatchesSetCookie(t *testing.T) {
	sm := NewSessionManager(SessionConfig{})
	r := httptest.NewRequest(http.MethodPost, "http://mail.internal:8025/auth/logout", nil)

	w := httptest.NewRecorder()
	sm.ClearCookie(w, r)
	header := w.Header().Get("Set-Cookie")

	if strings.Contains(header, "Secure") {
		t.Errorf("clearing over plain HTTP must not set Secure, or the browser keeps the "+
			"original cookie and logout does nothing: %q", header)
	}
	if !strings.Contains(header, "Max-Age=0") && !strings.Contains(header, "Max-Age=-1") {
		t.Errorf("clearing must expire the cookie: %q", header)
	}
}
