package api

import (
	"net/http/httptest"
	"testing"
)

// Behind the proxy the console sees the visitor, and a forged header from
// anywhere else changes nothing.
func TestConsoleSeesThroughItsProxy(t *testing.T) {
	limiter := NewRateLimitMiddleware(RateLimitConfig{TrustedProxies: []string{"10.253.53.80/32"}})
	t.Cleanup(limiter.Stop)
	viaProxy := httptest.NewRequest("GET", "/", nil)
	viaProxy.RemoteAddr = "10.253.53.80:41000"
	viaProxy.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := extractIP(viaProxy, limiter.trustedProxies); got != "203.0.113.7" {
		t.Fatalf("through the proxy: %s", got)
	}
	direct := httptest.NewRequest("GET", "/", nil)
	direct.RemoteAddr = "198.51.100.9:41000"
	direct.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := extractIP(direct, limiter.trustedProxies); got != "198.51.100.9" {
		t.Fatalf("a forged header counted: %s", got)
	}
}
