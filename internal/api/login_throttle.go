package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Brute-force protection for password logins.
//
// The general API rate limiter allows 10 requests a second per address, which
// is 36,000 password guesses an hour against an account. Each failed login
// costs at least 100ms (Authenticate pads to that), so the limiter is the
// only thing bounding a guessing attack, and it bounds it far too loosely.
//
// Two counters, both over a sliding window:
//
//   - per (address, username): a handful of failures locks that pair out. A
//     legitimate user who mistypes is the common case, so it is small but not
//     one.
//   - per address: catches one host spraying many usernames.
//
// Deliberately not per username alone. That would let anyone lock the admin
// out of the dashboard just by failing to log in as them.

const (
	loginWindow          = 15 * time.Minute
	loginMaxPerUserAddr  = 5
	loginMaxPerAddr      = 20
	loginThrottleMaxKeys = 100000 // memory bound under a spray from many addresses
)

type loginThrottle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	now      func() time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{failures: make(map[string][]time.Time), now: time.Now}
}

func throttleKeys(addr, username string) (pair, host string) {
	return "u\x00" + addr + "\x00" + strings.ToLower(username), "a\x00" + addr
}

// retryAfter reports how long addr must wait before trying username again,
// or zero if it may try now.
func (lt *loginThrottle) retryAfter(addr, username string) time.Duration {
	if lt == nil {
		return 0
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	now := lt.now()
	pair, host := throttleKeys(addr, username)
	wait := lt.waitLocked(pair, loginMaxPerUserAddr, now)
	if w := lt.waitLocked(host, loginMaxPerAddr, now); w > wait {
		wait = w
	}
	return wait
}

// waitLocked prunes key's failures to the window and returns how long until
// it drops below max.
func (lt *loginThrottle) waitLocked(key string, max int, now time.Time) time.Duration {
	times := lt.failures[key]
	kept := times[:0]
	for _, t := range times {
		if now.Sub(t) < loginWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(lt.failures, key)
		return 0
	}
	lt.failures[key] = kept
	if len(kept) < max {
		return 0
	}
	// The oldest failure that keeps the count at max has to age out.
	return loginWindow - now.Sub(kept[len(kept)-max])
}

func (lt *loginThrottle) recordFailure(addr, username string) {
	if lt == nil {
		return
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if len(lt.failures) >= loginThrottleMaxKeys {
		lt.pruneLocked(lt.now())
	}
	now := lt.now()
	pair, host := throttleKeys(addr, username)
	lt.failures[pair] = append(lt.failures[pair], now)
	lt.failures[host] = append(lt.failures[host], now)
}

// recordSuccess clears the pair's failures, so a user who mistyped and then
// got in is not left one typo from a lockout. The address counter stays: a
// sprayer that guesses one account right should not get a fresh budget.
func (lt *loginThrottle) recordSuccess(addr, username string) {
	if lt == nil {
		return
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	pair, _ := throttleKeys(addr, username)
	delete(lt.failures, pair)
}

func (lt *loginThrottle) pruneLocked(now time.Time) {
	for key, times := range lt.failures {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= loginWindow {
			delete(lt.failures, key)
		}
	}
}

// writeThrottled answers a locked-out login.
func writeThrottled(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "Too many failed logins; try again in "+strconv.Itoa((secs+59)/60)+" minute(s)", http.StatusTooManyRequests)
}

// loginAddr is the client address used for throttling, honouring the same
// trusted proxies as the API rate limiter.
func (s *Server) loginAddr(r *http.Request) string {
	var trusted []*net.IPNet
	if s.rateLimiter != nil {
		trusted = s.rateLimiter.trustedProxies
	}
	return extractIP(r, trusted)
}
