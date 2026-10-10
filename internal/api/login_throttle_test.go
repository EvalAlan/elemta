package api

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoginThrottleLocksAPairAfterRepeatedFailures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	lt := newLoginThrottle()
	lt.now = func() time.Time { return now }

	for i := 0; i < loginMaxPerUserAddr; i++ {
		require.Zero(t, lt.retryAfter("198.51.100.7", "admin"), "attempt %d should be allowed", i+1)
		lt.recordFailure("198.51.100.7", "admin")
	}
	wait := lt.retryAfter("198.51.100.7", "admin")
	require.Greater(t, wait, time.Duration(0), "the pair must be locked after %d failures", loginMaxPerUserAddr)

	// The same account from elsewhere is unaffected: failing to log in as
	// admin must not be a way to lock admin out.
	require.Zero(t, lt.retryAfter("203.0.113.9", "admin"))

	now = now.Add(wait)
	require.Zero(t, lt.retryAfter("198.51.100.7", "admin"), "the lock must lift once the window passes")
}

func TestLoginThrottleCatchesUsernameSpraying(t *testing.T) {
	lt := newLoginThrottle()
	for i := 0; i < loginMaxPerAddr; i++ {
		lt.recordFailure("198.51.100.7", "user"+string(rune('a'+i)))
	}
	require.Greater(t, lt.retryAfter("198.51.100.7", "someone-new"), time.Duration(0))
}

func TestLoginThrottleSuccessClearsThePair(t *testing.T) {
	lt := newLoginThrottle()
	for i := 0; i < loginMaxPerUserAddr-1; i++ {
		lt.recordFailure("198.51.100.7", "alice")
	}
	lt.recordSuccess("198.51.100.7", "alice")
	lt.recordFailure("198.51.100.7", "alice")
	require.Zero(t, lt.retryAfter("198.51.100.7", "alice"))
}

// Through the real login endpoint and through Basic auth: after the limit,
// even the right password is refused until the window passes.
func TestLoginEndpointsAreThrottled(t *testing.T) {
	base, _ := startUserServer(t)

	post := func(password string) int {
		body := []byte(`{"username":"viewer","password":"` + password + `"}`)
		resp, err := http.Post(base+"/auth/login", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < loginMaxPerUserAddr; i++ {
		require.Equal(t, http.StatusUnauthorized, post("wrong-password"))
	}
	require.Equal(t, http.StatusTooManyRequests, post(testUserPassword))

	code, _ := userRequest(t, "GET", base+"/api/queue/stats", "viewer", testUserPassword, nil)
	require.Equal(t, http.StatusUnauthorized, code, "Basic auth must share the lockout")

	code, _ = userRequest(t, "GET", base+"/api/queue/stats", "root", testAdminPassword, nil)
	require.Equal(t, http.StatusOK, code, "other accounts from the same address still work")
}
