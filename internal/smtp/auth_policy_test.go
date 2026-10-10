package smtp

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func authHandlerFrom(t *testing.T, remoteIP string, cfg *Config, shared *AuthenticationSecurityManager) *AuthHandler {
	t.Helper()
	conn := fakeAddrConn{remote: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 40000}}
	session := &Session{config: cfg, logger: slog.Default()}
	state := NewSessionState(slog.Default())
	ah := NewAuthHandler(session, state, nil, conn, slog.Default())
	if shared != nil {
		ah.securityManager = shared
	}
	return ah
}

func TestPasswordAuthNeedsTLSExceptOnLoopback(t *testing.T) {
	cfg := &Config{Auth: &AuthConfig{Enabled: true}}
	ctx := context.Background()

	remote := authHandlerFrom(t, "203.0.113.7", cfg, nil)
	for _, m := range []AuthMethod{AuthMethodPlain, AuthMethodLogin} {
		err := remote.checkSecurityConstraints(ctx, m)
		if err == nil || !strings.HasPrefix(err.Error(), "538") {
			t.Errorf("%s over plaintext from a remote client: got %v, want 538", m, err)
		}
	}
	if remote.plaintextAuthAllowed() {
		t.Error("AUTH would be advertised to a remote client before STARTTLS")
	}

	if err := authHandlerFrom(t, "127.0.0.1", cfg, nil).checkSecurityConstraints(ctx, AuthMethodPlain); err != nil {
		t.Errorf("loopback refused: %v", err)
	}

	optOut := &Config{Auth: &AuthConfig{Enabled: true, AllowPlaintextAuth: true}}
	if err := authHandlerFrom(t, "203.0.113.7", optOut, nil).checkSecurityConstraints(ctx, AuthMethodPlain); err != nil {
		t.Errorf("allow_plaintext_auth did not apply: %v", err)
	}
}

// Failures from one address must count across connections; a lockout must
// not lock the account out for everyone else.
func TestAuthLimitsAreSharedAcrossSessions(t *testing.T) {
	cfg := &Config{Auth: &AuthConfig{Enabled: true, AllowPlaintextAuth: true}}
	shared := NewAuthenticationSecurityManager(&AuthSecurityConfig{
		MaxAuthAttempts: 5, MaxAuthAttemptsPerIP: 3, AuthRateInterval: 1e12, AccountLockoutDuration: 1e12,
		EnabledMethods: []AuthMethod{AuthMethodPlain},
	}, slog.Default())

	for i := 0; i < 3; i++ {
		ah := authHandlerFrom(t, "198.51.100.4", cfg, shared) // a fresh connection each time
		ah.recordAuthFailureCounts("alice")
	}
	next := authHandlerFrom(t, "198.51.100.4", cfg, shared)
	if err := next.checkSecurityConstraints(context.Background(), AuthMethodPlain); err == nil {
		t.Fatal("reconnecting reset the per-address limit")
	}
	other := authHandlerFrom(t, "203.0.113.50", cfg, shared)
	if err := other.checkSecurityConstraints(context.Background(), AuthMethodPlain); err != nil {
		t.Errorf("another address was limited too: %v", err)
	}
}

// recordAuthFailureCounts records one failure the way recordAuthFailure does,
// without the logging it also does (which needs a live session).
func (ah *AuthHandler) recordAuthFailureCounts(username string) {
	m := ah.securityManager
	m.mu.Lock()
	defer m.mu.Unlock()
	host, _, _ := net.SplitHostPort(ah.conn.RemoteAddr().String())
	if f, ok := m.ipFailures[host]; ok {
		f.Count++
	} else {
		m.ipFailures[host] = &AuthFailureInfo{Count: 1, LastTime: timeNow(), IPAddress: host}
	}
	_ = username
}

var timeNow = time.Now
