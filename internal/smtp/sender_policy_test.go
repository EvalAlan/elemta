package smtp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAdminAPI serves one user's effective policy, as the mailbox does.
func fakeAdminAPI(t *testing.T, eff *mailpolicy.Effective, up *atomic.Bool, calls *atomic.Int32) string {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !up.Load() {
			http.Error(w, `{"error":"down"}`, http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer admin-token" || r.URL.Path != "/v1/admin/effective" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("address") != "dana@example.com" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(eff)
	}))
	t.Cleanup(api.Close)
	return api.URL
}

func TestSenderPolicies(t *testing.T) {
	eff := mailpolicy.Builtin()
	eff.MaxMessageBytes, eff.MaxAttachmentBytes = 1000, 100
	eff.MessagesPerHour, eff.RecipientsPerMessage, eff.RecipientsPerDay = 2, 3, 5
	var up atomic.Bool
	var calls atomic.Int32
	up.Store(true)
	url := fakeAdminAPI(t, &eff, &up, &calls)
	t.Setenv(mailpolicy.TokenEnv, "admin-token")
	t.Setenv("VALKEY_ADDR", "")
	p := newSenderPolicies(&Config{Auth: &AuthConfig{MailboxSecurityURL: url}}, slog.Default())
	require.NotNil(t, p)
	clock := time.Date(2026, 10, 19, 10, 15, 0, 0, time.UTC)
	p.now = func() time.Time { return clock }
	ctx := context.Background()
	user := "Dana@Example.com"

	// Size declared at MAIL FROM, and measured once the message arrives.
	assert.ErrorContains(t, p.checkMail(ctx, user, 5000), "552 5.3.4")
	assert.NoError(t, p.checkMail(ctx, user, 500))
	assert.ErrorContains(t, p.checkContent(ctx, user, 2000, nil), "552 5.3.4")
	withFile := []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/zip; name=a.zip\r\n\r\n" + strings.Repeat("z", 200) + "\r\n--b--\r\n")
	assert.ErrorContains(t, p.checkContent(ctx, user, int64(len(withFile)), func() ([]byte, error) { return withFile, nil }), "attachment")

	// Recipients per message.
	assert.NoError(t, p.checkRcpt(ctx, user, 2))
	assert.ErrorContains(t, p.checkRcpt(ctx, user, 3), "452 4.5.3")

	// Messages per hour and recipients per day, counted as mail is accepted.
	p.record(ctx, user, 2)
	assert.NoError(t, p.checkMail(ctx, user, 0))
	p.record(ctx, user, 2)
	assert.ErrorContains(t, p.checkMail(ctx, user, 0), "451 4.7.1", "third message in the hour")
	assert.ErrorContains(t, p.checkRcpt(ctx, user, 1), "452 4.7.1", "fifth recipient of the day")
	clock = clock.Add(time.Hour)
	assert.NoError(t, p.checkMail(ctx, user, 0), "a new hour")
	assert.ErrorContains(t, p.checkRcpt(ctx, user, 1), "452 4.7.1", "still the same day")
	clock = clock.Add(24 * time.Hour)
	assert.NoError(t, p.checkRcpt(ctx, user, 1), "a new day")

	// The policy is cached, so a busy sender costs one lookup a minute.
	before := calls.Load()
	for range 10 {
		_ = p.checkRcpt(ctx, user, 0)
	}
	assert.LessOrEqual(t, calls.Load()-before, int32(1))

	// Not knowing the limits defers rather than letting mail through.
	up.Store(false)
	clock = clock.Add(2 * time.Minute)
	assert.ErrorContains(t, p.checkMail(ctx, user, 0), "451 4.7.1")

	// Without the admin token the rules are off entirely.
	t.Setenv(mailpolicy.TokenEnv, "")
	assert.Nil(t, newSenderPolicies(&Config{Auth: &AuthConfig{MailboxSecurityURL: url}}, slog.Default()))
}
