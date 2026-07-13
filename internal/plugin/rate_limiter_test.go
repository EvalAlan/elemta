package plugin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBucket_TryConsume(t *testing.T) {
	t.Run("consumes tokens up to capacity", func(t *testing.T) {
		tb := NewTokenBucket(5, 1)
		for i := 0; i < 5; i++ {
			assert.True(t, tb.TryConsume(1), "expected token %d to be available", i)
		}
		assert.False(t, tb.TryConsume(1), "bucket should be exhausted")
	})

	t.Run("refuses to consume more than capacity even when empty", func(t *testing.T) {
		tb := NewTokenBucket(3, 1)
		assert.False(t, tb.TryConsume(10))
	})

	t.Run("refills over time based on refill rate", func(t *testing.T) {
		tb := NewTokenBucket(2, 100) // 100 tokens/sec refill
		assert.True(t, tb.TryConsume(2))
		assert.False(t, tb.TryConsume(1))

		time.Sleep(50 * time.Millisecond) // ~5 tokens refilled at 100/s
		assert.True(t, tb.TryConsume(1))
	})

	t.Run("never exceeds capacity when refilling", func(t *testing.T) {
		tb := NewTokenBucket(2, 1000)
		time.Sleep(20 * time.Millisecond)
		assert.Equal(t, int64(2), tb.GetTokens())
	})
}

func TestTokenBucket_GetTokens(t *testing.T) {
	tb := NewTokenBucket(10, 5)
	assert.Equal(t, int64(10), tb.GetTokens())

	tb.TryConsume(4)
	assert.Equal(t, int64(6), tb.GetTokens())
}

func TestConnectionRateLimiter_CheckConnection(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.ConnectionBurstSize = 2
	cfg.ConnectionRatePerMinute = 60 // 1/sec
	cfg.CleanupInterval = time.Hour
	crl := NewConnectionRateLimiter(cfg)
	defer crl.Close()

	ok, reason := crl.CheckConnection("1.2.3.4")
	assert.True(t, ok)
	assert.Empty(t, reason)

	ok, _ = crl.CheckConnection("1.2.3.4")
	assert.True(t, ok)

	ok, reason = crl.CheckConnection("1.2.3.4")
	assert.False(t, ok)
	assert.Contains(t, reason, "connection rate limit exceeded")

	// A different IP gets its own bucket
	ok, _ = crl.CheckConnection("5.6.7.8")
	assert.True(t, ok)
}

func TestMessageRateLimiter_CheckMessageRate(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.MaxMessagesPerMinute = 1
	mrl := NewMessageRateLimiter(cfg)

	ok, _ := mrl.CheckMessageRate("sender@example.com")
	assert.True(t, ok)

	ok, reason := mrl.CheckMessageRate("sender@example.com")
	assert.False(t, ok)
	assert.Contains(t, reason, "message rate limit exceeded")
}

func TestMessageRateLimiter_CheckRecipientRate(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.MaxRecipientsPerHour = 5
	mrl := NewMessageRateLimiter(cfg)

	ok, _ := mrl.CheckRecipientRate("sender@example.com", 5)
	assert.True(t, ok)

	ok, reason := mrl.CheckRecipientRate("sender@example.com", 1)
	assert.False(t, ok)
	assert.Contains(t, reason, "recipient rate limit exceeded")
}

func TestVolumeRateLimiter_CheckVolumeRate(t *testing.T) {
	t.Run("default config's MaxDataPerHour parses and volume checks work", func(t *testing.T) {
		cfg := DefaultRateLimiterConfig() // MaxDataPerHour: "1GB"
		vrl := NewVolumeRateLimiter(cfg)

		ok, reason := vrl.CheckVolumeRate("1.2.3.4", 10)
		assert.True(t, ok)
		assert.Empty(t, reason)
	})

	t.Run("data under the limit is accepted", func(t *testing.T) {
		cfg := DefaultRateLimiterConfig()
		cfg.MaxDataPerHour = "1000B"
		vrl := NewVolumeRateLimiter(cfg)

		ok, _ := vrl.CheckVolumeRate("1.2.3.4", 500)
		assert.True(t, ok)
	})

	t.Run("rejects data over the parsed limit", func(t *testing.T) {
		cfg := DefaultRateLimiterConfig()
		cfg.MaxDataPerHour = "100B"
		vrl := NewVolumeRateLimiter(cfg)

		ok, reason := vrl.CheckVolumeRate("1.2.3.4", 1000)
		assert.False(t, ok)
		assert.Contains(t, reason, "volume rate limit exceeded")
	})

	t.Run("invalid volume config produces error message", func(t *testing.T) {
		cfg := DefaultRateLimiterConfig()
		cfg.MaxDataPerHour = "not-a-size"
		vrl := NewVolumeRateLimiter(cfg)

		ok, reason := vrl.CheckVolumeRate("1.2.3.4", 10)
		assert.False(t, ok)
		assert.Contains(t, reason, "invalid volume configuration")
	})
}

func TestAuthRateLimiter_CheckAuthRate(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.AuthBurstSize = 2
	// A high per-minute rate keeps the token bucket's refill fast so the
	// lockout-expiry assertion below doesn't need a long sleep.
	cfg.MaxAuthAttemptsPerMinute = 6000 // 100 tokens/sec refill
	cfg.AuthLockoutDuration = 50 * time.Millisecond
	arl := NewAuthRateLimiter(cfg)

	ok, _ := arl.CheckAuthRate("9.9.9.9")
	assert.True(t, ok)
	ok, _ = arl.CheckAuthRate("9.9.9.9")
	assert.True(t, ok)

	// Exceeds burst -> triggers lockout
	ok, reason := arl.CheckAuthRate("9.9.9.9")
	assert.False(t, ok)
	assert.Contains(t, reason, "locked out")

	// Still locked out immediately after
	ok, reason = arl.CheckAuthRate("9.9.9.9")
	assert.False(t, ok)
	assert.Contains(t, reason, "authentication locked out")

	// After the lockout duration expires, the bucket (which persists across
	// lockouts) has had time to refill at 100 tokens/sec, so requests
	// succeed again.
	time.Sleep(100 * time.Millisecond)
	ok, _ = arl.CheckAuthRate("9.9.9.9")
	assert.True(t, ok)
}

func TestAccessList_WhitelistAndBlacklist(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	cfg.WhitelistIPs = []string{"1.1.1.1"}
	cfg.WhitelistDomains = []string{"good.com"}
	cfg.BlacklistIPs = []string{"6.6.6.6"}
	cfg.BlacklistDomains = []string{"bad.com"}

	al := NewAccessList(cfg)

	assert.True(t, al.IsWhitelisted("1.1.1.1", ""))
	assert.True(t, al.IsWhitelisted("", "good.com"))
	assert.False(t, al.IsWhitelisted("2.2.2.2", "other.com"))

	assert.True(t, al.IsBlacklisted("6.6.6.6", ""))
	assert.True(t, al.IsBlacklisted("", "bad.com"))
	assert.False(t, al.IsBlacklisted("2.2.2.2", "other.com"))
}

func TestRateLimiterMetrics_IncrementAndGet(t *testing.T) {
	rm := NewRateLimiterMetrics()

	rm.IncrementConnectionLimitsHit()
	rm.IncrementConnectionLimitsHit()
	rm.IncrementMessageLimitsHit()
	rm.IncrementVolumeLimitsHit()
	rm.IncrementAuthLimitsHit()
	rm.IncrementWhitelistHits()
	rm.IncrementBlacklistHits()
	rm.IncrementTotalRequests()

	metrics := rm.GetMetrics()
	assert.Equal(t, int64(2), metrics["connection_limits_hit"])
	assert.Equal(t, int64(1), metrics["message_limits_hit"])
	assert.Equal(t, int64(1), metrics["volume_limits_hit"])
	assert.Equal(t, int64(1), metrics["auth_limits_hit"])
	assert.Equal(t, int64(1), metrics["whitelist_hits"])
	assert.Equal(t, int64(1), metrics["blacklist_hits"])
	assert.Equal(t, int64(1), metrics["total_requests_processed"])
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{"two-letter MB suffix", "50MB", 50 * 1024 * 1024, false},
		{"two-letter GB suffix", "1GB", 1024 * 1024 * 1024, false},
		{"two-letter KB suffix", "10KB", 10 * 1024, false},
		{"plain bytes", "100B", 100, false},
		{"single-letter kilobytes", "5K", 5 * 1024, false},
		{"single-letter megabytes", "50M", 50 * 1024 * 1024, false},
		{"single-letter gigabytes", "1G", 1024 * 1024 * 1024, false},
		{"lowercase suffix", "50mb", 50 * 1024 * 1024, false},
		{"surrounding whitespace", " 50MB ", 50 * 1024 * 1024, false},
		{"empty string errors", "", 0, true},
		{"whitespace-only string errors", "   ", 0, true},
		{"unsupported unit errors", "10XXX", 0, true},
		{"bare number without unit errors", "100", 0, true},
		{"unit without a number errors", "GB", 0, true},
		{"non-numeric value errors", "abcMB", 0, true},
		{"negative size errors", "-1MB", 0, true},
		{"overflowing size errors", "9999999999GB", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSize(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultRateLimiterConfig(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	assert.True(t, cfg.Enabled)
	assert.Greater(t, cfg.MaxConnectionsPerIP, 0)
	assert.Greater(t, cfg.MaxMessagesPerMinute, 0)
	assert.Equal(t, "elemta:ratelimit:", cfg.ValkeyKeyPrefix)
	assert.Empty(t, cfg.WhitelistIPs)
	assert.Empty(t, cfg.BlacklistIPs)
}
