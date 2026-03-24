package plugin

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiterPlugin_Init_UsesInjectedRedisClientFactory(t *testing.T) {
	oldFactory := newRateLimitRedisClient
	defer func() { newRateLimitRedisClient = oldFactory }()

	called := false
	newRateLimitRedisClient = func(redisURL, keyPrefix string, logger *slog.Logger) (*RedisClient, error) {
		called = true
		assert.Equal(t, "valkey:6379", redisURL)
		assert.Equal(t, "elemta:test", keyPrefix)
		return &RedisClient{enabled: false, logger: logger}, nil
	}

	plugin := NewRateLimiterPlugin()
	plugin.config.Enabled = true
	plugin.config.ValkeyURL = "valkey:6379"
	plugin.config.ValkeyKeyPrefix = "elemta:test"
	err := plugin.Init(nil)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestRateLimiterPlugin_Init_FallsBackWhenInjectedRedisFactoryFails(t *testing.T) {
	oldFactory := newRateLimitRedisClient
	defer func() { newRateLimitRedisClient = oldFactory }()

	newRateLimitRedisClient = func(redisURL, keyPrefix string, logger *slog.Logger) (*RedisClient, error) {
		return nil, errors.New("boom")
	}

	plugin := NewRateLimiterPlugin()
	plugin.config.ValkeyURL = "valkey:6379"
	plugin.config.ValkeyKeyPrefix = "elemta:test"

	err := plugin.Init(nil)
	require.NoError(t, err)
	assert.NotNil(t, plugin.connectionLimiter)
	assert.NotNil(t, plugin.messageLimiter)
	assert.NotNil(t, plugin.volumeLimiter)
	assert.NotNil(t, plugin.authLimiter)
}
