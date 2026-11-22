package commands

import (
	"testing"

	"github.com/EvalAlan/elemta/internal/config"
	"github.com/stretchr/testify/require"
)

// The console has to show what the SMTP server uses: the flat key wins.
func TestConsoleConfigPrecedence(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxSize, cfg.Server.MaxSize = 52428800, 26214400
	cfg.Hostname, cfg.Server.Hostname = "flat.example.com", "section.example.com"
	cfg.ListenAddr, cfg.Server.Listen = ":2525", ":25"
	got := convertToAPIMainConfig(cfg)
	require.Equal(t, cfg.EffectiveMaxSize(), got.MaxSize)
	require.Equal(t, cfg.EffectiveHostname(), got.Hostname)
	require.Equal(t, cfg.EffectiveListenAddr(), got.ListenAddr)
}
