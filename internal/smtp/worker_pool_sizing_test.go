package smtp

import (
	"log/slog"
	"testing"
)

// The connection worker pool caps how many SMTP sessions run at once: each
// accepted connection holds a worker for its whole session, and everything
// beyond the pool waits in a queue.
//
// It was hardcoded to 20 while the shipped configuration allowed 1000
// connections, so past 20 concurrent clients most of them sat queued rather
// than being served — visible as client timeouts while the server's CPU sat
// near idle.

func TestConnectionPoolSizeFollowsMaxConcurrent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))

	cases := []struct {
		name          string
		maxConcurrent int
		want          int
	}{
		{"unset falls back to the default", 0, defaultConnectionWorkers},
		{"explicit value is honoured", 50, 50},
		{"large value is honoured", 500, 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Hostname:  "test.example.com",
				Resources: &ResourceConfig{MaxConcurrent: tc.maxConcurrent},
			}
			_, rootCancel, _, cancel, _, _, pool := initConcurrency(cfg, logger, DefaultResourceLimits())
			defer rootCancel()
			defer cancel()

			if pool.size != tc.want {
				t.Errorf("pool size = %d, want %d", pool.size, tc.want)
			}
		})
	}
}

// TestConnectionPoolDefaultIsNotTwenty guards the specific regression: a pool
// of 20 is far below any reasonable connection limit and is what caused
// clients to time out while queued.
func TestConnectionPoolDefaultIsNotTwenty(t *testing.T) {
	if defaultConnectionWorkers <= 20 {
		t.Errorf("default connection workers = %d; a pool this small queues connections "+
			"at any real concurrency", defaultConnectionWorkers)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
