package commands

import (
	"context"
	"os"

	"github.com/EvalAlan/elemta/internal/logship"
)

// collectLogs copies this process's log to log shipping until stop, which
// waits for its last lines to go.
func collectLogs(service string) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		logship.Collect(ctx, service, os.Getenv("VALKEY_ADDR"))
	}()
	return func() {
		cancel()
		<-done
	}
}
