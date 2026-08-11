package suppression

import (
	"context"
	"log/slog"
	"time"
)

// Recorder adapts the store to the queue's delivery path.
//
// It exists so the queue can hand every permanent failure over without knowing
// which of them deserve suppression, and without being able to fail because of
// it: recording is best effort, and a delivery must never be affected by
// whether the list could be written.
type Recorder struct {
	store  *Store
	logger *slog.Logger
}

func NewRecorder(store *Store, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{store: store, logger: logger.With("component", "suppression")}
}

// RecordFailure offers one permanently failed recipient to the list.
//
// The decision about whether it belongs there is made here rather than by the
// caller, so the rule lives in one place next to the reasoning for it.
func (r *Recorder) RecordFailure(address, code, diagnostic string) {
	if r == nil || r.store == nil {
		return
	}

	source, suppress := ShouldSuppress(code, diagnostic)
	if !suppress {
		return
	}

	// Bounded, because this runs on the delivery path: a slow or locked
	// database must not hold a delivery worker.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.store.Add(ctx, Entry{
		Address: address, Source: source, Reason: diagnostic, Code: code,
	}); err != nil {
		// Logged, not returned. The message has already failed; losing the
		// suppression is a smaller problem than turning it into a delivery
		// error, and the operator can still see the bounce in the trace.
		r.logger.Warn("Could not record a suppression", "address", address, "error", err)
		return
	}

	r.logger.Info("Address suppressed",
		"event_type", "suppression",
		"address", address,
		"source", string(source),
		"code", code,
		"reason", diagnostic,
	)
}
