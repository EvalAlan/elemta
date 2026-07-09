package smtp

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsImplementsRecorder verifies the Prometheus Metrics type satisfies
// queue.MetricsRecorder and that each callback moves the right counter. Uses
// before/after deltas so it is independent of the singleton's prior state.
func TestMetricsRecorderIncrements(t *testing.T) {
	m := GetMetrics()
	ctx := context.Background()

	before := testutil.ToFloat64(m.DeliverySuccesses)
	if err := m.IncrDelivered(ctx); err != nil {
		t.Fatalf("IncrDelivered: %v", err)
	}
	if got := testutil.ToFloat64(m.DeliverySuccesses); got != before+1 {
		t.Errorf("DeliverySuccesses = %v, want %v", got, before+1)
	}

	beforeF := testutil.ToFloat64(m.DeliveryFailures)
	if err := m.IncrFailed(ctx); err != nil {
		t.Fatalf("IncrFailed: %v", err)
	}
	if got := testutil.ToFloat64(m.DeliveryFailures); got != beforeF+1 {
		t.Errorf("DeliveryFailures = %v, want %v", got, beforeF+1)
	}

	beforeD := testutil.ToFloat64(m.DeliveryDeferred)
	if err := m.IncrDeferred(ctx); err != nil {
		t.Fatalf("IncrDeferred: %v", err)
	}
	if got := testutil.ToFloat64(m.DeliveryDeferred); got != beforeD+1 {
		t.Errorf("DeliveryDeferred = %v, want %v", got, beforeD+1)
	}

	// AddRecentError is a no-op for Prometheus but must not error.
	if err := m.AddRecentError(ctx, "id", "rcpt@example.com", "boom"); err != nil {
		t.Fatalf("AddRecentError: %v", err)
	}
}

func TestSetQueueSizes(t *testing.T) {
	m := GetMetrics()
	m.SetQueueSizes(3, 5, 1, 2)

	if got := testutil.ToFloat64(m.QueueSize.WithLabelValues("active")); got != 3 {
		t.Errorf("active queue gauge = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.QueueSize.WithLabelValues("deferred")); got != 5 {
		t.Errorf("deferred queue gauge = %v, want 5", got)
	}
	if got := testutil.ToFloat64(m.QueueSize.WithLabelValues("hold")); got != 1 {
		t.Errorf("hold queue gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.QueueSize.WithLabelValues("failed")); got != 2 {
		t.Errorf("failed queue gauge = %v, want 2", got)
	}
}
