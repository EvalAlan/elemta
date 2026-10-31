package smtp

import (
	"context"
	"log/slog"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
)

func TestConnectionLimitFollowsTheAbusePolicy(t *testing.T) {
	limits := DefaultResourceLimits()
	limits.MaxConnectionsPerIP = 100
	rm := NewResourceManager(limits, slog.Default())
	defer rm.Close()
	s := &Server{resourceManager: rm, slogger: slog.Default()}
	e := abuse.New("test", "", nil)
	s.SetAbuse(e)
	tracker := rm.ipTracker
	policy := abuse.DefaultPolicy()
	policy.ConnectionsPerAddress = 2
	policy.Allowlist = []string{"198.51.100.7"}
	if err := e.Publish(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !tracker.AddConnection("203.0.113.9") {
			t.Fatalf("connection %d refused", i+1)
		}
	}
	if tracker.CanConnect("203.0.113.9") || tracker.AddConnection("203.0.113.9") {
		t.Fatal("a third connection was accepted")
	}
	for i := 0; i < 5; i++ {
		if !tracker.AddConnection("198.51.100.7") {
			t.Fatal("an allowlisted address was limited")
		}
	}
	// Anything but enforcing goes back to the configuration file's limit.
	policy.Mode = abuse.ModeOff
	if err := e.Publish(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if !tracker.AddConnection("203.0.113.9") {
		t.Fatal("the configured limit wasn't restored")
	}
}
