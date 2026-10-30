package datasource

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Values reach SanitizeInput before anyone knows what they are, and a password
// can easily look like an injection attempt.
func TestSanitizeInputDoesNotLogTheValue(t *testing.T) {
	var logs bytes.Buffer
	sm := NewSQLSecurityManager(slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := sm.SanitizeInput("hunter2 union select secret from x"); err == nil {
		t.Fatal("the injection pattern wasn't refused")
	}
	if logs.Len() == 0 {
		t.Fatal("the refusal wasn't logged")
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatalf("the value reached the log: %s", logs.String())
	}
}
