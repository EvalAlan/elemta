package queue

import (
	"strings"
	"testing"
)

func TestQueuePostgresBackendRequiresDSN(t *testing.T) {
	queueDir := t.TempDir()

	_, err := NewManagerFromBackend(
		queueDir,
		"postgres",
		SQLiteConfig{},
		PostgresConfig{},
		24,
	)
	if err == nil {
		t.Fatal("expected error when postgres backend dsn is missing")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "dsn") {
		t.Fatalf("expected error to mention dsn, got: %v", err)
	}
}
