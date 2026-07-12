package queue

import (
	"strings"
	"testing"
	"time"
)

// These tests intentionally exercise the SQL seam without requiring a live
// PostgreSQL server in the default unit suite. Integration is covered when a
// configured PostgreSQL instance is available outside this package.
func TestPostgresDeterministicEnqueueSQLGuarantees(t *testing.T) {
	checks := []struct {
		name, sql, want string
	}{
		{"cross-process transaction lock", postgresEnqueueLockSQL, "pg_advisory_xact_lock"},
		{"stable 64-bit text key", postgresEnqueueLockSQL, "hashtextextended($1, 0)"},
		{"live insert is non-destructive", postgresCreateMessageSQL, "ON CONFLICT (id) DO NOTHING"},
		{"tombstone is non-destructive", postgresInsertTombstoneSQL, "ON CONFLICT(id) DO NOTHING"},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.sql, tc.want) {
				t.Fatalf("SQL %q does not contain %q", tc.sql, tc.want)
			}
		})
	}
	if strings.Contains(strings.ToUpper(postgresInsertTombstoneSQL), "DO UPDATE") {
		t.Fatal("tombstone SQL may overwrite the first consumed identity")
	}
}

func TestPostgresTombstoneSchemaIsDurableAndIdempotent(t *testing.T) {
	// Keep the migration contract visible in a unit test: this table is neither
	// temporary nor tied by a cascading FK to the live queue row.
	if !strings.Contains(postgresTombstoneSchemaSQL, "CREATE TABLE IF NOT EXISTS queue_enqueue_tombstones") || strings.Contains(postgresTombstoneSchemaSQL, "TEMP") {
		t.Fatal("tombstone migration must create a durable table idempotently")
	}
	if !strings.Contains(postgresTombstoneSchemaSQL, "id TEXT PRIMARY KEY") || strings.Contains(postgresTombstoneSchemaSQL, "REFERENCES queue_messages") {
		t.Fatal("tombstone identity must be unique and survive live-row cascade deletion")
	}
}

func TestPostgresEnqueueIdentityIgnoresMutableLifecycle(t *testing.T) {
	at := time.Unix(123, 456).UTC()
	a := Message{ID: "stable", From: "a@example", To: []string{"b@example"}, Domain: "example", Subject: "s", Size: 4, Priority: PriorityHigh, ReceivedAt: at, QueueType: Active}
	b := a
	b.QueueType = Deferred
	b.RetryCount = 9
	b.LastError = "temporary"
	b.UpdatedAt = at.Add(time.Hour)
	if !sameEnqueueMessage(a, b) {
		t.Fatal("mutable delivery lifecycle fields changed enqueue identity")
	}
	b.Subject = "different"
	if sameEnqueueMessage(a, b) {
		t.Fatal("immutable payload change was accepted")
	}
}
