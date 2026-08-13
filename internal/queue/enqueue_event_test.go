package queue

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Every accepted message must report itself, whichever enqueue path ran.
//
// The report used to sit at the top of enqueueMessageWithID, so a backend
// reached through the streaming path never emitted it. The visible symptom was
// a throughput dashboard that was full on one storage backend and completely
// empty on another — which reads as "no mail is arriving" rather than "this
// event is not logged", and is the worst way for an observability gap to
// present itself.
func TestAcceptedMessageIsReportedOnEveryEnqueuePath(t *testing.T) {
	cases := []struct {
		name    string
		enqueue func(*Manager) (string, error)
	}{
		{"bytes", func(m *Manager) (string, error) {
			return m.EnqueueMessage("a@example.com", []string{"b@example.com"},
				"subject", []byte("hello"), PriorityNormal, time.Now())
		}},
		{"streaming", func(m *Manager) (string, error) {
			body := []byte("hello")
			open := func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
			return m.EnqueueMessageStream("a@example.com", []string{"b@example.com"},
				"subject", open, int64(len(body)), PriorityNormal, time.Now())
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			m := NewManager(t.TempDir(), 24)
			m.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

			id, err := tc.enqueue(m)
			if err != nil {
				t.Fatalf("enqueue: %v", err)
			}

			out := buf.String()
			if !strings.Contains(out, `"event_type":"message_accepted"`) {
				t.Fatalf("the %s enqueue path accepted %s without reporting it at INFO.\nlogged:\n%s",
					tc.name, id, out)
			}
			// The id ties the acceptance to the delivery of the same message;
			// without it the event cannot be correlated and is nearly useless.
			if !strings.Contains(out, id) {
				t.Errorf("the acceptance does not carry the message id %q:\n%s", id, out)
			}
		})
	}
}
