package api

import (
	"strings"
	"testing"
)

// A trace is an operator's answer to "where did this message go", so these
// tests are about it being complete, in order, and honest about what it does
// not know.

func logEntry(eventType, time string, fields map[string]interface{}) MessageLog {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	return MessageLog{Time: time, Level: "INFO", EventType: eventType, Fields: fields}
}

func TestBuildTraceOrdersEventsAndReportsTheOutcome(t *testing.T) {
	entries := []MessageLog{
		// Deliberately out of order: the assembly must not depend on the caller.
		logEntry("delivery", "2026-08-10T10:00:09Z", map[string]interface{}{
			"delivery_host": "mx.example.net", "delivery_method": "smtp",
		}),
		logEntry("message_accepted", "2026-08-10T10:00:00Z", map[string]interface{}{
			"from_envelope": "sender@example.com",
			"to_envelope":   []interface{}{"user@example.net"},
			"subject":       "Hello",
			"queue_type":    "active",
		}),
		logEntry("deferral", "2026-08-10T10:00:04Z", map[string]interface{}{
			"error": "451 4.3.0 try again later",
		}),
	}

	trace := buildTrace("msg-1", entries)

	if len(trace.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(trace.Events))
	}
	if trace.Events[0].Time > trace.Events[1].Time || trace.Events[1].Time > trace.Events[2].Time {
		t.Errorf("events are not in chronological order: %v", []string{
			trace.Events[0].Time, trace.Events[1].Time, trace.Events[2].Time})
	}
	// The last thing that happened is what the message's standing is.
	if trace.Outcome != "delivered" {
		t.Errorf("outcome = %q, want delivered", trace.Outcome)
	}

	// Envelope details come from whichever event carried them.
	if trace.From != "sender@example.com" || trace.Subject != "Hello" {
		t.Errorf("envelope not picked up: from=%q subject=%q", trace.From, trace.Subject)
	}
	if len(trace.To) != 1 || trace.To[0] != "user@example.net" {
		t.Errorf("recipients not picked up: %v", trace.To)
	}

	// The remote's own words are what an operator needs from a deferral.
	var deferral TraceEvent
	for _, e := range trace.Events {
		if e.Event == "deferral" {
			deferral = e
		}
	}
	if deferral.Detail != "451 4.3.0 try again later" {
		t.Errorf("the remote's reply should be surfaced, got %q", deferral.Detail)
	}
	if deferral.Summary == "" {
		t.Error("every event needs a readable summary")
	}
}

// TestBuildTraceKeepsUnknownEvents: an event type this code has not been taught
// about must still appear. Dropping it would make the timeline look complete
// while hiding the step that explains the problem.
func TestBuildTraceKeepsUnknownEvents(t *testing.T) {
	entries := []MessageLog{
		{Time: "2026-08-10T10:00:00Z", EventType: "something_new", Message: "a thing happened",
			Fields: map[string]interface{}{"detail": "x"}},
	}
	trace := buildTrace("msg-2", entries)
	if len(trace.Events) != 1 {
		t.Fatalf("unknown event was dropped")
	}
	if trace.Events[0].Summary != "a thing happened" {
		t.Errorf("summary = %q, want the log's own message", trace.Events[0].Summary)
	}
}

// TestBuildTraceSaysWhenItFoundNothing distinguishes "this message does not
// exist" from an empty timeline that looks like a delivered message.
func TestBuildTraceSaysWhenItFoundNothing(t *testing.T) {
	trace := buildTrace("msg-3", nil)
	if trace.Outcome != "not found" {
		t.Errorf("outcome = %q, want 'not found'", trace.Outcome)
	}
	if trace.Events == nil {
		t.Error("events should be an empty list, not null, so the UI can render it")
	}
}

// TestDetectionIsNotDisposition: a message can be classified as spam and still
// be delivered — reject_on_spam=false is the default. Reading detection as an
// outcome made a trace report "refused" about a message that had gone out,
// which is worse than reporting nothing. Found by tracing a real delivery.
func TestDetectionIsNotDisposition(t *testing.T) {
	for _, event := range []string{"spam_detected", "virus_detected"} {
		if got := outcomeFor(logEntry(event, "t", nil)); got != "" {
			t.Errorf("%s settled the outcome as %q; detection is an observation, not a disposition", event, got)
		}
		summary, _ := describeEvent(logEntry(event, "t", nil))
		if strings.Contains(strings.ToLower(summary), "refused") {
			t.Errorf("%s summary claims a refusal that may not have happened: %q", event, summary)
		}
	}

	// The full sequence: flagged, then delivered anyway.
	trace := buildTrace("msg-4", []MessageLog{
		logEntry("spam_detected", "2026-08-10T10:00:00Z", nil),
		logEntry("delivery", "2026-08-10T10:00:01Z", nil),
	})
	if trace.Outcome != "delivered" {
		t.Errorf("outcome = %q, want delivered", trace.Outcome)
	}
}

func TestOutcomeForFallsBackToStatus(t *testing.T) {
	e := logEntry("", "2026-08-10T10:00:00Z", map[string]interface{}{"status": "delivered"})
	if got := outcomeFor(e); got != "delivered" {
		t.Errorf("outcomeFor = %q, want the status field", got)
	}
	if got := outcomeFor(logEntry("", "t", nil)); got != "" {
		t.Errorf("an event that settles nothing should report nothing, got %q", got)
	}
}

func TestDescribeEventDoesNotRepeatItself(t *testing.T) {
	// When the detail and the summary would be the same string, showing both
	// is just noise.
	e := MessageLog{EventType: "unknown_thing", Message: "same text",
		Fields: map[string]interface{}{"message": "same text"}}
	summary, detail := describeEvent(e)
	if summary != "same text" || detail != "" {
		t.Errorf("summary=%q detail=%q, want the duplicate detail dropped", summary, detail)
	}
}

func TestStringsFieldAcceptsBothShapes(t *testing.T) {
	list := stringsField(map[string]interface{}{"to": []interface{}{"a@example.com", "b@example.com"}}, "to")
	if len(list) != 2 {
		t.Errorf("list form: got %v", list)
	}
	// Some events log a single recipient as a bare string.
	single := stringsField(map[string]interface{}{"to": "a@example.com"}, "to")
	if len(single) != 1 || single[0] != "a@example.com" {
		t.Errorf("string form: got %v", single)
	}
	if got := stringsField(map[string]interface{}{"to": ""}, "to"); got != nil {
		t.Errorf("an empty value is not a recipient: %v", got)
	}
}
