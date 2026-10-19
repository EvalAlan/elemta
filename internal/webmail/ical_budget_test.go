package webmail

import (
	"testing"
	"time"
)

// The public calendar view uses a shared budget; tests of a single event use
// this wrapper to exercise the same iterator with a standalone budget.
func (e *Event) occurrences(from, to time.Time) []Occurrence {
	budget := maxRecurrenceSteps
	return e.occurrencesBudget(from, to, &budget, time.Now().Add(100*time.Millisecond))
}

func TestDenseOldRecurrenceIsBounded(t *testing.T) {
	start := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	e := Event{Start: start, End: start.Add(time.Hour), RRule: "FREQ=SECONDLY"}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	begin := time.Now()
	got := e.occurrences(from, from.Add(30*24*time.Hour))
	if len(got) > maxOccurrences || time.Since(begin) > 2*time.Second {
		t.Fatalf("dense recurrence produced %d instances in %v", len(got), time.Since(begin))
	}
}

func TestCalendarViewHasSharedOccurrenceLimit(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := make([]Event, 20)
	for i := range events {
		events[i] = Event{Start: start, End: start.Add(time.Minute), RRule: "FREQ=MINUTELY"}
	}
	got := expand(events, start, start.Add(30*24*time.Hour))
	if len(got) > maxViewOccurrences {
		t.Fatalf("view expanded %d instances", len(got))
	}
}
