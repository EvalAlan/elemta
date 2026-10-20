package queue

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Aggregate counters say whether the queue is moving. They cannot say that one
// receiver has been deferring everything for an hour while the rest of the
// world is fine — which is the question an operator actually has, and the one
// that decides whether to change something or wait.

func TestOutcomesAreAttributedToTheirDestination(t *testing.T) {
	capture := &metricCapture{}
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{capture}}

	p.recordDomainOutcomes(&DeliveryResult{RecipientOutcomes: []RecipientOutcome{
		{Recipient: "a@gmail.com", Status: RecipientDelivered},
		{Recipient: "b@gmail.com", Status: RecipientTemporaryFailure},
		{Recipient: "c@gmail.com", Status: RecipientPermanentFailure},
		{Recipient: "d@other.example", Status: RecipientDelivered},
	}})

	got := strings.Join(capture.domains, " ")
	for _, want := range []string{
		"gmail.com:delivered", "gmail.com:deferred", "gmail.com:bounced",
		"other.example:delivered",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if len(capture.domains) != 4 {
		t.Errorf("recorded %d outcomes for 4 recipients: %v", len(capture.domains), capture.domains)
	}
}

// TestAPartlyDeliveredMessageIsCountedBothWays. A message can be delivered to
// one recipient and deferred for another, and the counting happens before the
// success/failure branch precisely so that a domain deferring half our mail
// does not look perfect.
func TestAPartlyDeliveredMessageIsCountedBothWays(t *testing.T) {
	capture := &metricCapture{}
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{capture}}

	p.recordDomainOutcomes(&DeliveryResult{
		Success: false,
		RecipientOutcomes: []RecipientOutcome{
			{Recipient: "ok@slow.example", Status: RecipientDelivered},
			{Recipient: "wait@slow.example", Status: RecipientTemporaryFailure},
		},
	})

	joined := strings.Join(capture.domains, " ")
	if !strings.Contains(joined, "slow.example:delivered") || !strings.Contains(joined, "slow.example:deferred") {
		t.Errorf("a partly delivered message was not counted both ways: %v", capture.domains)
	}
}

// TestDestinationIsTakenFromTheAddressNotTheRoute. Several MX hosts serve one
// domain, so counting by host would split a destination's record across rows
// that each look fine on their own.
func TestDestinationIsTakenFromTheAddressNotTheRoute(t *testing.T) {
	capture := &metricCapture{}
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{capture}}

	p.recordDomainOutcomes(&DeliveryResult{RecipientOutcomes: []RecipientOutcome{
		{Recipient: "a@example.com", Status: RecipientDelivered, Route: "mx1.example.com"},
		{Recipient: "b@example.com", Status: RecipientDelivered, Route: "mx2.example.com"},
	}})

	for _, entry := range capture.domains {
		if entry != "example.com:delivered" {
			t.Errorf("outcome recorded against %q; the destination is the address domain, not the MX", entry)
		}
	}
}

// TestUnusableRecipientsAreNotCounted: a row attributed to an empty domain
// means nothing and cannot be acted on.
func TestUnusableRecipientsAreNotCounted(t *testing.T) {
	capture := &metricCapture{}
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{capture}}

	p.recordDomainOutcomes(&DeliveryResult{RecipientOutcomes: []RecipientOutcome{
		{Recipient: "no-domain-here", Status: RecipientDelivered},
		{Recipient: "", Status: RecipientDelivered},
		{Recipient: "fine@example.com", Status: RecipientDelivered},
	}})

	if len(capture.domains) != 1 || capture.domains[0] != "example.com:delivered" {
		t.Errorf("recorded %v; only the usable recipient should count", capture.domains)
	}
}

// TestUnknownStatusesAreSkipped rather than guessed at. A status this code does
// not recognise is not evidence of anything.
func TestUnknownStatusesAreSkipped(t *testing.T) {
	capture := &metricCapture{}
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{capture}}

	p.recordDomainOutcomes(&DeliveryResult{RecipientOutcomes: []RecipientOutcome{
		{Recipient: "a@example.com", Status: RecipientDeliveryStatus("something-new")},
	}})

	if len(capture.domains) != 0 {
		t.Errorf("an unrecognised status was counted as something: %v", capture.domains)
	}
}

// TestNilResultIsSafe: the delivery path can produce no result at all.
func TestNilResultIsSafe(t *testing.T) {
	p := &Processor{ctx: context.Background(), metricsRecorders: []MetricsRecorder{&metricCapture{}}}
	p.recordDomainOutcomes(nil)
}

// TestProcessedMessagesFeedTheReports drives a message through the processor
// rather than calling the recorder directly: per-recipient outcomes are how
// every delivery reports now, and their handling used to return before the
// per-destination counts and the recent-error list were written, which left
// the dashboard's Reports page empty while mail flowed.
func TestProcessedMessagesFeedTheReports(t *testing.T) {
	m := NewManager(t.TempDir(), 0)
	defer m.Stop()
	id, _ := m.EnqueueMessage("sender@example.test", []string{"ok@good.example", "bad@dead.example"}, "s", []byte("body"), PriorityNormal, time.Now())
	msg, _ := m.GetMessage(id)
	capture := &metricCapture{}
	p := NewProcessor(m, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{
		{Recipient: msg.To[0], Status: RecipientDelivered},
		{Recipient: msg.To[1], Status: RecipientPermanentFailure, EnhancedStatusCode: "5.1.1", Diagnostic: "550 5.1.1 no such user"},
	}}, err: errors.New("partial")})
	p.SetBounceEngine(&bounceCapture{})
	p.SetMetricsRecorder(capture)
	runMessage(t, p, msg)

	got := strings.Join(capture.domains, " ")
	if !strings.Contains(got, "good.example:delivered") || !strings.Contains(got, "dead.example:bounced") {
		t.Errorf("per-destination outcomes = %v", capture.domains)
	}
	if len(capture.recent) != 1 || !strings.Contains(capture.recent[0], "550 5.1.1 no such user") {
		t.Errorf("recent errors = %v; the bounced recipient's reason should be listed", capture.recent)
	}
}
