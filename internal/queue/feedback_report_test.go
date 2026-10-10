package queue

import "testing"

type fakeFeedbackRecorder struct {
	reports int
}

func (f *fakeFeedbackRecorder) RecordFailure(address, code, diagnostic string) {}
func (f *fakeFeedbackRecorder) RecordFeedbackReport(raw []byte)                { f.reports++ }

func TestFeedbackReportsAreOnlyReadFromFeedbackAddresses(t *testing.T) {
	rec := &fakeFeedbackRecorder{}
	p := &Processor{}
	p.SetSuppressionRecorder(rec)
	p.SetFeedbackAddresses([]string{" <FBL@Sender.example> "})

	p.offerFeedbackReport(Message{To: []string{"someone@sender.example"}}, []byte("x"))
	if rec.reports != 0 {
		t.Fatal("mail to an ordinary address was read as a complaint report")
	}

	p.offerFeedbackReport(Message{To: []string{"fbl@sender.example"}}, []byte("x"))
	if rec.reports != 1 {
		t.Fatalf("report to the feedback address read %d times, want 1", rec.reports)
	}

	p.offerFeedbackReport(Message{To: []string{"fbl@sender.example"}, RetryCount: 2}, []byte("x"))
	if rec.reports != 1 {
		t.Error("a retried delivery of the same report was counted again")
	}
}
