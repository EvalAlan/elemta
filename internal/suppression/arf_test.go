package suppression

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// Modelled on the example in RFC 5965 appendix B.
const arfReport = "From: <abusedesk@example.com>\r\n" +
	"Date: Thu, 8 Mar 2026 14:00:00 EDT\r\n" +
	"Subject: FW: Earn money\r\n" +
	"To: <fbl@sender.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/report; report-type=feedback-report;\r\n" +
	"     boundary=\"part1_13d.2e68ed54_boundary\"\r\n" +
	"\r\n" +
	"--part1_13d.2e68ed54_boundary\r\n" +
	"Content-Type: text/plain; charset=\"US-ASCII\"\r\n" +
	"\r\n" +
	"This is an email abuse report for an email message received from IP\r\n" +
	"192.0.2.1 on Thu, 8 Mar 2026 14:00:00 EDT.\r\n" +
	"--part1_13d.2e68ed54_boundary\r\n" +
	"Content-Type: message/feedback-report\r\n" +
	"\r\n" +
	"Feedback-Type: abuse\r\n" +
	"User-Agent: SomeGenerator/1.0\r\n" +
	"Version: 1\r\n" +
	"Original-Mail-From: <somespammer@sender.example>\r\n" +
	"Original-Rcpt-To: <User@Example.com>\r\n" +
	"Arrival-Date: Thu, 8 Mar 2026 14:00:00 EDT\r\n" +
	"Reported-Domain: sender.example\r\n" +
	"Source-IP: 192.0.2.1\r\n" +
	"\r\n" +
	"--part1_13d.2e68ed54_boundary\r\n" +
	"Content-Type: message/rfc822\r\n" +
	"Content-Disposition: inline\r\n" +
	"\r\n" +
	"From: <somespammer@sender.example>\r\n" +
	"Received: from mailserver.example.net (mailserver.example.net [192.0.2.1])\r\n" +
	"To: <Undisclosed Recipients>\r\n" +
	"Subject: Earn money\r\n" +
	"\r\n" +
	"Spam Spam Spam\r\n" +
	"--part1_13d.2e68ed54_boundary--\r\n"

func TestParseFeedbackReport(t *testing.T) {
	report, err := ParseFeedbackReport([]byte(arfReport))
	if err != nil {
		t.Fatal(err)
	}
	if report.FeedbackType != "abuse" || !report.IsComplaint() {
		t.Errorf("feedback type %q, complaint %v", report.FeedbackType, report.IsComplaint())
	}
	if len(report.Recipients) != 1 || report.Recipients[0] != "user@example.com" {
		t.Errorf("recipients %v, want [user@example.com]", report.Recipients)
	}
	if report.SourceIP != "192.0.2.1" || report.ReportedDomain != "sender.example" {
		t.Errorf("source %q domain %q", report.SourceIP, report.ReportedDomain)
	}
}

// Several providers redact Original-Rcpt-To; the original message's To header
// is then the only place the recipient appears.
func TestParseFeedbackReportFallsBackToOriginalTo(t *testing.T) {
	raw := strings.Replace(arfReport, "Original-Rcpt-To: <User@Example.com>\r\n", "", 1)
	raw = strings.Replace(raw, "To: <Undisclosed Recipients>", "To: Bob <bob@example.org>", 1)
	report, err := ParseFeedbackReport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Recipients) != 1 || report.Recipients[0] != "bob@example.org" {
		t.Errorf("recipients %v, want [bob@example.org]", report.Recipients)
	}
}

func TestNotSpamIsNotAComplaint(t *testing.T) {
	report, err := ParseFeedbackReport([]byte(strings.Replace(arfReport, "Feedback-Type: abuse", "Feedback-Type: not-spam", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if report.IsComplaint() {
		t.Error("a not-spam report must not suppress anyone")
	}
}

func TestOrdinaryMailIsNotAReport(t *testing.T) {
	raw := "From: a@example.com\r\nTo: fbl@sender.example\r\nSubject: hi\r\n\r\nhello\r\n"
	if _, err := ParseFeedbackReport([]byte(raw)); err == nil {
		t.Fatal("plain mail parsed as a report")
	}
	other := strings.Replace(arfReport, "report-type=feedback-report", "report-type=delivery-status", 1)
	if _, err := ParseFeedbackReport([]byte(other)); err == nil {
		t.Fatal("a DSN parsed as a feedback report")
	}
}

func TestRecorderSuppressesComplainers(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rec := NewRecorder(store, nil)

	rec.RecordFeedbackReport([]byte(arfReport))

	entry, ok, err := store.IsSuppressed(context.Background(), "user@example.com")
	if err != nil || !ok {
		t.Fatalf("complainer not suppressed: ok=%v err=%v", ok, err)
	}
	if entry.Source != SourceComplaint {
		t.Errorf("source %q, want complaint", entry.Source)
	}

	rec.RecordFeedbackReport([]byte(strings.Replace(
		strings.Replace(arfReport, "Feedback-Type: abuse", "Feedback-Type: not-spam", 1),
		"User@Example.com", "happy@example.com", 1)))
	if _, ok, _ := store.IsSuppressed(context.Background(), "happy@example.com"); ok {
		t.Error("a not-spam report suppressed its recipient")
	}
}

func TestComplaintObserverSeesEveryComplaint(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rec := NewRecorder(store, nil)
	var seen []FeedbackReport
	rec.OnComplaint(func(r FeedbackReport) { seen = append(seen, r) })

	rec.RecordFeedbackReport([]byte(arfReport))
	// A report with the recipient redacted is still a complaint about our
	// mail and must be counted, even though there is no one to suppress.
	redacted := strings.Replace(arfReport, "Original-Rcpt-To: <User@Example.com>\r\n", "", 1)
	redacted = strings.Replace(redacted, "To: <Undisclosed Recipients>\r\n", "", 1)
	rec.RecordFeedbackReport([]byte(redacted))
	// Not complaints: not counted.
	rec.RecordFeedbackReport([]byte(strings.Replace(arfReport, "Feedback-Type: abuse", "Feedback-Type: not-spam", 1)))
	rec.RecordFeedbackReport([]byte("Subject: hello\r\n\r\njust mail\r\n"))

	if len(seen) != 2 {
		t.Fatalf("observer saw %d reports, want 2", len(seen))
	}
	if seen[0].SourceIP != "192.0.2.1" || len(seen[0].Recipients) != 1 {
		t.Errorf("first report = %+v", seen[0])
	}
}
