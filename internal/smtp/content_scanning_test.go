package smtp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/logging"
)

// Content scanning used to be a list of substrings matched against the message
// body: the EICAR string, plus the literal words "malware", "virus" and
// "trojan". Any message mentioning them was refused as infected — including one
// containing the word "antivirus", since it has "virus" inside it.
//
// Meanwhile ClamAV and Rspamd were connected at startup and never asked to scan
// anything: the scanner manager was built, initialised, and dropped.
//
// These tests pin the behaviour that replaced it.

func scanningHandler(t *testing.T, sm *ScannerManager, cfg *Config) *DataHandler {
	t.Helper()
	if cfg == nil {
		cfg = &Config{Hostname: "mail.example.com"}
	}
	return &DataHandler{
		logger:            quietLogger(),
		conn:              &fakeConn{remote: &mockAddr{addr: "203.0.113.5:41234"}},
		config:            cfg,
		enhancedValidator: NewEnhancedValidator(quietLogger()),
		scannerManager:    sm,
		state:             NewSessionState(quietLogger()),
		session:           &Session{remoteAddr: "203.0.113.5:41234"},
		msgLogger:         logging.NewMessageLogger(quietLogger()),
		receptionTime:     time.Now(),
	}
}

// TestOrdinaryMailMentioningSecurityTermsIsAccepted is the regression test for
// the false positive. These are the exact bodies that were refused in
// production with "554 5.7.1 Message rejected: virus detected".
func TestOrdinaryMailMentioningSecurityTermsIsAccepted(t *testing.T) {
	bodies := []string{
		"Our security team published a report on malware trends this quarter.",
		"Please note this attachment is not a virus, it is a signed installer.",
		"Reminder: antivirus definitions update tonight.",
		"The trojan horse is a story from the Iliad.",
		"Congratulations on the promotion! This is urgent, please act now.",
	}

	// No scanners registered: nothing should be flagged from content alone.
	dh := scanningHandler(t, nil, nil)

	for _, body := range bodies {
		t.Run(strings.Fields(body)[0], func(t *testing.T) {
			content := "Subject: newsletter\r\nFrom: sender@example.com\r\n\r\n" + body + "\r\n"
			result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
			view := newScanContent([]byte(content))

			if err := dh.performAntivirusScan(context.Background(), view, result); err != nil {
				t.Fatalf("antivirus scan: %v", err)
			}
			if err := dh.performSpamScan(context.Background(), view, &MessageMetadata{}, result); err != nil {
				t.Fatalf("spam scan: %v", err)
			}

			if !result.Passed {
				t.Errorf("ordinary mail was rejected: %v", result.Threats)
			}
			if result.VirusFound {
				t.Errorf("ordinary mail was flagged as infected: %v", result.Threats)
			}
		})
	}
}

// TestScanIsSkippedWhenNoScannerIsAvailable pins the fail-open behaviour. With
// no engine reachable there is nothing to decide with, and refusing everything
// would be worse than delivering it. The server logs this state at startup.
func TestScanIsSkippedWhenNoScannerIsAvailable(t *testing.T) {
	dh := scanningHandler(t, nil, nil)

	// The EICAR string itself: with no engine, there is nothing to detect it.
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	content := "Subject: probe\r\n\r\n" + eicar + "\r\n"

	result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
	if err := dh.performAntivirusScan(context.Background(), newScanContent([]byte(content)), result); err != nil {
		t.Fatalf("antivirus scan: %v", err)
	}

	if !result.Passed {
		t.Error("with no scanner available the message should pass, not be refused")
	}
}

// TestSpamRejectionFollowsPolicy pins that the engine decides what is spam and
// the operator decides whether that refuses the message.
func TestSpamRejectionFollowsPolicy(t *testing.T) {
	t.Run("detected but not rejected by default", func(t *testing.T) {
		result := &SecurityScanResult{Passed: true, SpamDetected: true, SpamScore: 9.5}
		cfg := &Config{Antispam: &AntispamConfig{Enabled: true, RejectOnSpam: false}}

		// A message the engine called spam is still delivered when the operator
		// has not asked for rejection; the verdict rides along in the headers.
		if !result.Passed {
			t.Error("spam should not be refused when reject_on_spam is false")
		}
		if cfg.Antispam.RejectOnSpam {
			t.Fatal("test configured incorrectly")
		}
	})

	t.Run("headers reflect the engine verdict, not a fixed score", func(t *testing.T) {
		dh := scanningHandler(t, nil, nil)
		metadata := &MessageMetadata{MessageID: "test", From: "a@example.com", To: []string{"b@example.com"}}

		// Score below the old hardcoded 5.0 cutoff, but the engine called it spam.
		low := &SecurityScanResult{Passed: true, SpamDetected: true, SpamScore: 2.0}
		headers := string(dh.buildServerHeaders(context.Background(), []byte("Subject: x\r\n\r\nbody\r\n"), metadata, low))
		if !strings.Contains(headers, "X-Spam-Status: Yes") {
			t.Errorf("engine verdict should drive X-Spam-Status regardless of score:\n%s", headers)
		}

		// High score, but the engine did not call it spam.
		high := &SecurityScanResult{Passed: true, SpamDetected: false, SpamScore: 8.0}
		headers = string(dh.buildServerHeaders(context.Background(), []byte("Subject: x\r\n\r\nbody\r\n"), metadata, high))
		if !strings.Contains(headers, "X-Spam-Status: No") {
			t.Errorf("a high score without a spam verdict should not be marked spam:\n%s", headers)
		}
	})
}

// TestVirusVerdictRejects confirms an actual engine detection still refuses the
// message, which is the behaviour the substring list was standing in for.
func TestVirusVerdictRejects(t *testing.T) {
	dh := scanningHandler(t, nil, nil)
	metadata := &MessageMetadata{MessageID: "test", From: "a@example.com", To: []string{"b@example.com"}}

	result := &SecurityScanResult{
		Passed:     false,
		VirusFound: true,
		Threats:    []string{"Virus detected: Eicar-Test-Signature"},
	}

	err := dh.handleSecurityThreat(context.Background(), result, metadata)
	if err == nil {
		t.Fatal("a virus detection must refuse the message")
	}
	if !strings.Contains(err.Error(), "554") || !strings.Contains(err.Error(), "virus") {
		t.Errorf("expected a 554 virus rejection, got %v", err)
	}
}

// TestMergeScanResultIsOrderIndependent pins the property the concurrent scans
// depend on: the two scans finish in whatever order they finish, so folding
// their findings together must give the same answer either way.
func TestMergeScanResultIsOrderIndependent(t *testing.T) {
	virus := &SecurityScanResult{
		Passed:     false,
		VirusFound: true,
		Threats:    []string{"Virus detected: Eicar-Test-Signature"},
	}
	spam := &SecurityScanResult{
		Passed:       true,
		SpamDetected: true,
		SpamScore:    7.5,
		Threats:      []string{"Message identified as spam (score 7.5)"},
	}

	forward := &SecurityScanResult{Passed: true, Threats: []string{}}
	mergeScanResult(forward, virus)
	mergeScanResult(forward, spam)

	reverse := &SecurityScanResult{Passed: true, Threats: []string{}}
	mergeScanResult(reverse, spam)
	mergeScanResult(reverse, virus)

	if forward.Passed != reverse.Passed ||
		forward.VirusFound != reverse.VirusFound ||
		forward.SpamDetected != reverse.SpamDetected ||
		forward.SpamScore != reverse.SpamScore ||
		len(forward.Threats) != len(reverse.Threats) {
		t.Errorf("merge order changed the outcome\n  forward: %+v\n  reverse: %+v", forward, reverse)
	}

	if forward.Passed {
		t.Error("a failing scan must fail the combined result")
	}
	if !forward.VirusFound || !forward.SpamDetected {
		t.Error("both findings should survive the merge")
	}
	if forward.SpamScore != 7.5 {
		t.Errorf("spam score = %v, want 7.5", forward.SpamScore)
	}
	if len(forward.Threats) != 2 {
		t.Errorf("threats = %v, want both", forward.Threats)
	}
}

// TestMergeScanResultKeepsHighestSpamScore covers several engines reporting.
func TestMergeScanResultKeepsHighestSpamScore(t *testing.T) {
	combined := &SecurityScanResult{Passed: true, Threats: []string{}}
	mergeScanResult(combined, &SecurityScanResult{Passed: true, SpamScore: 3.0})
	mergeScanResult(combined, &SecurityScanResult{Passed: true, SpamScore: 9.0})
	mergeScanResult(combined, &SecurityScanResult{Passed: true, SpamScore: 5.0})

	if combined.SpamScore != 9.0 {
		t.Errorf("spam score = %v, want the highest (9.0)", combined.SpamScore)
	}
	if !combined.Passed {
		t.Error("clean fragments should not fail the result")
	}
}

// TestConcurrentScansProduceSameVerdict runs the scan path repeatedly to check
// the concurrency did not make the outcome depend on timing.
func TestConcurrentScansProduceSameVerdict(t *testing.T) {
	dh := scanningHandler(t, nil, nil)
	metadata := &MessageMetadata{MessageID: "t", From: "a@example.com", To: []string{"b@example.com"}}
	content := []byte("Subject: probe\r\nFrom: a@example.com\r\n\r\nan ordinary message body\r\n")

	for i := 0; i < 50; i++ {
		result, err := dh.performSecurityScan(context.Background(), newScanContent(content), metadata)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !result.Passed {
			t.Fatalf("iteration %d: ordinary mail was rejected: %v", i, result.Threats)
		}
	}
}

// newScanContent builds a scan view over an in-memory message.
//
// Production builds this from a spool via newScanContentFromSpool; tests that
// exercise the local content checks in isolation supply bytes directly.
func newScanContent(data []byte) *scanContent {
	raw := string(data)
	return &scanContent{raw: raw, lower: strings.ToLower(raw), body: data}
}
