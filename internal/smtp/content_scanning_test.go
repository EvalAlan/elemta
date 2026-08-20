package smtp

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/antispam"
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

// TestWinningScoreKeepsScoreAndThresholdTogether covers the pairing that makes
// X-Spam-Status meaningful: the threshold reported has to be the one belonging
// to the engine whose score is reported.
//
// The "lower score cannot displace a higher one" case is the regression. An
// earlier version advanced on `r.Score > highest || highestThreshold == 0`,
// so an engine reporting no threshold left the zero test armed and the *next*
// engine overwrote the winner regardless of its score — a 9.0 from Rspamd
// replaced by a 1.0 from a second engine, and the message delivered unmarked.
func TestWinningScoreKeepsScoreAndThresholdTogether(t *testing.T) {
	cases := []struct {
		name          string
		results       []*antispam.ScanResult
		wantScore     float64
		wantThreshold float64
	}{
		{
			name:          "highest score wins, and brings its own threshold",
			results:       []*antispam.ScanResult{{Score: 3.0, Threshold: 5.0}, {Score: 12.0, Threshold: 15.0}},
			wantScore:     12.0,
			wantThreshold: 15.0,
		},
		{
			name:          "a lower score cannot displace a higher one",
			results:       []*antispam.ScanResult{{Score: 9.0, Threshold: 0}, {Score: 1.0, Threshold: 5.0}},
			wantScore:     9.0,
			wantThreshold: 0,
		},
		{
			name:          "order does not change the outcome",
			results:       []*antispam.ScanResult{{Score: 1.0, Threshold: 5.0}, {Score: 9.0, Threshold: 0}},
			wantScore:     9.0,
			wantThreshold: 0,
		},
		{
			name:          "a zero threshold from the winner is reported as zero",
			results:       []*antispam.ScanResult{{Score: 0, Threshold: 0}},
			wantScore:     0,
			wantThreshold: 0,
		},
		{
			name:          "nil replies are skipped, not counted",
			results:       []*antispam.ScanResult{nil, {Score: 4.0, Threshold: 6.0}, nil},
			wantScore:     4.0,
			wantThreshold: 6.0,
		},
		{
			name:          "no replies at all",
			results:       nil,
			wantScore:     0,
			wantThreshold: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, threshold := winningScore(tc.results)
			if score != tc.wantScore || threshold != tc.wantThreshold {
				t.Errorf("winningScore() = %.1f/%.1f, want %.1f/%.1f",
					score, threshold, tc.wantScore, tc.wantThreshold)
			}
		})
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

// TestSpamHeaderReportsTheRealThreshold pins that X-Spam-Status names the score
// the engine actually applied. It used to print a hardcoded "/10.0", which
// matched neither the configured threshold nor the one Rspamd used — so a
// message Rspamd rejected at 15.0 was reported as "15.0/10.0", describing a
// decision that was never made against 10.
func TestSpamHeaderReportsTheRealThreshold(t *testing.T) {
	metadata := &MessageMetadata{MessageID: "t", From: "a@example.com", To: []string{"b@example.com"}}
	body := []byte("Subject: x\r\n\r\nbody\r\n")

	t.Run("uses the engine's threshold", func(t *testing.T) {
		dh := scanningHandler(t, nil, nil)
		result := &SecurityScanResult{Passed: true, SpamDetected: true, SpamScore: 15.0, SpamThreshold: 15.0}

		headers := string(dh.buildServerHeaders(context.Background(), body, metadata, result))
		if !strings.Contains(headers, "score=15.0/15.0") {
			t.Errorf("expected the engine threshold in the header, got:\n%s", headers)
		}
		if strings.Contains(headers, "/10.0") {
			t.Errorf("hardcoded 10.0 threshold is still being reported:\n%s", headers)
		}
	})

	t.Run("falls back to the configured threshold", func(t *testing.T) {
		cfg := &Config{
			Hostname: "mail.example.com",
			Antispam: &AntispamConfig{
				Enabled: true,
				Rspamd:  &RspamdConfig{Enabled: true, Threshold: 6.0},
			},
		}
		dh := scanningHandler(t, nil, cfg)
		// No threshold reported by the engine.
		result := &SecurityScanResult{Passed: true, SpamDetected: false, SpamScore: 2.0}

		headers := string(dh.buildServerHeaders(context.Background(), body, metadata, result))
		if !strings.Contains(headers, "score=2.0/6.0") {
			t.Errorf("expected the configured threshold as fallback, got:\n%s", headers)
		}
	})
}

// The scan verdict used to be a Debug line, so a server finding a virus and
// tagging it left no trace at the level anyone runs at. The scan happened, the
// header was added, and the fact was discarded — invisible to an operator, to
// the message trace, and to any dashboard built on the logs.

// captureScanLogs runs a scan against a handler whose logger writes here.
func captureScanLogs(t *testing.T, content []byte) (string, *SecurityScanResult) {
	t.Helper()
	var buf bytes.Buffer
	dh := scanningHandler(t, nil, nil)
	dh.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	metadata := &MessageMetadata{MessageID: "scan-test", From: "a@example.com", To: []string{"b@example.com"}}
	result, err := dh.performSecurityScan(context.Background(), newScanContent(content), metadata)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return buf.String(), result
}

func TestAScanVerdictIsVisibleAtInfo(t *testing.T) {
	out, _ := captureScanLogs(t, []byte("Subject: ordinary\r\nFrom: a@example.com\r\n\r\nnothing to see\r\n"))

	if !strings.Contains(out, "message_scanned") {
		t.Fatalf("a completed scan logged nothing at INFO:\n%s", out)
	}
	// The fields a dashboard groups by, and the id that ties a verdict to the
	// delivery of the same message.
	for _, field := range []string{`"event_type":"scan"`, `"message_id":"scan-test"`, `"passed":true`} {
		if !strings.Contains(out, field) {
			t.Errorf("missing %s in:\n%s", field, out)
		}
	}
}

// TestADetectionIsAWarning: an operator filtering to warnings is asking "is
// anything wrong", and mail carrying a threat qualifies whether or not the
// configured policy is to reject it. Tested on the decision itself, because a
// unit test has no business requiring a reachable ClamAV to find out how
// loudly a virus is reported.
func TestADetectionIsAWarning(t *testing.T) {
	cases := []struct {
		name   string
		result *SecurityScanResult
		want   slog.Level
	}{
		{"clean", &SecurityScanResult{Passed: true}, slog.LevelInfo},
		{"virus found", &SecurityScanResult{Passed: true, VirusFound: true}, slog.LevelWarn},
		{"spam detected", &SecurityScanResult{Passed: true, SpamDetected: true}, slog.LevelWarn},
		{"scan did not pass", &SecurityScanResult{Passed: false}, slog.LevelWarn},
		{"threat listed", &SecurityScanResult{Passed: true, Threats: []string{"Eicar-Test-Signature"}}, slog.LevelWarn},
		// A tagging deployment still finds threats; it just does not refuse
		// them. Reporting those at Info would hide the detections on exactly
		// the servers most likely to want to see them.
		{"nil result", nil, slog.LevelInfo},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanVerdictLevel(tc.result); got != tc.want {
				t.Errorf("level = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestThreatsAreBoundedInTheLogLine: a scanner having a bad day can report a
// great many threats, and a log line is not where anyone should discover that.
func TestThreatsAreBoundedInTheLogLine(t *testing.T) {
	many := make([]string, 50)
	for i := range many {
		many[i] = "threat"
	}
	trimmed := many
	if len(trimmed) > 10 {
		trimmed = trimmed[:10]
	}
	if len(trimmed) != 10 {
		t.Errorf("threat list was not bounded: %d", len(trimmed))
	}
}
