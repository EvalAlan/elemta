package smtp

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/antispam"
)

// rejectScanner answers every message with Rspamd's "reject" action.
type rejectScanner struct{ disposition antispam.Disposition }

func (r *rejectScanner) Connect() error    { return nil }
func (r *rejectScanner) Close() error      { return nil }
func (r *rejectScanner) IsConnected() bool { return true }
func (r *rejectScanner) Name() string      { return "reject" }
func (r *rejectScanner) Type() string      { return "stub" }
func (r *rejectScanner) ScanBytes(context.Context, []byte) (*antispam.ScanResult, error) {
	return &antispam.ScanResult{Engine: "stub", Score: 14, Threshold: 6, Disposition: r.disposition}, nil
}
func (r *rejectScanner) ScanReader(ctx context.Context, _ io.Reader) (*antispam.ScanResult, error) {
	return r.ScanBytes(ctx, nil)
}
func (r *rejectScanner) ScanFile(ctx context.Context, _ string) (*antispam.ScanResult, error) {
	return r.ScanBytes(ctx, nil)
}

func quarantineHandler(t *testing.T, d antispam.Disposition, quarantine, authenticated bool, rcpts ...string) *DataHandler {
	t.Helper()
	cfg := &Config{
		Hostname:     "mail.example.com",
		LocalDomains: []string{"Example.com"},
		Antispam:     &AntispamConfig{Enabled: true, RejectOnSpam: true, Quarantine: quarantine},
	}
	sm := NewScannerManager(cfg, nil)
	if err := sm.antispamManager.Register(&rejectScanner{disposition: d}); err != nil {
		t.Fatal(err)
	}
	dh := scanningHandler(t, sm, cfg)
	ctx := context.Background()
	dh.state.SetAuthenticated(ctx, authenticated, "user@example.com")
	if err := dh.state.SetPhase(ctx, PhaseMail); err != nil {
		t.Fatal(err)
	}
	if err := dh.state.SetMailFrom(ctx, "x@other.test"); err != nil {
		t.Fatal(err)
	}
	for _, r := range rcpts {
		if err := dh.state.AddRecipient(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	return dh
}

func scanSpam(t *testing.T, dh *DataHandler) *SecurityScanResult {
	t.Helper()
	result := &SecurityScanResult{Passed: true}
	view := &scanContent{raw: "Subject: x\r\n\r\nbody\r\n", lower: "subject: x\r\n\r\nbody\r\n", body: []byte("Subject: x\r\n\r\nbody\r\n")}
	if err := dh.performSpamScan(context.Background(), view, &MessageMetadata{MessageID: "m"}, result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestQuarantineDecision(t *testing.T) {
	tests := []struct {
		name          string
		disposition   antispam.Disposition
		quarantine    bool
		authenticated bool
		rcpts         []string
		held, passed  bool
	}{
		{"spam for a local mailbox is held", antispam.DispositionReject, true, false, []string{"a@example.com"}, true, true},
		{"several local mailboxes", antispam.DispositionReject, true, false, []string{"a@example.com", "b@EXAMPLE.com"}, true, true},
		{"quarantine off still refuses", antispam.DispositionReject, false, false, []string{"a@example.com"}, false, false},
		{"an outside recipient has no Quarantine folder", antispam.DispositionReject, true, false, []string{"a@example.com", "b@other.test"}, false, false},
		{"a logged-in sender still sees the refusal", antispam.DispositionReject, true, true, []string{"a@example.com"}, false, false},
		{"a tag isn't a reject, so nothing to hold", antispam.DispositionTag, true, false, []string{"a@example.com"}, false, true},
		{"a deferral stays temporary", antispam.DispositionDefer, true, false, []string{"a@example.com"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scanSpam(t, quarantineHandler(t, tt.disposition, tt.quarantine, tt.authenticated, tt.rcpts...))
			if r.SpamHeld != tt.held || r.Passed != tt.passed {
				t.Fatalf("held %v passed %v, want %v %v", r.SpamHeld, r.Passed, tt.held, tt.passed)
			}
		})
	}
}

// The word stays after "Yes" so a mailbox that doesn't know it files the
// message in Junk rather than the INBOX.
func TestHeldMailIsMarked(t *testing.T) {
	dh := quarantineHandler(t, antispam.DispositionReject, true, false, "a@example.com")
	result := &SecurityScanResult{Passed: true, SpamDetected: true, SpamHeld: true, SpamScore: 14, SpamThreshold: 6}
	metadata := &MessageMetadata{MessageID: "m", From: "x@other.test", To: []string{"a@example.com"}}
	headers := string(dh.buildServerHeaders(context.Background(), []byte("Subject: x\r\n\r\nbody\r\n"), metadata, result))
	if !strings.Contains(headers, "X-Spam-Status: Yes, quarantine, score=14.0/6.0") {
		t.Fatalf("headers:\n%s", headers)
	}
}

// A virus is refused however the spam check came out.
func TestAHeldVirusIsStillRefused(t *testing.T) {
	dh := quarantineHandler(t, antispam.DispositionReject, true, false, "a@example.com")
	result := &SecurityScanResult{VirusFound: true, SpamHeld: true, SpamDetected: true, Threats: []string{"Virus detected: Eicar"}}
	err := dh.handleSecurityThreat(context.Background(), result, &MessageMetadata{MessageID: "m"})
	if err == nil || !strings.Contains(err.Error(), "virus") {
		t.Fatalf("got %v", err)
	}
}

// The scans run side by side and their results are folded together, so a field
// the fold doesn't copy is lost without a trace. Held mail then went to Junk.
func TestMergeKeepsTheHold(t *testing.T) {
	for _, tt := range []struct {
		name     string
		dst, src SecurityScanResult
	}{
		{"spam scan folded in", SecurityScanResult{Passed: true}, SecurityScanResult{Passed: true, SpamDetected: true, SpamHeld: true}},
		{"spam scan folded into", SecurityScanResult{Passed: true, SpamDetected: true, SpamHeld: true}, SecurityScanResult{Passed: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dst := tt.dst
			mergeScanResult(&dst, &tt.src)
			if !dst.SpamHeld || !dst.Passed {
				t.Fatalf("merged %+v", dst)
			}
		})
	}
}

// The same fold used to drop a deferral, so Rspamd's "soft reject" reached the
// sender as a permanent 554 instead of the 451 it asked for.
func TestMergeKeepsADeferral(t *testing.T) {
	dst := SecurityScanResult{Passed: true}
	mergeScanResult(&dst, &SecurityScanResult{SpamDetected: true, SpamDefer: true})
	if !dst.SpamDefer || dst.Passed {
		t.Fatalf("merged %+v", dst)
	}
	dh := quarantineHandler(t, antispam.DispositionDefer, true, false, "a@example.com")
	err := dh.handleSecurityThreat(context.Background(), &dst, &MessageMetadata{MessageID: "m"})
	if err == nil || !strings.HasPrefix(err.Error(), "451") {
		t.Fatalf("got %v, want a temporary refusal", err)
	}
}
