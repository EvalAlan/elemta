package smtp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/EvalAlan/elemta/internal/antivirus"
)

// downScanner is a registered antivirus scanner that can't be reached.
type downScanner struct{}

func (downScanner) Connect() error    { return nil }
func (downScanner) Close() error      { return nil }
func (downScanner) IsConnected() bool { return false }
func (downScanner) Name() string      { return "down" }
func (downScanner) Type() string      { return "clamav" }
func (downScanner) ScanBytes(context.Context, []byte) (*antivirus.ScanResult, error) {
	return nil, io.ErrUnexpectedEOF
}
func (downScanner) ScanReader(context.Context, io.Reader) (*antivirus.ScanResult, error) {
	return nil, io.ErrUnexpectedEOF
}
func (downScanner) ScanFile(context.Context, string) (*antivirus.ScanResult, error) {
	return nil, io.ErrUnexpectedEOF
}

// [antivirus] reject_on_failure decides what a failed scan does: on, the
// message is deferred; off (the default), it is delivered unscanned. The
// setting used to be saved but ignored.
func TestAntivirusRejectOnFailure(t *testing.T) {
	for _, reject := range []bool{false, true} {
		cfg := &Config{Antivirus: &AntivirusConfig{Enabled: true, RejectOnFailure: reject}}
		sm := NewScannerManager(cfg, nil)
		if err := sm.antivirusManager.Register(downScanner{}); err != nil {
			t.Fatal(err)
		}
		dh := &DataHandler{config: cfg, scannerManager: sm, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		err := dh.performAntivirusScan(context.Background(), &scanContent{body: []byte("Subject: x\r\n\r\nbody\r\n")}, &SecurityScanResult{Passed: true})
		if reject && err == nil {
			t.Error("reject_on_failure on: an unscannable message was let through")
		}
		if !reject && err != nil {
			t.Errorf("reject_on_failure off: the message should be delivered unscanned, got %v", err)
		}
	}
}
