package antispam

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Every scanner this package can build must actually talk to its engine.
//
// This exists because the Rspamd client did not. It matched the GTUBE string
// locally and fabricated a score of 100 with a rule named GTUBE_TEST, while its
// only real request was /ping — which is what produced "registered and
// connected" at startup. ScanFile returned "not supported". All of it passed
// the tests it shipped with, because those tests asserted the shape of the
// result rather than that any work happened.
//
// The property below is what distinguishes the two: a scanner pointed at an
// address where nothing is listening cannot know whether a message is clean, so
// it must report a failure. A local pattern-matcher answers cheerfully and
// fails this test.

// deadAddress is a port nothing listens on. Rspamd is addressed by URL.
const deadAddress = "127.0.0.1:1"

func scannerAddress(scannerType string) string {
	if scannerType == "rspamd" {
		return "http://" + deadAddress
	}
	return deadAddress
}

func scannerTypes() []string { return []string{"rspamd", "spamassassin"} }

func TestScannerMustContactItsEngine(t *testing.T) {
	const gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

	for _, scannerType := range scannerTypes() {
		t.Run(scannerType, func(t *testing.T) {
			scanner, err := Factory(Config{
				Type:    scannerType,
				Name:    scannerType,
				Address: scannerAddress(scannerType),
				Options: map[string]interface{}{"timeout": 1},
			})
			if err != nil {
				t.Fatalf("Factory: %v", err)
			}

			// Connect must fail: there is nothing there.
			if err := scanner.Connect(); err == nil {
				t.Error("Connect succeeded against an address with nothing listening; " +
					"it is not contacting the engine")
			}
			if scanner.IsConnected() {
				t.Error("IsConnected is true after a failed Connect")
			}

			// Each scan entry point must report failure rather than a verdict.
			t.Run("ScanBytes", func(t *testing.T) {
				result, err := scanner.ScanBytes(context.Background(), []byte(gtube))
				assertNoVerdict(t, "ScanBytes", result, err)
			})

			t.Run("ScanReader", func(t *testing.T) {
				result, err := scanner.ScanReader(context.Background(), stringReader(gtube))
				assertNoVerdict(t, "ScanReader", result, err)
			})

			t.Run("ScanFile", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "sample")
				if err := os.WriteFile(path, []byte(gtube), 0o600); err != nil {
					t.Fatalf("write sample: %v", err)
				}
				result, err := scanner.ScanFile(context.Background(), path)
				assertNoVerdict(t, "ScanFile", result, err)
			})
		})
	}
}

// assertNoVerdict fails if a scan produced an answer without an engine to
// produce it. Reporting Clean here is the worst outcome: it is indistinguishable
// from a real all-clear and would silently disable virus detection.
func assertNoVerdict(t *testing.T, method string, result *ScanResult, err error) {
	t.Helper()

	if err != nil {
		return // correct: the scan could not be performed
	}
	if result == nil {
		return
	}
	if result.Clean {
		t.Errorf("%s reported the message clean with no engine reachable; "+
			"a scanner that answers without contacting anything is not scanning", method)
		return
	}
	t.Errorf("%s returned a verdict (%+v) with no engine reachable", method, result)
}

type stringReaderT struct {
	s string
	i int
}

func (r *stringReaderT) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

func stringReader(s string) *stringReaderT { return &stringReaderT{s: s} }
