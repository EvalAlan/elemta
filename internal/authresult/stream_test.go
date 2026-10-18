package authresult

import (
	"io"
	"os"
	"testing"
	"time"
)

// Opt-in real-message verification keeps personal mail out of repository fixtures.
func TestCapturedSignedMessageStream(t *testing.T) {
	path := os.Getenv("ELEMTA_TEST_SIGNED_MESSAGE")
	if path == "" {
		t.Skip("set ELEMTA_TEST_SIGNED_MESSAGE to a complete signed message")
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	head, err := io.ReadAll(io.LimitReader(reader, 256*1024))
	if err != nil {
		t.Fatal(err)
	}
	verifier := New(Config{Enabled: true, DKIMEnabled: true, ARCEnabled: true, Timeout: 10 * time.Second})
	results := verifier.CheckWithOpener(t.Context(), nil, "", "", head, func() (io.ReadCloser, error) { return os.Open(path) })
	if len(results.DKIM) == 0 || results.DKIM[0].Value != "pass" || results.ARC.Value != "pass" {
		t.Fatalf("full-message verification: DKIM=%+v ARC=%+v", results.DKIM, results.ARC)
	}
	t.Logf("full-message verification: DKIM=%+v ARC=%+v", results.DKIM, results.ARC)
}
