package antispam

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// These tests drive the scanner against a stand-in Rspamd over HTTP, so what is
// verified is that the message reaches the server and that its verdict is what
// decides the outcome.
//
// The previous implementation matched the GTUBE string locally and fabricated a
// score of 100 with a rule named "GTUBE_TEST". Its only real network call was
// /ping. The tests it shipped with asserted that "VIAGRA FREE!!!" scored as
// spam, which said nothing about Rspamd.

// fakeRspamd records the requests it receives and replies with a fixed verdict.
type fakeRspamd struct {
	server *httptest.Server

	mu       sync.Mutex
	body     []byte
	paths    []string
	password string

	response   RspamdResponse
	statusCode int
	rawBody    string // when set, returned instead of JSON
}

func startFakeRspamd(t *testing.T, response RspamdResponse) *fakeRspamd {
	t.Helper()

	f := &fakeRspamd{response: response, statusCode: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.password = r.Header.Get("Password")
		if r.URL.Path != "/ping" {
			f.body = body
		}
		status, raw, resp := f.statusCode, f.rawBody, f.response
		f.mu.Unlock()

		if r.URL.Path == "/ping" {
			_, _ = w.Write([]byte("pong"))
			return
		}

		w.WriteHeader(status)
		if raw != "" {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeRspamd) receivedBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.body...)
}

func (f *fakeRspamd) sawPath(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.paths {
		if got == p {
			return true
		}
	}
	return false
}

func newTestRspamd(t *testing.T, f *fakeRspamd, cfg Config) *Rspamd {
	t.Helper()
	cfg.Type = "rspamd"
	cfg.Address = f.server.URL
	if cfg.Threshold == 0 {
		cfg.Threshold = 6.0
	}
	s := NewRspamd(cfg)
	s.connected = true // Connect() is covered separately
	return s
}

// TestRspamdPostsMessageToCheckv2 asserts the message actually reaches Rspamd,
// which the previous implementation never did.
func TestRspamdPostsMessageToCheckv2(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action", Score: 0.1, Required: 6.0})
	s := newTestRspamd(t, f, Config{})

	message := []byte("Subject: hello\r\nFrom: a@example.com\r\n\r\nbody text\r\n")
	result, err := s.ScanBytes(context.Background(), message)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !f.sawPath("/checkv2") {
		t.Error("scanner did not POST to /checkv2")
	}
	if got := f.receivedBody(); !bytes.Equal(got, message) {
		t.Errorf("server received different bytes than were scanned\n  want %q\n  got  %q", message, got)
	}
	if !result.Clean {
		t.Errorf("expected clean, got %+v", result)
	}
}

// TestRspamdVerdictFollowsAction pins that Rspamd's own decision is what counts,
// rather than a score compared against a locally chosen number.
func TestRspamdVerdictFollowsAction(t *testing.T) {
	cases := []struct {
		action    string
		score     float64
		wantClean bool
	}{
		{"no action", 0.5, true},
		{"greylist", 4.0, true},
		{"add header", 6.5, false},
		{"rewrite subject", 8.0, false},
		{"soft reject", 9.0, false},
		{"reject", 15.0, false},
		// A high score with no action reported falls back to the threshold.
		{"", 9.0, false},
		{"", 1.0, true},
	}

	for _, tc := range cases {
		name := tc.action
		if name == "" {
			name = "no-action-field"
		}
		t.Run(name, func(t *testing.T) {
			f := startFakeRspamd(t, RspamdResponse{Action: tc.action, Score: tc.score, Required: 6.0})
			s := newTestRspamd(t, f, Config{})

			result, err := s.ScanBytes(context.Background(), []byte("message"))
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if result.Clean != tc.wantClean {
				t.Errorf("action %q score %.1f: clean = %v, want %v", tc.action, tc.score, result.Clean, tc.wantClean)
			}
			if result.Score != tc.score {
				t.Errorf("score = %.1f, want %.1f", result.Score, tc.score)
			}
		})
	}
}

// TestRspamdReportsSymbolsAsRules checks the triggered rules are carried
// through, since they are what makes a verdict explainable.
func TestRspamdReportsSymbolsAsRules(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{
		Action:   "reject",
		Score:    15.0,
		Required: 6.0,
		Symbols: map[string]Symbol{
			"GTUBE":      {Name: "GTUBE", Score: 15.0},
			"BAYES_SPAM": {Name: "BAYES_SPAM", Score: 3.0},
		},
	})
	s := newTestRspamd(t, f, Config{})

	result, err := s.ScanBytes(context.Background(), []byte("message"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	joined := strings.Join(result.Rules, ",")
	if !strings.Contains(joined, "GTUBE") || !strings.Contains(joined, "BAYES_SPAM") {
		t.Errorf("rules = %v, want both symbols", result.Rules)
	}
}

// TestRspamdUnusableResponseIsAnError pins the safety property: a response that
// cannot be understood must not become a clean verdict.
func TestRspamdUnusableResponseIsAnError(t *testing.T) {
	t.Run("malformed JSON", func(t *testing.T) {
		f := startFakeRspamd(t, RspamdResponse{})
		f.rawBody = "not json at all"
		s := newTestRspamd(t, f, Config{})

		result, err := s.ScanBytes(context.Background(), []byte("message"))
		if err == nil {
			t.Errorf("expected an error, got %+v", result)
		}
		if result != nil && result.Clean {
			t.Error("an unparseable response must not yield a clean verdict")
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		f := startFakeRspamd(t, RspamdResponse{})
		f.statusCode = http.StatusInternalServerError
		s := newTestRspamd(t, f, Config{})

		result, err := s.ScanBytes(context.Background(), []byte("message"))
		if err == nil {
			t.Errorf("expected an error, got %+v", result)
		}
		if result != nil && result.Clean {
			t.Error("a failed request must not yield a clean verdict")
		}
	})
}

// TestRspamdScanFileStreams covers the path a spooled message takes. ScanFile
// used to return "direct file scanning not supported", forcing the caller to
// read the message into memory — the thing spooling exists to avoid.
func TestRspamdScanFileStreams(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action", Required: 6.0})
	s := newTestRspamd(t, f, Config{})

	content := bytes.Repeat([]byte("spooled message line\r\n"), 5000)
	path := filepath.Join(t.TempDir(), "message")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := s.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scan file: %v", err)
	}
	if !result.Clean {
		t.Error("expected a clean verdict")
	}
	if got := f.receivedBody(); !bytes.Equal(got, content) {
		t.Errorf("file content did not reach the scanner intact (%d vs %d bytes)", len(content), len(got))
	}
}

func TestRspamdScanReaderStreams(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action", Required: 6.0})
	s := newTestRspamd(t, f, Config{})

	content := bytes.Repeat([]byte("streamed line\r\n"), 4000)
	if _, err := s.ScanReader(context.Background(), bytes.NewReader(content)); err != nil {
		t.Fatalf("scan reader: %v", err)
	}
	if got := f.receivedBody(); !bytes.Equal(got, content) {
		t.Errorf("streamed content differs (%d vs %d bytes)", len(content), len(got))
	}
}

func TestRspamdScanLimitTruncates(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action", Required: 6.0})
	s := newTestRspamd(t, f, Config{})
	s.scanLimit = 512

	if _, err := s.ScanBytes(context.Background(), bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := len(f.receivedBody()); got != 512 {
		t.Errorf("scan_limit not applied: server received %d bytes, want 512", got)
	}
}

func TestRspamdSendsAPIKey(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action", Required: 6.0})
	s := newTestRspamd(t, f, Config{})
	s.apiKey = "s3cret"

	if _, err := s.ScanBytes(context.Background(), []byte("message")); err != nil {
		t.Fatalf("scan: %v", err)
	}

	f.mu.Lock()
	got := f.password
	f.mu.Unlock()
	if got != "s3cret" {
		t.Errorf("Password header = %q, want s3cret", got)
	}
}

func TestRspamdRefusesWhenNotConnected(t *testing.T) {
	f := startFakeRspamd(t, RspamdResponse{Action: "no action"})
	s := newTestRspamd(t, f, Config{})
	s.connected = false

	if _, err := s.ScanBytes(context.Background(), []byte("message")); err == nil {
		t.Error("scanning while disconnected should fail rather than report clean")
	}
}

// TestRspamdActionsMapToDistinctDispositions is the regression test for a
// mail-loss bug. Rspamd's actions were flattened to a boolean, so "add header"
// (deliver and mark) and "soft reject" (retry later) both became "spam" — and
// with reject_on_spam enabled both produced a permanent 554.
//
// Measured on a real corpus before the fix: 139 legitimate messages refused,
// and no spam caught.
func TestRspamdActionsMapToDistinctDispositions(t *testing.T) {
	cases := []struct {
		action string
		want   Disposition
		why    string
	}{
		{"no action", DispositionClean, "clean mail is delivered"},
		{"greylist", DispositionClean, "greylisting is not a spam verdict"},
		{"add header", DispositionTag, "tagging means deliver and mark, never refuse"},
		{"add_header", DispositionTag, "underscore spelling behaves the same"},
		{"rewrite subject", DispositionTag, "rewriting means deliver and mark"},
		{"soft reject", DispositionDefer, "a soft reject must stay temporary"},
		{"soft_reject", DispositionDefer, "underscore spelling behaves the same"},
		{"reject", DispositionReject, "only a reject refuses outright"},
	}

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			f := startFakeRspamd(t, RspamdResponse{Action: tc.action, Score: 7.0, Required: 15.0})
			s := newTestRspamd(t, f, Config{})

			result, err := s.ScanBytes(context.Background(), []byte("message"))
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if result.Disposition != tc.want {
				t.Errorf("action %q -> %v, want %v (%s)",
					tc.action, result.Disposition, tc.want, tc.why)
			}
			// Clean must stay consistent with the disposition.
			if result.Clean != (tc.want == DispositionClean) {
				t.Errorf("action %q: Clean = %v but disposition is %v",
					tc.action, result.Clean, result.Disposition)
			}
		})
	}
}

// TestRspamdScoreFallbackRejectsOnlyAtThreshold covers the case where Rspamd
// reports no action at all: the score decides, against the engine's threshold.
func TestRspamdScoreFallbackRejectsOnlyAtThreshold(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  Disposition
	}{
		{5.0, DispositionClean},
		{14.9, DispositionClean},
		{15.0, DispositionReject},
		{30.0, DispositionReject},
	} {
		f := startFakeRspamd(t, RspamdResponse{Action: "", Score: tc.score, Required: 15.0})
		s := newTestRspamd(t, f, Config{})
		result, err := s.ScanBytes(context.Background(), []byte("message"))
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if result.Disposition != tc.want {
			t.Errorf("score %.1f/15.0 -> %v, want %v", tc.score, result.Disposition, tc.want)
		}
	}
}
