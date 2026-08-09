package antivirus

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// These tests speak clamd's wire protocol to a stand-in server, so what is
// verified is the bytes on the connection rather than the shape of the result.
//
// The previous implementation returned a hardcoded verdict from a substring
// check and never opened a socket, while reporting itself as "clamav". Its
// tests passed. Asserting on the protocol is what makes that impossible.

// fakeClamd is a minimal clamd that records what it was sent.
type fakeClamd struct {
	listener net.Listener

	// verdict is written back after a complete INSTREAM, without the trailing NUL.
	verdict string
	// failAfterChunks aborts the connection mid-stream when > 0.
	failAfterChunks int

	mu       sync.Mutex
	received []byte
	commands []string
	chunks   []int
}

func startFakeClamd(t *testing.T, verdict string) *fakeClamd {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeClamd{listener: ln, verdict: verdict}
	t.Cleanup(func() { _ = ln.Close() })

	go f.serve()
	return f
}

func (f *fakeClamd) addr() string { return f.listener.Addr().String() }

func (f *fakeClamd) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeClamd) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	cmd, err := readNulTerminated(conn)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()

	switch cmd {
	case "zPING":
		_, _ = conn.Write([]byte("PONG\x00"))
		return
	case "zINSTREAM":
	default:
		_, _ = conn.Write([]byte("UNKNOWN COMMAND\x00"))
		return
	}

	var body bytes.Buffer
	chunkCount := 0
	for {
		var header [4]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 {
			break // end of stream
		}
		chunkCount++
		f.mu.Lock()
		f.chunks = append(f.chunks, int(size))
		f.mu.Unlock()

		if f.failAfterChunks > 0 && chunkCount >= f.failAfterChunks {
			return // drop the connection mid-stream
		}
		if _, err := io.CopyN(&body, conn, int64(size)); err != nil {
			return
		}
	}

	f.mu.Lock()
	f.received = body.Bytes()
	f.mu.Unlock()

	_, _ = conn.Write([]byte(f.verdict + "\x00"))
}

func (f *fakeClamd) body() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.received...)
}

func (f *fakeClamd) sawCommand(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if c == name {
			return true
		}
	}
	return false
}

func (f *fakeClamd) chunkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.chunks)
}

func readNulTerminated(r io.Reader) (string, error) {
	var out []byte
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		if buf[0] == 0 {
			return string(out), nil
		}
		out = append(out, buf[0])
	}
}

func newTestClamAV(addr string, options map[string]interface{}) *ClamAV {
	if options == nil {
		options = map[string]interface{}{}
	}
	if _, ok := options["timeout"]; !ok {
		options["timeout"] = 5
	}
	return NewClamAV(Config{Type: "clamav", Name: "clamav", Address: addr, Options: options})
}

// TestClamAVSendsMessageOverINSTREAM is the test that the previous
// implementation could not have passed: it asserts the message actually
// reached the server.
func TestClamAVSendsMessageOverINSTREAM(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), nil)

	message := []byte("Subject: hello\r\n\r\nthis is the body\r\n")
	result, err := c.ScanBytes(context.Background(), message)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !result.Clean {
		t.Errorf("expected a clean verdict, got %+v", result)
	}
	if !server.sawCommand("zINSTREAM") {
		t.Error("scanner did not issue INSTREAM")
	}
	if got := server.body(); !bytes.Equal(got, message) {
		t.Errorf("server received different bytes than were scanned\n  want %q\n  got  %q", message, got)
	}
}

// TestClamAVReportsInfection covers the verdict that matters.
func TestClamAVReportsInfection(t *testing.T) {
	server := startFakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	c := newTestClamAV(server.addr(), nil)

	result, err := c.ScanBytes(context.Background(), []byte("anything"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.Clean {
		t.Fatal("expected an infected verdict")
	}
	if len(result.Infections) != 1 || result.Infections[0] != "Eicar-Test-Signature" {
		t.Errorf("infections = %v, want [Eicar-Test-Signature]", result.Infections)
	}
}

// TestClamAVUnrecognisedReplyIsAnError pins the safety property: a reply that
// cannot be understood must not be reported as clean.
func TestClamAVUnrecognisedReplyIsAnError(t *testing.T) {
	for _, reply := range []string{"stream: something odd", "", "INSTREAM size limit exceeded ERROR"} {
		server := startFakeClamd(t, reply)
		c := newTestClamAV(server.addr(), nil)

		result, err := c.ScanBytes(context.Background(), []byte("data"))
		if err == nil {
			t.Errorf("reply %q should be an error, got result %+v", reply, result)
		}
		if result != nil && result.Clean {
			t.Errorf("reply %q must never yield a clean verdict", reply)
		}
	}
}

// TestClamAVStreamsInChunks shows a large message is sent incrementally rather
// than assembled, which is what lets a spooled message be scanned without its
// size bounding memory.
func TestClamAVStreamsInChunks(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), nil)

	large := bytes.Repeat([]byte("abcdefghij"), 40*1024) // ~400KB
	result, err := c.ScanBytes(context.Background(), large)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !result.Clean {
		t.Error("expected a clean verdict")
	}
	if got := server.chunkCount(); got < 2 {
		t.Errorf("expected the body to be sent in multiple chunks, got %d", got)
	}
	if got := server.body(); !bytes.Equal(got, large) {
		t.Errorf("streamed body differs: sent %d bytes, server saw %d", len(large), len(got))
	}
}

// TestClamAVScanFileStreamsFromDisk covers the path a spooled message takes.
func TestClamAVScanFileStreamsFromDisk(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), nil)

	content := bytes.Repeat([]byte("spooled message line\r\n"), 5000)
	path := writeTempFile(t, content)

	result, err := c.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scan file: %v", err)
	}
	if !result.Clean {
		t.Error("expected a clean verdict")
	}
	if got := server.body(); !bytes.Equal(got, content) {
		t.Errorf("file content did not reach the scanner intact (%d vs %d bytes)", len(content), len(got))
	}
}

// TestClamAVScanFileDoesNotSilentlyPass is the regression test for the stub
// that returned Clean unconditionally without contacting anything. Wiring the
// spooling work to it would have disabled virus detection entirely.
func TestClamAVScanFileDoesNotSilentlyPass(t *testing.T) {
	server := startFakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	c := newTestClamAV(server.addr(), nil)

	path := writeTempFile(t, []byte("whatever the content is"))

	result, err := c.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scan file: %v", err)
	}
	if result.Clean {
		t.Fatal("ScanFile reported clean despite an infected verdict from the server")
	}
	if !server.sawCommand("zINSTREAM") {
		t.Error("ScanFile did not contact the scanner at all")
	}
}

// TestClamAVScanLimitTruncates pins the configured bound.
func TestClamAVScanLimitTruncates(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), map[string]interface{}{"scan_limit": 1024})

	large := bytes.Repeat([]byte("x"), 8192)
	if _, err := c.ScanBytes(context.Background(), large); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := len(server.body()); got != 1024 {
		t.Errorf("scan_limit not applied: server received %d bytes, want 1024", got)
	}
}

// TestClamAVConnectVerifiesReachability pins that Connect actually contacts
// clamd. It used to set a flag and return nil, so "connected" meant nothing
// had been attempted.
func TestClamAVConnectVerifiesReachability(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), nil)

	if err := c.Connect(); err != nil {
		t.Fatalf("connect to a live server: %v", err)
	}
	if !server.sawCommand("zPING") {
		t.Error("Connect did not ping the server")
	}
	if !c.IsConnected() {
		t.Error("IsConnected should be true after a successful ping")
	}

	// A dead address must fail rather than report success.
	dead := newTestClamAV("127.0.0.1:1", map[string]interface{}{"timeout": 1})
	if err := dead.Connect(); err == nil {
		t.Error("connecting to a dead address should fail")
	}
	if dead.IsConnected() {
		t.Error("IsConnected should be false after a failed connect")
	}
}

// TestClamAVScanFailureIsAnError makes sure a connection lost mid-stream is
// reported rather than being turned into a clean verdict.
func TestClamAVScanFailureIsAnError(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	server.failAfterChunks = 1
	c := newTestClamAV(server.addr(), nil)

	large := bytes.Repeat([]byte("y"), 512*1024)
	result, err := c.ScanBytes(context.Background(), large)
	if err == nil && result != nil && result.Clean {
		t.Error("a scan aborted mid-stream must not report clean")
	}
}

func TestClamAVRespectsContextCancellation(t *testing.T) {
	server := startFakeClamd(t, "stream: OK")
	c := newTestClamAV(server.addr(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.ScanBytes(ctx, []byte("data")); err == nil {
		t.Error("a cancelled context should abort the scan")
	} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Logf("scan failed as expected: %v", err)
	}
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "scan-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}
