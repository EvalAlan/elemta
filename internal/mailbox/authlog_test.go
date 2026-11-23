package mailbox

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

// logBuffer is a log destination the server's goroutines can share.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// lines decodes the JSON lines whose msg is msg.
func (b *logBuffer) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	text := b.buf.String()
	b.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(text, "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// waitLines waits for n lines with msg: a session's closing line is written
// as the server notices the client has gone.
func (b *logBuffer) waitLines(t *testing.T, msg string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := b.lines(t, msg)
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func checkFields(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v (line %v)", k, line[k], v, line)
		}
	}
}

// loggedService is a service whose log can be read, with TLS for the public
// listeners.
func loggedService(t *testing.T, e *Engine, a Account) (*Service, *logBuffer, *tls.Config) {
	t.Helper()
	cert, key := writeCert(t, t.TempDir(), "mail.example.com")
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.TLSCert = cert
	cfg.Server.TLSKey = key
	logs := &logBuffer{}
	s, err := newService(cfg, e, testAuth{a}, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cancel)
	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	return s, logs, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}
}

// serve runs one of the service's servers on a fresh local listener.
func serve(t *testing.T, run func(net.Listener) error, stop func() error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = run(ln) }()
	t.Cleanup(func() {
		if stop != nil {
			_ = stop()
		}
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

// A refused POP3 sign-in used to leave no line at all.
func TestPOP3SignInsAreLogged(t *testing.T) {
	e, a := testEngine(t)
	s, logs, tlsConfig := loggedService(t, e, a)
	addr := serve(t, s.servePOP3, nil)

	p := dialPOPTest(t, addr)
	p.secure(tlsConfig)
	p.command("USER "+a.Address, true)
	p.command("PASS wrong-password", false)
	p.login(a.Address)
	p.command("QUIT", true)

	refused := logs.waitLines(t, "mailbox: sign-in refused", 1)
	if len(refused) != 1 {
		t.Fatalf("%d refusal lines, want 1", len(refused))
	}
	checkFields(t, refused[0], map[string]any{"level": "WARN", "event_type": "authentication", "protocol": "pop3",
		"username": a.Address, "client_ip": "127.0.0.1", "success": false, "failure_reason": "credentials"})

	in := logs.waitLines(t, "mailbox: signed in", 1)
	if len(in) != 1 {
		t.Fatalf("%d sign-in lines, want 1", len(in))
	}
	checkFields(t, in[0], map[string]any{"level": "INFO", "event_type": "authentication", "protocol": "pop3",
		"username": a.Address, "client_ip": "127.0.0.1", "success": true})

	ended := logs.waitLines(t, "mailbox: session ended", 1)
	if len(ended) != 1 {
		t.Fatalf("%d session-end lines, want 1", len(ended))
	}
	checkFields(t, ended[0], map[string]any{"event_type": "session_end", "protocol": "pop3", "username": a.Address})
	if _, ok := ended[0]["duration_ms"].(float64); !ok {
		t.Errorf("no duration: %v", ended[0])
	}
	assertNoPassword(t, logs, "testpass", "wrong-password")
}

// Public IMAP logs its sign-ins; the webmail's internal listener doesn't,
// because the webmail logs them itself with the user's real address.
func TestIMAPSignInsAreLoggedOnPublicListenersOnly(t *testing.T) {
	e, a := testEngine(t)
	s, logs, tlsConfig := loggedService(t, e, a)
	public := serve(t, s.imapStartTLS.Serve, s.imapStartTLS.Close)
	internal := serve(t, s.imap.Serve, s.imap.Close)

	c, err := imapclient.DialStartTLS(public, &imapclient.Options{TLSConfig: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(a.Address, "wrong-password").Wait(); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := c.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	_ = c.Logout().Wait()
	_ = c.Close()

	refused := logs.waitLines(t, "mailbox: sign-in refused", 1)
	if len(refused) != 1 {
		t.Fatalf("%d refusal lines, want 1", len(refused))
	}
	checkFields(t, refused[0], map[string]any{"protocol": "imap", "username": a.Address, "client_ip": "127.0.0.1",
		"success": false, "failure_reason": "credentials"})
	in := logs.waitLines(t, "mailbox: signed in", 1)
	if len(in) != 1 {
		t.Fatalf("%d sign-in lines, want 1", len(in))
	}
	checkFields(t, in[0], map[string]any{"protocol": "imap", "username": a.Address, "success": true})
	if ended := logs.waitLines(t, "mailbox: session ended", 1); len(ended) != 1 {
		t.Fatalf("%d session-end lines, want 1", len(ended))
	}

	// The internal listener: sign in and out, and nothing more is logged.
	c, err = imapclient.DialInsecure(internal, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	_ = c.Logout().Wait()
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
	if n := len(logs.lines(t, "mailbox: signed in")); n != 1 {
		t.Errorf("internal listener logged a sign-in: %d lines", n)
	}
	if n := len(logs.lines(t, "mailbox: session ended")); n != 1 {
		t.Errorf("internal listener logged a session end: %d lines", n)
	}
	assertNoPassword(t, logs, "testpass", "wrong-password")
}

func assertNoPassword(t *testing.T, logs *logBuffer, passwords ...string) {
	t.Helper()
	logs.mu.Lock()
	text := logs.buf.String()
	logs.mu.Unlock()
	for _, p := range passwords {
		if strings.Contains(text, p) {
			t.Errorf("password %q reached the log", p)
		}
	}
}

func TestRemoteIPKeepsTheWholeAddress(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("2001:db8::1234"), Port: 993}
	if got := remoteIP(addr); got != "2001:db8::1234" {
		t.Fatalf("remoteIP = %q", got)
	}
	// clientKey is the /64, which isn't an address to put in a log line.
	if clientKey(addr) == remoteIP(addr) {
		t.Fatal("clientKey and remoteIP agree; the test no longer shows the difference")
	}
}
