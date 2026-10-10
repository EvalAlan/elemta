package smtp

import (
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func submissionMailCheck(t *testing.T, remoteIP string, cfg *Config, submission bool) error {
	t.Helper()
	conn := fakeAddrConn{remote: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 40000}}
	state := NewSessionState(slog.Default())
	session := &Session{config: cfg, logger: slog.Default(), submission: submission, state: state}
	ch := &CommandHandler{session: session, state: state, conn: conn, config: cfg, logger: slog.Default()}
	return ch.checkSubmissionSender()
}

// On the submission port an anonymous client is refused at MAIL FROM unless
// it is on a trusted network; the MX port does not ask.
func TestSubmissionRequiresAuthOrTrustedNetwork(t *testing.T) {
	cfg := &Config{LocalDomains: []string{"example.com"}, AllowedRelays: []string{"private"}}

	if err := submissionMailCheck(t, "203.0.113.9", cfg, true); err == nil {
		t.Error("anonymous public client accepted on the submission port")
	}
	if err := submissionMailCheck(t, "10.20.30.40", cfg, true); err != nil {
		t.Errorf("trusted private network refused on the submission port: %v", err)
	}
	if err := submissionMailCheck(t, "203.0.113.9", cfg, false); err != nil {
		t.Errorf("the MX port asked an anonymous sender to authenticate: %v", err)
	}
}

// The submission listener runs alongside the MX listener and sessions on it
// work end to end.
func TestSubmissionListenerAccepts(t *testing.T) {
	cfg := createTestConfig(t)
	cfg.SubmissionAddr = "127.0.0.1:0"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Start() }()
	time.Sleep(150 * time.Millisecond)

	sub := server.getSubmissionListener()
	if sub == nil {
		t.Fatal("submission listener not started")
	}
	p := dialProbe(t, sub.Addr().String())
	p.cmd("EHLO probe.example")
	// Loopback is always trusted, so this is accepted without AUTH.
	if reply := p.cmd("MAIL FROM:<app@example.com>"); !strings.HasPrefix(reply, "250") {
		t.Errorf("MAIL FROM on the submission port from loopback: %q", reply)
	}
}
