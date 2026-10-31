package smtp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
)

func TestConnectionLimitFollowsTheAbusePolicy(t *testing.T) {
	limits := DefaultResourceLimits()
	limits.MaxConnectionsPerIP = 100
	rm := NewResourceManager(limits, slog.Default())
	defer rm.Close()
	s := &Server{resourceManager: rm, slogger: slog.Default()}
	e := abuse.New("test", "", nil)
	s.SetAbuse(e)
	tracker := rm.ipTracker
	policy := abuse.DefaultPolicy()
	policy.ConnectionsPerAddress = 2
	policy.Allowlist = []string{"198.51.100.7"}
	if err := e.Publish(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !tracker.AddConnection("203.0.113.9") {
			t.Fatalf("connection %d refused", i+1)
		}
	}
	if tracker.CanConnect("203.0.113.9") || tracker.AddConnection("203.0.113.9") {
		t.Fatal("a third connection was accepted")
	}
	for i := 0; i < 5; i++ {
		if !tracker.AddConnection("198.51.100.7") {
			t.Fatal("an allowlisted address was limited")
		}
	}
	// Anything but enforcing goes back to the configuration file's limit.
	policy.Mode = abuse.ModeOff
	if err := e.Publish(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if !tracker.AddConnection("203.0.113.9") {
		t.Fatal("the configured limit wasn't restored")
	}
}

type fixedAddrConn struct {
	net.Conn
	addr string
}

func (c fixedAddrConn) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(c.addr)
	p, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

// Blocking is for clients. Refusing port 25 would lose mail from every server
// sharing that address, for something a compromised laptop did.
func TestBlockedAddressKeepsPort25(t *testing.T) {
	e := abuse.New("test", "", nil)
	if _, err := e.BlockAddress(context.Background(), "203.0.113.9", "", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	s := &Server{abuse: e, slogger: slog.Default()}
	pipe := func() (net.Conn, net.Conn) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return fixedAddrConn{a, "203.0.113.9:4000"}, b
	}
	mail, _ := pipe()
	if s.refuseBlocked(mail) {
		t.Fatal("a blocked address was refused on port 25")
	}
	submission, _ := pipe()
	if !s.refuseBlocked(submissionConn{Conn: submission}) {
		t.Fatal("a blocked address reached submission")
	}
	webmail, _ := pipe()
	if s.refuseBlocked(submissionConn{Conn: webmail, webmail: true}) {
		t.Fatal("the webmail's own port was refused")
	}
	other, _ := net.Pipe()
	defer other.Close()
	if s.refuseBlocked(submissionConn{Conn: fixedAddrConn{other, "198.51.100.1:4000"}}) {
		t.Fatal("an unblocked address was refused")
	}
}
