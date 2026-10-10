package smtp

import (
	"context"
	"log/slog"
	"net"
	"testing"
)

// fakeAddrConn is a net.Conn whose only job is to report a remote address.
type fakeAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeAddrConn) RemoteAddr() net.Addr { return c.remote }

func relayCheck(t *testing.T, remoteIP string, cfg *Config) error {
	t.Helper()
	conn := fakeAddrConn{remote: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 40000}}
	state := NewSessionState(slog.Default())
	ch := &CommandHandler{state: state, conn: conn, config: cfg, logger: slog.Default()}
	return ch.checkRelayPermissions(context.Background(), "victim@outside.example")
}

// The relay decision must not depend on dev_mode (the shipped config had it
// on) or on the client merely having a private address (SNAT and proxies make
// every client look private).
func TestRelayPolicy(t *testing.T) {
	base := func() *Config {
		return &Config{LocalDomains: []string{"example.com"}}
	}

	devMode := base()
	devMode.DevMode = true
	if err := relayCheck(t, "203.0.113.9", devMode); err == nil {
		t.Error("dev_mode let a public client relay")
	}
	if err := relayCheck(t, "10.1.2.3", base()); err == nil {
		t.Error("an unlisted private address was allowed to relay")
	}
	listed := base()
	listed.AllowedRelays = []string{"10.0.0.0/8"}
	if err := relayCheck(t, "10.1.2.3", listed); err != nil {
		t.Errorf("a listed network was refused: %v", err)
	}
	if err := relayCheck(t, "127.0.0.1", base()); err != nil {
		t.Errorf("loopback was refused: %v", err)
	}
}
