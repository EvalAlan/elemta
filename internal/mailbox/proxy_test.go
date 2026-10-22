package mailbox

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPublicListenerTakesProxyProtocol pins that the public listeners take
// the PROXY header from a configured load balancer and still speak their
// protocol after it, and that the balancer's own connection without one is
// refused.
func TestPublicListenerTakesProxyProtocol(t *testing.T) {
	e, a := testEngine(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.ProxyProtocolFrom = []string{"127.0.0.1"}
	s, _, _ := startTestService(t, e, a, cfg)
	ln, err := s.publicListen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.servePOP3(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	greeting := func(prefix string) string {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(7 * time.Second))
		if prefix != "" {
			_, _ = c.Write([]byte(prefix))
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		return line
	}
	if g := greeting("PROXY TCP4 203.0.113.9 127.0.0.1 40000 110\r\n"); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("POP3 through the balancer greeted %q", g)
	}
	if g := greeting(""); strings.HasPrefix(g, "+OK") {
		t.Fatalf("the balancer's address without a header was served: %q", g)
	}
	if err := (Config{Server: ServerConfig{ProxyProtocolFrom: []string{"nonsense"}}}).Validate(); err == nil {
		t.Error("a bad proxy_protocol_from was accepted")
	}
}
