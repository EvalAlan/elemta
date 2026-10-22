package proxyproto

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// serve accepts one connection on a wrapped listener and reports the
// client address it sees and the first line it reads.
func serve(t *testing.T, trusted []string) (addr string, got chan [2]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := Wrap(ln, trusted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	got = make(chan [2]string, 1)
	go func() {
		c, err := wrapped.Accept()
		if err != nil {
			got <- [2]string{"", err.Error()}
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(7 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			got <- [2]string{c.RemoteAddr().String(), "error: " + err.Error()}
			return
		}
		got <- [2]string{c.RemoteAddr().String(), strings.TrimSpace(line)}
	}()
	return ln.Addr().String(), got
}

func send(t *testing.T, addr, data string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedBalancerGivesClientAddress(t *testing.T) {
	addr, got := serve(t, []string{"127.0.0.0/8"})
	send(t, addr, "PROXY TCP4 203.0.113.7 192.0.2.1 40000 25\r\nEHLO client\r\n")
	r := <-got
	if !strings.HasPrefix(r[0], "203.0.113.7:") || r[1] != "EHLO client" {
		t.Fatalf("saw %q reading %q", r[0], r[1])
	}
}

func TestUntrustedHeaderIsNotBelieved(t *testing.T) {
	addr, got := serve(t, []string{"192.0.2.0/24"})
	send(t, addr, "PROXY TCP4 203.0.113.7 192.0.2.1 40000 25\r\n")
	r := <-got
	if strings.HasPrefix(r[0], "203.0.113.7") || !strings.HasPrefix(r[1], "PROXY") {
		t.Fatalf("an untrusted client chose its address: saw %q reading %q", r[0], r[1])
	}
}

func TestTrustedWithoutHeaderIsRefused(t *testing.T) {
	addr, got := serve(t, []string{"127.0.0.1"})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("EHLO sneaky\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open")
	}
	select {
	case r := <-got:
		t.Fatalf("a trusted address without a header was handed on: %v", r)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNoTrustedLeavesListenerAlone(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	if w, err := Wrap(ln, nil); err != nil || w != ln {
		t.Fatalf("Wrap with nothing trusted = %v, %v", w, err)
	}
	if _, err := ParseTrusted([]string{"not-an-address"}); err == nil {
		t.Error("a bad address was accepted")
	}
}
