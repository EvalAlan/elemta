package mailbox

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
)

func TestAbuseListenerLimitsOneAddress(t *testing.T) {
	e := abuse.New("test", "", nil)
	p := abuse.DefaultPolicy()
	p.Mode = abuse.ModeEnforce
	p.ConnectionsPerAddress = 1
	// Loopback is exempt, so the test connects from a second loopback name
	// through a listener that reports another client.
	if err := e.Publish(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	ln := &abuseListener{Listener: renamedListener{inner}, abuse: e}
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	dial()
	first := <-accepted
	over := dial()
	_ = over.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := over.Read(make([]byte, 1)); err == nil {
		t.Fatal("the second connection stayed open")
	}
	// Closing gives the slot back.
	_ = first.Close()
	dial()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("a released slot wasn't reusable")
	}
}

type renamedListener struct{ net.Listener }

func (l renamedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return renamedConn{c}, nil
}

type renamedConn struct{ net.Conn }

func (renamedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}
}
