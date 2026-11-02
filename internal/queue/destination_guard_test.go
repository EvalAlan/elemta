package queue

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// The guard has to run in a real dial, on the address about to be connected to.
func TestDestinationGuardRefusesTheDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("220 test\r\n"))
			_ = c.Close()
		}
	}()

	var seen net.IP
	h := &SMTPDeliveryHandler{}
	h.SetDestinationGuard(func(ip net.IP) error {
		seen = ip
		return errors.New("refused by a rule")
	})
	_, _, err = h.dialAndGreet(context.Background(), ln.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "refused by a rule") {
		t.Fatalf("dial = %v", err)
	}
	if !seen.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("guard saw %v", seen)
	}

	h.SetDestinationGuard(func(net.IP) error { return nil })
	if _, _, err = h.dialAndGreet(context.Background(), ln.Addr().String()); err != nil && strings.Contains(err.Error(), "refused by a rule") {
		t.Fatalf("an allowing guard refused: %v", err)
	}
}
