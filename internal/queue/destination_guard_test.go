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

// A rule's refusal is the operator's decision, so the message bounces at once,
// unless another of the domain's servers merely failed and may come back.
func TestRefusedDestinationIsPermanent(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("no 127.0.0.2 here:", err)
	}
	_, port, _ := net.SplitHostPort(closed.Addr().String())
	_ = closed.Close() // nothing listens there now, so a dial is refused

	deliver := func(mx []*net.MX) error {
		h := NewSMTPDeliveryHandler(0)
		h.resolver = resolverFunc(func(context.Context, string) ([]*net.MX, error) { return mx, nil })
		h.mtastsManager = allowMTASTS{}
		h.mxPort = port
		h.SetDestinationGuard(func(ip net.IP) error {
			if ip.Equal(net.ParseIP("127.0.0.1")) {
				return errors.New("refused by a rule on 127.0.0.1")
			}
			return nil
		})
		_, _, _, err := h.deliverToDomainWithMetadata(context.Background(), Message{From: "a@example.com"}, "dest.example", []string{"b@dest.example"}, []byte("x"), false)
		return err
	}
	classifier := &Processor{}

	err = deliver([]*net.MX{{Host: "127.0.0.1"}})
	if err == nil || classifier.isTemporaryFailure(err) || !strings.Contains(err.Error(), "5.7.1") {
		t.Fatalf("every server refused: %v, temporary %v", err, classifier.isTemporaryFailure(err))
	}
	err = deliver([]*net.MX{{Host: "127.0.0.2", Pref: 10}, {Host: "127.0.0.1", Pref: 20}})
	if err == nil || !classifier.isTemporaryFailure(err) {
		t.Fatalf("one server down, one refused: %v should retry", err)
	}
}
