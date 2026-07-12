package queue

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

type staticMXResolver struct{}

func (staticMXResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.local", Pref: 0}}, nil
}

type allowMTASTS struct{}

func (allowMTASTS) EnforcePolicy(context.Context, string, string, bool) error { return nil }

func startSMTPServer(t *testing.T, final string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := bufio.NewWriter(c)
				fmt.Fprint(w, "220 fake ESMTP\r\n")
				w.Flush()
				inData := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if strings.TrimSpace(line) == "." {
							fmt.Fprintf(w, "%s\r\n", final)
							w.Flush()
							inData = false
						}
						continue
					}
					u := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(u, "EHLO"), strings.HasPrefix(u, "HELO"):
						fmt.Fprint(w, "250 fake\r\n")
					case strings.HasPrefix(u, "MAIL"), strings.HasPrefix(u, "RCPT"):
						fmt.Fprint(w, "250 ok\r\n")
					case u == "DATA":
						fmt.Fprint(w, "354 send\r\n")
						inData = true
					case u == "QUIT":
						fmt.Fprint(w, "221 bye\r\n")
						w.Flush()
						return
					default:
						fmt.Fprint(w, "250 ok\r\n")
					}
					w.Flush()
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func TestSMTPHandlerActiveMixedSuccessAndFailureOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, failure string
		want          RecipientDeliveryStatus
	}{{"success and 451", "451 4.3.0 try later", RecipientTemporaryFailure}, {"success and 550", "550 5.1.1 user unknown", RecipientPermanentFailure}} {
		t.Run(tc.name, func(t *testing.T) {
			okAddr, stopOK := startSMTPServer(t, "250 2.0.0 queued")
			defer stopOK()
			failAddr, stopFail := startSMTPServer(t, tc.failure)
			defer stopFail()
			h := NewSMTPDeliveryHandler(0)
			h.resolver = staticMXResolver{}
			h.mtastsManager = allowMTASTS{}
			h.maxMXLookups = 1
			h.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				target := failAddr
				if strings.Contains(address, "mx.local") { /* domain selected below through counter */
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}
			// Select deterministic server by recipient domain while retaining the active handler path.
			calls := 0
			h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				calls++
				target := okAddr
				if calls > 1 {
					target = failAddr
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}
			res, err := h.DeliverMessageWithMetadata(context.Background(), Message{From: "sender@test", To: []string{"ok@a.test", "bad@b.test"}}, []byte("Subject: x\r\n\r\nbody"))
			if err == nil || !res.Success || len(res.RecipientOutcomes) != 2 {
				t.Fatalf("result=%+v err=%v", res, err)
			}
			if res.RecipientOutcomes[0].Status != RecipientDelivered || res.RecipientOutcomes[1].Status != tc.want {
				t.Fatalf("outcomes=%+v", res.RecipientOutcomes)
			}
		})
	}
}

func TestSMTPHandlerSameDomainMixedRCPTOutcomes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	commands := make(chan []string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			commands <- nil
			return
		}
		defer conn.Close()
		r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
		fmt.Fprint(w, "220 mixed ESMTP\r\n")
		w.Flush()
		var seen []string
		inData := false
		for {
			line, readErr := r.ReadString('\n')
			if readErr != nil {
				commands <- seen
				return
			}
			trimmed := strings.TrimSpace(line)
			if inData {
				if trimmed == "." {
					seen = append(seen, "DATA-BODY")
					fmt.Fprint(w, "250 2.0.0 queued\r\n")
					w.Flush()
					inData = false
				}
				continue
			}
			u := strings.ToUpper(trimmed)
			switch {
			case strings.HasPrefix(u, "EHLO"), strings.HasPrefix(u, "HELO"):
				fmt.Fprint(w, "250 mixed\r\n")
			case strings.HasPrefix(u, "MAIL"):
				fmt.Fprint(w, "250 ok\r\n")
			case strings.Contains(u, "OK@SAME.TEST"):
				seen = append(seen, "ok")
				fmt.Fprint(w, "250 2.1.5 ok\r\n")
			case strings.Contains(u, "LATER@SAME.TEST"):
				seen = append(seen, "later")
				fmt.Fprint(w, "451 4.2.0 later\r\n")
			case strings.Contains(u, "BAD@SAME.TEST"):
				seen = append(seen, "bad")
				fmt.Fprint(w, "550 5.1.1 unknown\r\n")
			case u == "DATA":
				seen = append(seen, "DATA")
				fmt.Fprint(w, "354 send\r\n")
				inData = true
			case u == "QUIT":
				fmt.Fprint(w, "221 bye\r\n")
				w.Flush()
				commands <- seen
				return
			}
			w.Flush()
		}
	}()

	h := NewSMTPDeliveryHandler(0)
	h.resolver, h.mtastsManager, h.maxMXLookups = staticMXResolver{}, allowMTASTS{}, 1
	h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}
	msg := Message{From: "sender@test", To: []string{"ok@same.test", "later@same.test", "bad@same.test"}}
	res, err := h.DeliverMessageWithMetadata(context.Background(), msg, []byte("Subject: x\r\n\r\nbody"))
	if err == nil || res == nil || !res.Success {
		t.Fatalf("result=%+v err=%v", res, err)
	}
	want := []RecipientDeliveryStatus{RecipientDelivered, RecipientTemporaryFailure, RecipientPermanentFailure}
	for i := range want {
		if res.RecipientOutcomes[i].Recipient != msg.To[i] || res.RecipientOutcomes[i].Status != want[i] {
			t.Fatalf("outcomes=%+v", res.RecipientOutcomes)
		}
	}
	if got := strings.Join(<-commands, ","); got != "ok,later,bad,DATA,DATA-BODY" {
		t.Fatalf("SMTP commands=%q", got)
	}
}

func startLMTPServer(t *testing.T, finals []string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := bufio.NewWriter(c)
		fmt.Fprint(w, "220 fake LMTP\r\n")
		w.Flush()
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimSpace(line) == "." {
					for _, f := range finals {
						fmt.Fprintf(w, "%s\r\n", f)
					}
					w.Flush()
					inData = false
				}
				continue
			}
			u := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(u, "LHLO"):
				fmt.Fprint(w, "250 fake\r\n")
			case strings.HasPrefix(u, "MAIL"), strings.HasPrefix(u, "RCPT"):
				fmt.Fprint(w, "250 ok\r\n")
			case u == "DATA":
				fmt.Fprint(w, "354 send\r\n")
				inData = true
			case u == "QUIT":
				fmt.Fprint(w, "221 bye\r\n")
				w.Flush()
				return
			}
			w.Flush()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func TestLMTPHandlerMixedFinalOutcomes(t *testing.T) {
	addr, stop := startLMTPServer(t, []string{"250 2.0.0 delivered", "451 4.2.0 later", "550 5.1.1 unknown"})
	defer stop()
	host, portText, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portText, "%d", &port)
	h := NewLMTPDeliveryHandler(host, port, 10, 0)
	msg := Message{From: "sender@test", To: []string{"ok@test", "later@test", "bad@test"}}
	res, err := h.DeliverMessageWithMetadata(context.Background(), msg, []byte("Subject: x\r\n\r\nbody"))
	if err == nil || res == nil || !res.Success || len(res.RecipientOutcomes) != 3 {
		t.Fatalf("result=%+v err=%v", res, err)
	}
	want := []RecipientDeliveryStatus{RecipientDelivered, RecipientTemporaryFailure, RecipientPermanentFailure}
	for i := range want {
		if res.RecipientOutcomes[i].Status != want[i] {
			t.Fatalf("outcomes=%+v", res.RecipientOutcomes)
		}
	}
}

func TestLMTPHandlerAllAcceptedRecipientsFailReturnsOutcomes(t *testing.T) {
	addr, stop := startLMTPServer(t, []string{"451 4.2.0 later", "550 5.1.1 unknown"})
	defer stop()
	host, portText, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portText, "%d", &port)
	res, err := NewLMTPDeliveryHandler(host, port, 10, 0).DeliverMessageWithMetadata(context.Background(), Message{From: "sender@test", To: []string{"later@test", "bad@test"}}, []byte("body"))
	if err == nil || res == nil || len(res.RecipientOutcomes) != 2 || res.RecipientOutcomes[0].Status != RecipientTemporaryFailure || res.RecipientOutcomes[1].Status != RecipientPermanentFailure {
		t.Fatalf("result=%+v err=%v", res, err)
	}
}
