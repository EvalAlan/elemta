package queue

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	smtp "github.com/emersion/go-smtp"
)

type countSession struct{ got *atomic.Int32 }

func (s *countSession) Reset()                               {}
func (s *countSession) Logout() error                        { return nil }
func (s *countSession) Mail(string, *smtp.MailOptions) error { return nil }
func (s *countSession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (s *countSession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	s.got.Add(1)
	return err
}

func TestLMTPReusesSessions(t *testing.T) {
	var conns, got atomic.Int32
	server := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		conns.Add(1)
		return &countSession{got: &got}, nil
	}))
	server.LMTP = true
	server.Domain = "mailbox.test"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	h := NewLMTPDeliveryHandler(host, port, 10, 0)
	msg := Message{ID: "q", From: "a@example.com", To: []string{"b@example.com"}}
	for i := 0; i < 5; i++ {
		if err := h.DeliverMessage(context.Background(), msg, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	if got.Load() != 5 || conns.Load() != 1 {
		t.Fatalf("delivered %d over %d connections, want 5 over 1", got.Load(), conns.Load())
	}
	// A pooled session the server has dropped is replaced, not a failure.
	h.poolMu.Lock()
	for _, s := range h.pool {
		_ = s.conn.Close()
	}
	h.poolMu.Unlock()
	if err := h.DeliverMessage(context.Background(), msg, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("after a dropped session: %v", err)
	}
	if got.Load() != 6 || conns.Load() != 2 {
		t.Fatalf("delivered %d over %d connections, want 6 over 2", got.Load(), conns.Load())
	}
}
