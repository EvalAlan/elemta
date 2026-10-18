package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"

	smtp "github.com/emersion/go-smtp"
)

type capturedLMTP struct {
	token string
	raw   []byte
}
type retryLMTPSession struct {
	records chan capturedLMTP
	token   string
}

func (s *retryLMTPSession) Reset()        { s.token = "" }
func (s *retryLMTPSession) Logout() error { return nil }
func (s *retryLMTPSession) Mail(_ string, o *smtp.MailOptions) error {
	s.token = o.EnvelopeID
	return nil
}
func (s *retryLMTPSession) Rcpt(_ string, _ *smtp.RcptOptions) error { return nil }
func (s *retryLMTPSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err == nil {
		s.records <- capturedLMTP{token: s.token, raw: raw}
	}
	return err
}
func TestLMTPStableRetryAndDotTransparency(t *testing.T) {
	for _, dsn := range []bool{false, true} {
		t.Run(fmt.Sprint(dsn), func(t *testing.T) {
			records := make(chan capturedLMTP, 2)
			server := smtp.NewServer(smtp.BackendFunc(func(_ *smtp.Conn) (smtp.Session, error) { return &retryLMTPSession{records: records}, nil }))
			server.LMTP = true
			server.Domain = "fixture"
			server.EnableDSN = dsn
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = server.Serve(listener) }()
			defer func() { _ = server.Close(); <-done }()
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			handler := NewLMTPDeliveryHandler(host, port, 10, 0)
			msg := Message{ID: "stable-queue-id", From: "sender@example.com", To: []string{"user@example.com"}}
			raw := []byte("Subject: dots\r\n\r\nfirst\r\n.\r\n..two\r\nlast\r\n")
			for range 2 {
				if err := handler.DeliverMessage(context.Background(), msg, raw); err != nil {
					t.Fatal(err)
				}
				record := <-records
				if !bytes.Equal(record.raw, raw) {
					t.Fatalf("dot transparency changed bytes: %q", record.raw)
				}
				want := ""
				if dsn {
					want = fmt.Sprintf("%x", sha256.Sum256([]byte(msg.ID)))
				}
				if record.token != want {
					t.Fatalf("retry token=%q want=%q", record.token, want)
				}
			}
		})
	}
}
