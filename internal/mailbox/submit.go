package mailbox

// Outgoing mail for Sieve redirect and vacation replies, handed to the MTA
// over SMTP submission like any other client's mail, so it gets the same
// signing, queueing and policy.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

func (s *Service) submit(ctx context.Context, from string, to []string, msg []byte) error {
	cfg := s.cfg.Sieve
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", cfg.SubmitAddr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	host, _, _ := net.SplitHostPort(cfg.SubmitAddr)
	var c *smtp.Client
	switch cfg.SubmitTLS {
	case "starttls":
		// #nosec G402 -- opt-in for development certificates, documented as such
		c, err = smtp.NewClientStartTLS(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.SubmitInsecureSkipVerify})
		if err != nil {
			_ = conn.Close()
			return err
		}
	case "none", "":
		c = smtp.NewClient(conn)
	default:
		_ = conn.Close()
		return errors.New("sieve.submit_tls must be none or starttls")
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(cfg.Hostname); err != nil && cfg.SubmitTLS != "starttls" {
		return err
	}
	if user := os.Getenv(cfg.SubmitUserEnv); user != "" {
		if err := c.Auth(sasl.NewPlainClient("", user, os.Getenv(cfg.SubmitPasswordEnv))); err != nil {
			return err
		}
	}
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := bytes.NewReader(msg).WriteTo(w); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
