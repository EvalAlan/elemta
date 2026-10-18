package queue

// LMTP session reuse. Opening a connection, reading the greeting, LHLO and
// (when required) STARTTLS with a full TLS handshake costs more than
// delivering a typical message, and the queue delivers to one mailbox
// server, so finished sessions wait in a small pool and the next delivery
// takes one, checked with RSET. A session is pooled only after a clean
// transaction, and idles at most lmtpIdle, well under the mailbox
// server's own idle timeout.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const lmtpIdle = 30 * time.Second

// errLMTPSetup marks a failure while preparing a session (TLS required but
// unavailable or failing), which the queue treats as temporary.
var errLMTPSetup = errors.New("LMTP session setup failed")

type lmtpSession struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	exts map[string]bool
	idle time.Time
	h    *LMTPDeliveryHandler
}

// command sends one command line and reads a one-line reply.
func (s *lmtpSession) command(cmd string) (string, error) {
	s.h.logger.Debug("LMTP command", "command", strings.TrimSpace(cmd))
	if _, err := s.w.WriteString(cmd); err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}
	if err := s.w.Flush(); err != nil {
		return "", fmt.Errorf("failed to flush command: %w", err)
	}
	resp, err := s.r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	resp = strings.TrimSpace(resp)
	s.h.logger.Debug("LMTP response", "response", resp)
	return resp, nil
}

// lhlo sends LHLO and returns the server's extensions (upper case).
func (s *lmtpSession) lhlo() (map[string]bool, error) {
	resp, err := s.command("LHLO elemta.local\r\n")
	if err != nil {
		return nil, fmt.Errorf("LHLO failed: %w", err)
	}
	exts := map[string]bool{}
	note := func(line string) {
		if len(line) >= 4 {
			exts[strings.ToUpper(strings.Fields(line[4:] + " ")[0])] = true
		}
	}
	note(resp)
	for strings.HasPrefix(resp, "250-") {
		if resp, err = s.r.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("failed to read LHLO continuation: %w", err)
		}
		resp = strings.TrimSpace(resp)
		note(resp)
	}
	if !strings.HasPrefix(resp, "250 ") {
		return nil, fmt.Errorf("server rejected LHLO: %s", resp)
	}
	return exts, nil
}

// acquire returns a ready session: a pooled one that still answers RSET,
// or a new one.
func (h *LMTPDeliveryHandler) acquire(ctx context.Context) (*lmtpSession, error) {
	deadline := time.Now().Add(h.timeout)
	for {
		h.poolMu.Lock()
		var s *lmtpSession
		if n := len(h.pool); n > 0 {
			s, h.pool = h.pool[n-1], h.pool[:n-1]
		}
		h.poolMu.Unlock()
		if s == nil {
			break
		}
		if time.Since(s.idle) > lmtpIdle {
			_ = s.conn.Close()
			continue
		}
		_ = s.conn.SetDeadline(deadline)
		if resp, err := s.command("RSET\r\n"); err == nil && strings.HasPrefix(resp, "250") {
			return s, nil
		}
		_ = s.conn.Close() // the server closed it while idle
	}
	return h.dial(ctx, deadline)
}

// release returns a session after a clean transaction.
func (h *LMTPDeliveryHandler) release(s *lmtpSession) {
	s.idle = time.Now()
	_ = s.conn.SetDeadline(time.Time{})
	h.poolMu.Lock()
	defer h.poolMu.Unlock()
	if len(h.pool) >= h.maxInFly {
		_ = s.conn.Close()
		return
	}
	h.pool = append(h.pool, s)
}

func (h *LMTPDeliveryHandler) dial(ctx context.Context, deadline time.Time) (*lmtpSession, error) {
	addr := net.JoinHostPort(h.host, fmt.Sprintf("%d", h.port))
	d := net.Dialer{Timeout: h.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LMTP server %s: %w", addr, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(deadline); err != nil {
		h.logger.Warn("Failed to set connection deadline", "error", err)
	}
	s := &lmtpSession{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn), h: h}
	greeting, err := s.r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read server greeting: %w", err)
	}
	if greeting = strings.TrimSpace(greeting); !strings.HasPrefix(greeting, "220 ") {
		return nil, fmt.Errorf("unexpected server greeting: %s", greeting)
	}
	if s.exts, err = s.lhlo(); err != nil {
		return nil, err
	}
	if h.tlsConfig != nil {
		// TLS was required, so a server without it is a temporary failure,
		// never a silent downgrade to plaintext.
		if !s.exts["STARTTLS"] {
			return nil, fmt.Errorf("%w: LMTP server doesn't offer STARTTLS, which is required", errLMTPSetup)
		}
		if resp, err := s.command("STARTTLS\r\n"); err != nil || !strings.HasPrefix(resp, "220") {
			return nil, fmt.Errorf("%w: STARTTLS failed: %s %v", errLMTPSetup, resp, err)
		}
		cfg := h.tlsConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = h.host
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("%w: TLS handshake failed: %v", errLMTPSetup, err)
		}
		conn = tc
		s.conn, s.r, s.w = tc, bufio.NewReader(tc), bufio.NewWriter(tc)
		// RFC 3207: forget everything learnt before TLS and ask again.
		if s.exts, err = s.lhlo(); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}

// Close drops pooled sessions.
func (h *LMTPDeliveryHandler) Close() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()
	for _, s := range h.pool {
		_, _ = s.w.WriteString("QUIT\r\n")
		_ = s.w.Flush()
		_ = s.conn.Close()
	}
	h.pool = nil
}
