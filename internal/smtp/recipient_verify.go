package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// Recipient verification at RCPT time, for local domains.
//
// Without it, mail to a mailbox that does not exist is accepted with 250 and
// fails later, when the mailbox server refuses it, and the failure becomes a
// bounce to the envelope sender. Spam forges that sender, so the bounce lands
// on an innocent third party: backscatter, which gets the bouncing server
// blocklisted. Refusing the recipient during the SMTP conversation tells the
// real client instead, and nothing is generated.
//
// The mailbox server is the authority on which mailboxes exist, so it is
// asked, with an LMTP probe that stops after RCPT. Only a definite 5xx refuses
// the recipient. If the probe cannot get an answer (mailbox server down,
// timeout, 4xx), the recipient is accepted and the queue handles it as before:
// a verification outage must not become a mail outage.

type rcptVerdict int

const (
	rcptUnknown rcptVerdict = iota // could not tell; accept
	rcptExists
	rcptRejected
)

type cachedVerdict struct {
	verdict rcptVerdict
	reply   string
	expires time.Time
}

type recipientVerifier struct {
	addr     string // host:port of the LMTP server
	heloName string
	timeout  time.Duration
	logger   *slog.Logger

	// dial is replaced in tests.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	mu               sync.Mutex
	cache            map[string]cachedVerdict
	generation       func() string
	cachedGeneration string
	now              func() time.Time
	// unavailableUntil skips probing for a while after one fails, so a
	// mailbox server outage does not add the probe timeout to every RCPT.
	unavailableUntil time.Time
	// tlsConfig, when set, requires STARTTLS on every probe.
	tlsConfig *tls.Config
}

const rcptProbeBackoff = 30 * time.Second

const (
	rcptCacheExists   = 30 * time.Minute
	rcptCacheRejected = 5 * time.Minute
	rcptCacheMaxSize  = 20000
)

func newRecipientVerifier(addr, heloName string, logger *slog.Logger) *recipientVerifier {
	if heloName == "" {
		heloName = "localhost"
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &recipientVerifier{
		addr:     addr,
		heloName: heloName,
		timeout:  5 * time.Second,
		logger:   logger.With("component", "recipient-verify"),
		dial:     d.DialContext,
		cache:    make(map[string]cachedVerdict),
		now:      time.Now,
	}
}

// Verify reports whether rcpt exists, and the server's reply when it does not.
func (v *recipientVerifier) Verify(ctx context.Context, rcpt string) (rcptVerdict, string) {
	key := strings.ToLower(rcpt)
	now := v.now()
	generation := ""
	if v.generation != nil {
		generation = v.generation()
	}
	v.mu.Lock()
	if generation != v.cachedGeneration {
		v.cache = make(map[string]cachedVerdict)
		v.unavailableUntil = time.Time{}
		v.cachedGeneration = generation
	}

	if c, ok := v.cache[key]; ok && now.Before(c.expires) {
		v.mu.Unlock()
		return c.verdict, c.reply
	}
	if now.Before(v.unavailableUntil) {
		v.mu.Unlock()
		return rcptUnknown, ""
	}
	v.mu.Unlock()

	verdict, reply, err := v.probe(ctx, rcpt)
	if err != nil {
		v.mu.Lock()
		v.unavailableUntil = now.Add(rcptProbeBackoff)
		v.mu.Unlock()
		v.logger.Warn("Recipient verification unavailable; accepting recipients unverified for a while",
			"recipient", rcpt, "lmtp", v.addr, "error", err, "retry_after", rcptProbeBackoff.String())
		return rcptUnknown, ""
	}

	ttl := rcptCacheExists
	if verdict == rcptRejected {
		ttl = rcptCacheRejected
	}
	if v.generation != nil && v.generation() != generation {
		return verdict, reply
	}
	if verdict != rcptUnknown {
		v.mu.Lock()
		if v.cachedGeneration != generation {
			v.mu.Unlock()
			return verdict, reply
		}

		if len(v.cache) >= rcptCacheMaxSize {
			for k, c := range v.cache {
				if now.After(c.expires) {
					delete(v.cache, k)
				}
			}
			if len(v.cache) >= rcptCacheMaxSize {
				v.cache = make(map[string]cachedVerdict)
			}
		}
		v.cache[key] = cachedVerdict{verdict: verdict, reply: reply, expires: now.Add(ttl)}
		v.mu.Unlock()
	}
	return verdict, reply
}

// probe runs LHLO, MAIL FROM:<>, RCPT TO and stops, without sending a message.
func (v *recipientVerifier) probe(ctx context.Context, rcpt string) (rcptVerdict, string, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	conn, err := v.dial(ctx, "tcp", v.addr)
	if err != nil {
		return rcptUnknown, "", err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	r := bufio.NewReader(conn)
	readReply := func() (int, string, error) {
		var code int
		var last string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			line = strings.TrimRight(line, "\r\n")
			if len(line) < 3 {
				return 0, "", fmt.Errorf("short reply %q", line)
			}
			if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
				return 0, "", fmt.Errorf("malformed reply %q", line)
			}
			last = line
			if len(line) == 3 || line[3] != '-' {
				return code, last, nil
			}
		}
	}
	send := func(cmd string) (int, string, error) {
		if _, err := fmt.Fprintf(conn, "%s\r\n", cmd); err != nil {
			return 0, "", err
		}
		return readReply()
	}

	if code, line, err := readReply(); err != nil || code != 220 {
		return rcptUnknown, "", fmt.Errorf("greeting: %d %q %v", code, line, err)
	}
	if code, line, err := send("LHLO " + v.heloName); err != nil || code != 250 {
		return rcptUnknown, "", fmt.Errorf("LHLO: %d %q %v", code, line, err)
	}
	if v.tlsConfig != nil {
		// Same rule as delivery: STARTTLS or nothing, never a downgrade. The
		// probe needn't check the LHLO reply for STARTTLS; a server without
		// it refuses the command.
		if code, line, err := send("STARTTLS"); err != nil || code != 220 {
			return rcptUnknown, "", fmt.Errorf("STARTTLS: %d %q %v", code, line, err)
		}
		cfg := v.tlsConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(v.addr)
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return rcptUnknown, "", fmt.Errorf("TLS handshake: %w", err)
		}
		conn, r = tc, bufio.NewReader(tc)
		if code, line, err := send("LHLO " + v.heloName); err != nil || code != 250 {
			return rcptUnknown, "", fmt.Errorf("LHLO after TLS: %d %q %v", code, line, err)
		}
	}
	if code, line, err := send("MAIL FROM:<>"); err != nil || code != 250 {
		return rcptUnknown, "", fmt.Errorf("MAIL FROM: %d %q %v", code, line, err)
	}
	code, line, err := send("RCPT TO:<" + rcpt + ">")
	_, _ = fmt.Fprintf(conn, "RSET\r\nQUIT\r\n")
	if err != nil {
		return rcptUnknown, "", err
	}
	switch {
	case code >= 200 && code < 300:
		return rcptExists, "", nil
	case code >= 500 && code < 600:
		return rcptRejected, line, nil
	default:
		// 4xx: the server could not decide now. Not a "no".
		return rcptUnknown, "", fmt.Errorf("RCPT: %s", line)
	}
}
