package webmail

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// A minimal ManageSieve client (RFC 5804): enough to list, read, store
// and activate one user's scripts. Filters are edited rarely, so each
// request dials, authenticates as the user, does its work and hangs up;
// nothing is pooled.

// SieveScript is one script on the server.
type SieveScript struct {
	Name   string
	Active bool
}

// SieveConn is a signed-in ManageSieve session.
type SieveConn interface {
	List() ([]SieveScript, error)
	Get(name string) (string, error)
	Put(name, script string) error
	SetActive(name string) error
	Close() error
}

// SieveDialer opens a SieveConn as one user.
type SieveDialer func(ctx context.Context, user, password string) (SieveConn, error)

// ErrSieveRejected wraps a script the server refused to store, whose
// message (a compile error) is safe and useful to show.
var ErrSieveRejected = errors.New("webmail: sieve script rejected")

type sieveClient struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

// ManageSieveDialer connects to addr with the given TLS mode.
func ManageSieveDialer(addr, mode string, insecureSkipVerify bool) SieveDialer {
	return func(ctx context.Context, user, password string) (SieveConn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		tlsConf := &tls.Config{
			ServerName: host, MinVersion: tls.VersionTLS12,
			// #nosec G402 -- opt-in for the dev stack's self-signed certificate; documented as dev-only
			InsecureSkipVerify: insecureSkipVerify,
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		var conn net.Conn
		if mode == TLSModeImplicit {
			conn, err = tls.DialWithDialer(d, "tcp", addr, tlsConf)
		} else {
			conn, err = d.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("webmail: connect to ManageSieve %s: %w", addr, err)
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		c := &sieveClient{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn)}
		caps, err := c.response()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("webmail: ManageSieve greeting: %w", err)
		}
		if mode == TLSModeStartTLS {
			if !hasCap(caps, "STARTTLS") {
				_ = conn.Close()
				return nil, errors.New("webmail: ManageSieve server doesn't offer STARTTLS; set sieve_tls")
			}
			if _, err := c.cmd("STARTTLS"); err != nil {
				_ = conn.Close()
				return nil, err
			}
			tconn := tls.Client(conn, tlsConf)
			if err := tconn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("webmail: ManageSieve TLS: %w", err)
			}
			c.conn, c.r, c.w = tconn, bufio.NewReader(tconn), bufio.NewWriter(tconn)
			// The server re-announces its capabilities after STARTTLS.
			if _, err := c.response(); err != nil {
				_ = c.conn.Close()
				return nil, err
			}
		}
		auth := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
		if _, err := c.cmd(`AUTHENTICATE "PLAIN" ` + quoteSieve(auth)); err != nil {
			_ = c.conn.Close()
			var no *sieveNo
			if errors.As(err, &no) {
				return nil, ErrAuthFailed
			}
			return nil, err
		}
		return c, nil
	}
}

func hasCap(lines []string, name string) bool {
	for _, l := range lines {
		if strings.HasPrefix(strings.ToUpper(l), `"`+name+`"`) {
			return true
		}
	}
	return false
}

// sieveNo is a NO or BYE response, carrying the server's explanation.
type sieveNo struct{ msg string }

func (e *sieveNo) Error() string { return "webmail: ManageSieve: " + e.msg }

func (c *sieveClient) cmd(line string) ([]string, error) {
	if _, err := c.w.WriteString(line + "\r\n"); err != nil {
		return nil, err
	}
	if err := c.w.Flush(); err != nil {
		return nil, err
	}
	return c.response()
}

// response reads lines until OK, NO or BYE. Literals ({n} or {n+}) are
// folded into the line they belong to, so callers see one logical line per
// item.
func (c *sieveClient) response() ([]string, error) {
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		upper := strings.ToUpper(line)
		switch {
		case upper == "OK" || strings.HasPrefix(upper, "OK "):
			return lines, nil
		case upper == "NO" || strings.HasPrefix(upper, "NO ") || strings.HasPrefix(upper, "BYE"):
			return nil, &sieveNo{msg: sieveMessage(line)}
		}
		lines = append(lines, line)
	}
}

// readLine reads one logical line, inlining any literal it ends with.
func (c *sieveClient) readLine() (string, error) {
	var out strings.Builder
	for {
		raw, err := c.r.ReadString('\n')
		if err != nil {
			return "", err
		}
		raw = strings.TrimRight(raw, "\r\n")
		n, prefix, ok := literalLength(raw)
		if !ok {
			out.WriteString(raw)
			return out.String(), nil
		}
		if n > 1<<20 {
			return "", errors.New("webmail: ManageSieve literal too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return "", err
		}
		out.WriteString(prefix)
		// Re-quote the literal, so callers parse one string syntax.
		out.WriteString(`"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(string(buf)) + `"`)
	}
}

// literalLength recognises a line ending in {n} or {n+}.
func literalLength(line string) (int, string, bool) {
	if !strings.HasSuffix(line, "}") {
		return 0, "", false
	}
	i := strings.LastIndexByte(line, '{')
	if i < 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(line[i+1:len(line)-1], "+"))
	if err != nil || n < 0 {
		return 0, "", false
	}
	return n, line[:i], true
}

// sieveMessage pulls the human-readable text out of a NO response:
// NO (CODE) "text" or NO "text".
func sieveMessage(line string) string {
	if i := strings.IndexByte(line, '"'); i >= 0 {
		if s, _, err := unquoteSieve(line[i:]); err == nil {
			return s
		}
	}
	return line
}

func quoteSieve(s string) string {
	// Quoted strings can't carry line breaks; anything with them, or that
	// is long, goes as a literal instead.
	if strings.ContainsAny(s, "\r\n") || len(s) > 1000 {
		return "{" + strconv.Itoa(len(s)) + "+}\r\n" + s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// unquoteSieve reads a quoted string at the start of s and returns it with
// the rest of s.
func unquoteSieve(s string) (string, string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", s, errors.New("not quoted")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", errors.New("unterminated string")
}

func (c *sieveClient) List() ([]SieveScript, error) {
	lines, err := c.cmd("LISTSCRIPTS")
	if err != nil {
		return nil, err
	}
	var out []SieveScript
	for _, l := range lines {
		name, rest, err := unquoteSieve(l)
		if err != nil {
			continue
		}
		out = append(out, SieveScript{Name: name, Active: strings.Contains(strings.ToUpper(rest), "ACTIVE")})
	}
	return out, nil
}

func (c *sieveClient) Get(name string) (string, error) {
	lines, err := c.cmd("GETSCRIPT " + quoteSieve(name))
	if err != nil {
		var no *sieveNo
		if errors.As(err, &no) {
			return "", ErrNotFound
		}
		return "", err
	}
	if len(lines) == 0 {
		return "", nil
	}
	s, _, err := unquoteSieve(lines[0])
	return s, err
}

func (c *sieveClient) Put(name, script string) error {
	_, err := c.cmd("PUTSCRIPT " + quoteSieve(name) + " {" + strconv.Itoa(len(script)) + "+}\r\n" + script)
	var no *sieveNo
	if errors.As(err, &no) {
		return fmt.Errorf("%w: %s", ErrSieveRejected, no.msg)
	}
	return err
}

func (c *sieveClient) SetActive(name string) error {
	_, err := c.cmd("SETACTIVE " + quoteSieve(name))
	return err
}

func (c *sieveClient) Close() error {
	_, _ = c.cmd("LOGOUT")
	return c.conn.Close()
}
