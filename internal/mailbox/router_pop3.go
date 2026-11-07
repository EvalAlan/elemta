package mailbox

// POP3 and ManageSieve through the router: everything up to sign-in here,
// then the cell.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// servePOP3 handles one POP3 client (RFC 1939, STLS from RFC 2595, AUTH
// PLAIN from RFC 5034). Sign-in needs TLS, as on a mailbox server.
func (r *Router) servePOP3(c net.Conn) {
	l := newLineConn(c)
	defer func() { _ = l.Close() }()
	if err := l.writeLine("+OK Elemta POP3 ready"); err != nil {
		return
	}
	var user string
	tries := 0
	for tries < routerTries {
		line, err := l.readLine()
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		switch cmd {
		case "CAPA":
			_ = l.writeLine("+OK Capability list follows")
			_ = l.writeLine("USER")
			_ = l.writeLine("UIDL")
			_ = l.writeLine("TOP")
			if l.secure {
				_ = l.writeLine("SASL PLAIN")
			} else if r.tls != nil {
				_ = l.writeLine("STLS")
			}
			_ = l.writeLine(".")
		case "STLS":
			if l.secure || r.tls == nil {
				_ = l.writeLine("-ERR STLS unavailable")
				continue
			}
			if err := l.writeLine("+OK Begin TLS"); err != nil {
				return
			}
			if err := l.upgradeServer(r.tls); err != nil {
				return
			}
			user = ""
		case "QUIT":
			_ = l.writeLine("+OK Bye")
			return
		case "NOOP":
			_ = l.writeLine("+OK")
		case "USER", "PASS", "AUTH":
			if !l.secure {
				_ = l.writeLine("-ERR [AUTH] Use STLS before authentication")
				continue
			}
			switch cmd {
			case "USER":
				if arg == "" || strings.Contains(arg, " ") {
					_ = l.writeLine("-ERR Invalid username")
					continue
				}
				user = arg
				_ = l.writeLine("+OK Send password")
				continue
			case "PASS":
				if user == "" {
					_ = l.writeLine("-ERR Send USER first")
					continue
				}
			case "AUTH":
				mech, response, _ := strings.Cut(arg, " ")
				if !strings.EqualFold(mech, "PLAIN") {
					_ = l.writeLine("-ERR Unsupported mechanism")
					continue
				}
				if response == "" {
					if err := l.writeLine("+ "); err != nil {
						return
					}
					if response, err = l.readLine(); err != nil {
						return
					}
				}
				raw, err := base64.StdEncoding.DecodeString(response)
				authz, u, p, ok := saslPlain(raw)
				if err != nil || !ok || (authz != "" && !strings.EqualFold(authz, u)) {
					_ = l.writeLine("-ERR Malformed PLAIN response")
					continue
				}
				user, arg = u, p
			}
			done, failed := r.pop3SignIn(l, user, arg)
			if done {
				return
			}
			if failed {
				tries++
			}
			user = ""
		default:
			_ = l.writeLine("-ERR Authentication required")
		}
	}
}

// pop3SignIn signs in at the mailbox's cell and hands the client over.
// done is true when the client was handed over or is gone; failed counts a
// wrong password.
func (r *Router) pop3SignIn(l *lineConn, user, password string) (done, failed bool) {
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	b, err := r.cellLine(ctx, user, l, func(c *routerCell) string { return c.POP3 }, func(b *lineConn) error {
		greeting, err := b.readLine()
		if err != nil || !strings.HasPrefix(greeting, "+OK") {
			return fmt.Errorf("cell greeted with %q (%v)", greeting, err)
		}
		return nil
	}, "STLS", "+OK")
	if err != nil {
		_ = l.writeLine("-ERR [SYS/TEMP] Mailbox temporarily unavailable, try again shortly")
		return false, false
	}
	reply, err := exchange(b, "USER "+user)
	if err == nil && strings.HasPrefix(reply, "+OK") {
		reply, err = exchange(b, "PASS "+password)
	}
	if err != nil {
		_ = b.Close()
		_ = l.writeLine("-ERR [SYS/TEMP] Mailbox temporarily unavailable, try again shortly")
		return false, false
	}
	if !strings.HasPrefix(reply, "+OK") {
		_ = b.Close()
		_ = l.writeLine(reply)
		// The cell ends the session on these; so does the router.
		return strings.Contains(reply, "[IN-USE]") || strings.Contains(reply, "[SYS/PERM]"), strings.Contains(reply, "[AUTH]")
	}
	if err := l.writeLine(reply); err != nil {
		_ = b.Close()
		return true, false
	}
	relay(l, b)
	return true, false
}

func exchange(b *lineConn, line string) (string, error) {
	if err := b.writeLine(line); err != nil {
		return "", err
	}
	return b.readLine()
}

// cellLine connects to user's cell on the listener addr picks, reads its
// greeting, and starts TLS with the STARTTLS command given, expecting a
// reply starting with okPrefix.
func (r *Router) cellLine(ctx context.Context, user string, client *lineConn, addr func(*routerCell) string, greet func(*lineConn) error, starttls, okPrefix string) (*lineConn, error) {
	cell, err := r.cellFor(ctx, user)
	if err != nil {
		r.log.Warn("router: finding a mailbox's cell", "error", err)
		return nil, err
	}
	bc, err := r.dialCell(ctx, cell, addr(cell), client.Conn, false)
	if err != nil {
		r.log.Warn("router: connecting to a cell", "cell", cell.Name, "error", err)
		return nil, err
	}
	b := newLineConn(bc)
	fail := func(err error) (*lineConn, error) {
		_ = b.Close()
		r.log.Warn("router: starting a session at a cell", "cell", cell.Name, "error", err)
		return nil, err
	}
	if err := greet(b); err != nil {
		return fail(err)
	}
	reply, err := exchange(b, starttls)
	if err != nil {
		return fail(err)
	}
	if !strings.HasPrefix(reply, okPrefix) {
		return fail(fmt.Errorf("cell refused %s: %q", starttls, reply))
	}
	tc, err := r.startTLS(ctx, cell, b.Conn)
	if err != nil {
		return fail(err)
	}
	return newLineConn(tc), nil
}

// serveSieve handles one ManageSieve client (RFC 5804). The webmail edits
// filters through it.
func (r *Router) serveSieve(c net.Conn) {
	l := newLineConn(c)
	defer func() { _ = l.Close() }()
	plainOK := func() bool { return l.secure || r.isInternal(l.RemoteAddr()) }
	capabilities := func() error {
		lines := []string{`"IMPLEMENTATION" "Elemta"`, `"SIEVE" ` + quote(sieveExtensions)}
		if plainOK() {
			lines = append(lines, `"SASL" "PLAIN"`)
		} else {
			lines = append(lines, `"SASL" ""`)
		}
		if r.tls != nil && !l.secure {
			lines = append(lines, `"STARTTLS"`)
		}
		lines = append(lines, `"MAXREDIRECTS" `+quote(strconv.Itoa(Config{}.WithDefaults().Sieve.MaxRedirects)), `"VERSION" "1.0"`)
		for _, line := range lines {
			if err := l.writeLine(line); err != nil {
				return err
			}
		}
		return nil
	}
	if capabilities() != nil || l.writeLine(`OK "Elemta ManageSieve ready"`) != nil {
		return
	}
	tries := 0
	for tries < routerTries {
		words, err := readTokens(l, "")
		if err != nil {
			return
		}
		if len(words) == 0 {
			continue
		}
		switch strings.ToUpper(words[0]) {
		case "CAPABILITY":
			if capabilities() != nil || l.writeLine(`OK "Capability completed"`) != nil {
				return
			}
		case "NOOP":
			_ = l.writeLine(`OK "Done"`)
		case "LOGOUT":
			_ = l.writeLine(`OK "Bye"`)
			return
		case "STARTTLS":
			if l.secure || r.tls == nil {
				_ = l.writeLine(`NO "STARTTLS isn't available"`)
				continue
			}
			if l.writeLine(`OK "Begin TLS negotiation"`) != nil || l.upgradeServer(r.tls) != nil {
				return
			}
			if capabilities() != nil || l.writeLine(`OK "TLS active"`) != nil {
				return
			}
		case "AUTHENTICATE":
			if !plainOK() {
				_ = l.writeLine(`NO (ENCRYPT-NEEDED) "Use STARTTLS first"`)
				continue
			}
			if len(words) < 2 || !strings.EqualFold(words[1], "PLAIN") {
				_ = l.writeLine(`NO "Only PLAIN is supported"`)
				continue
			}
			response := ""
			if len(words) > 2 {
				response = words[2]
			} else {
				if err := l.writeLine(`""`); err != nil {
					return
				}
				more, err := readTokens(l, "")
				if err != nil || len(more) != 1 {
					_ = l.writeLine(`NO "Authentication cancelled"`)
					continue
				}
				response = more[0]
			}
			raw, err := base64.StdEncoding.DecodeString(response)
			authz, user, _, ok := saslPlain(raw)
			if err != nil || !ok || (authz != "" && authz != user) {
				_ = l.writeLine(`NO "Invalid PLAIN response"`)
				continue
			}
			done, failed := r.sieveSignIn(l, user, response)
			if done {
				return
			}
			if failed {
				tries++
			}
		default:
			_ = l.writeLine(`NO "Sign in first"`)
		}
	}
}

func (r *Router) sieveSignIn(l *lineConn, user, plain string) (done, failed bool) {
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	readCaps := func(b *lineConn) error {
		for {
			line, err := b.readLine()
			if err != nil {
				return err
			}
			if strings.HasPrefix(line, "OK") {
				return nil
			}
			if strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
				return fmt.Errorf("cell said %q", line)
			}
		}
	}
	b, err := r.cellLine(ctx, user, l, func(c *routerCell) string { return c.Sieve }, readCaps, "STARTTLS", "OK")
	if err == nil {
		// Capabilities again after TLS (RFC 5804 2.2).
		if err = readCaps(b); err != nil {
			_ = b.Close()
		}
	}
	if err != nil {
		_ = l.writeLine(`NO (TRYLATER) "Temporarily unavailable"`)
		return false, false
	}
	reply, err := exchange(b, `AUTHENTICATE "PLAIN" "`+plain+`"`)
	if err != nil {
		_ = b.Close()
		_ = l.writeLine(`NO (TRYLATER) "Temporarily unavailable"`)
		return false, false
	}
	if !strings.HasPrefix(reply, "OK") {
		_ = b.Close()
		_ = l.writeLine(reply)
		return false, !strings.Contains(reply, "TRYLATER")
	}
	if err := l.writeLine(reply); err != nil {
		_ = b.Close()
		return true, false
	}
	relay(l, b)
	return true, false
}
