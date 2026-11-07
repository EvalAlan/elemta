package mailbox

// IMAP through the router: everything up to sign-in here, then the cell.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// serveIMAP handles one IMAP client. public listeners require TLS before
// sign-in; the internal one allows plaintext from internal networks.
func (r *Router) serveIMAP(c net.Conn, public bool) {
	r.imap(newLineConn(c), public)
}

// imapClient is one IMAP client before sign-in.
type imapClient struct {
	r      *Router
	l      *lineConn
	public bool
	tries  int
}

func (r *Router) imap(l *lineConn, public bool) {
	ic := &imapClient{r: r, l: l, public: public}
	defer func() { _ = l.Close() }()
	if err := l.writeLine("* OK [CAPABILITY " + ic.caps() + "] Elemta mailbox ready"); err != nil {
		return
	}
	for {
		tag, name, args, err := readIMAPCommand(l)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				_ = l.writeLine("* BYE Line too long")
			}
			return
		}
		if tag == "" {
			_ = l.writeLine("* BAD Missing tag")
			continue
		}
		switch name {
		case "CAPABILITY":
			_ = l.writeLine("* CAPABILITY " + ic.caps())
			_ = l.writeLine(tag + " OK CAPABILITY completed")
		case "NOOP":
			_ = l.writeLine(tag + " OK NOOP completed")
		case "ID":
			_ = l.writeLine(`* ID ("name" "Elemta")`)
			_ = l.writeLine(tag + " OK ID completed")
		case "LOGOUT":
			_ = l.writeLine("* BYE Logging out")
			_ = l.writeLine(tag + " OK LOGOUT completed")
			return
		case "STARTTLS":
			if l.secure || r.tls == nil {
				_ = l.writeLine(tag + " BAD STARTTLS not available")
				continue
			}
			if err := l.writeLine(tag + " OK Begin TLS negotiation now"); err != nil {
				return
			}
			if err := l.upgradeServer(r.tls); err != nil {
				return
			}
		case "LOGIN":
			if len(args) != 2 {
				_ = l.writeLine(tag + " BAD LOGIN takes a user name and a password")
				continue
			}
			if !ic.plainAllowed() {
				_ = l.writeLine(tag + " NO [PRIVACYREQUIRED] Use STARTTLS first")
				continue
			}
			if ic.signIn(tag, args[0], args[1]) {
				return
			}
		case "AUTHENTICATE":
			if len(args) < 1 || !strings.EqualFold(args[0], "PLAIN") {
				_ = l.writeLine(tag + " NO Unsupported authentication mechanism")
				continue
			}
			if !ic.plainAllowed() {
				_ = l.writeLine(tag + " NO [PRIVACYREQUIRED] Use STARTTLS first")
				continue
			}
			var response string
			if len(args) > 1 {
				response = args[1]
			} else {
				if err := l.writeLine("+ "); err != nil {
					return
				}
				if response, err = l.readLine(); err != nil {
					return
				}
				if response == "*" {
					_ = l.writeLine(tag + " BAD Authentication cancelled")
					continue
				}
			}
			if response == "=" {
				response = ""
			}
			raw, err := base64.StdEncoding.DecodeString(response)
			authz, user, password, ok := saslPlain(raw)
			if err != nil || !ok {
				_ = l.writeLine(tag + " BAD Malformed PLAIN response")
				continue
			}
			if authz != "" && !strings.EqualFold(authz, user) {
				_ = l.writeLine(tag + " NO [AUTHORIZATIONFAILED] Signing in as someone else isn't supported")
				continue
			}
			if ic.signIn(tag, user, password) {
				return
			}
		default:
			_ = l.writeLine(tag + " BAD Sign in first")
		}
		if ic.tries >= routerTries {
			_ = l.writeLine("* BYE Too many failed sign-ins")
			return
		}
	}
}

func (ic *imapClient) plainAllowed() bool {
	return ic.l.secure || (!ic.public && ic.r.isInternal(ic.l.RemoteAddr()))
}

func (ic *imapClient) caps() string {
	caps := []string{"IMAP4rev1", "ID", "LITERAL+", "SASL-IR"}
	if !ic.l.secure && ic.r.tls != nil {
		caps = append(caps, "STARTTLS")
	}
	if ic.plainAllowed() {
		caps = append(caps, "AUTH=PLAIN")
	} else {
		caps = append(caps, "LOGINDISABLED")
	}
	return strings.Join(caps, " ")
}

// signIn signs in at the mailbox's cell. It returns true once the client
// is handed over (or gone); false leaves it here to try again.
func (ic *imapClient) signIn(tag, user, password string) bool {
	l := ic.l
	ctx, cancel := context.WithTimeout(ic.r.ctx, 20*time.Second)
	defer cancel()
	cell, err := ic.r.cellFor(ctx, user)
	if err != nil {
		ic.r.log.Warn("router: finding a mailbox's cell", "error", err)
		_ = l.writeLine(tag + " NO [UNAVAILABLE] Mailbox temporarily unavailable, try again shortly")
		return false
	}
	bc, err := ic.r.dialCell(ctx, cell, cell.IMAPS, l.Conn, true)
	if err != nil {
		ic.r.log.Warn("router: connecting to a cell", "cell", cell.Name, "error", err)
		_ = l.writeLine(tag + " NO [UNAVAILABLE] Mailbox temporarily unavailable, try again shortly")
		return false
	}
	b := newLineConn(bc)
	ok, untagged, final, err := imapLogin(b, user, password)
	if err != nil {
		_ = b.Close()
		ic.r.log.Warn("router: signing in at a cell", "cell", cell.Name, "error", err)
		_ = l.writeLine(tag + " NO [UNAVAILABLE] Mailbox temporarily unavailable, try again shortly")
		return false
	}
	if !ok {
		_ = b.Close()
		ic.tries++
		_ = l.writeLine(tag + " NO" + final)
		return false
	}
	for _, u := range untagged {
		if err := l.writeLine(u); err != nil {
			_ = b.Close()
			return true
		}
	}
	if err := l.writeLine(tag + " OK" + final); err != nil {
		_ = b.Close()
		return true
	}
	relay(l, b)
	return true
}

// imapLogin signs in on a cell's connection. ok is the cell's answer;
// untagged are its untagged lines before it; final is the rest of its
// tagged line after OK or NO (" [CAPABILITY ...] Logged in").
func imapLogin(b *lineConn, user, password string) (ok bool, untagged []string, final string, err error) {
	greeting, err := b.readLine()
	if err != nil {
		return false, nil, "", err
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return false, nil, "", fmt.Errorf("cell greeted with %q", greeting)
	}
	// Synchronizing literals: they carry any user name or password
	// exactly, whatever characters it holds.
	const tag = "r1"
	steps := []string{fmt.Sprintf("%s LOGIN {%d}", tag, len(user)), fmt.Sprintf("%s {%d}", user, len(password)), password}
	for i, step := range steps {
		if err := b.writeLine(step); err != nil {
			return false, nil, "", err
		}
		if i == len(steps)-1 {
			break
		}
		// The cell asks for each literal with a continuation, or refuses.
		for {
			line, err := b.readLine()
			if err != nil {
				return false, nil, "", err
			}
			if strings.HasPrefix(line, "+") {
				break
			}
			if rest, found := strings.CutPrefix(line, tag+" "); found {
				_, after, _ := strings.Cut(rest, " ")
				if after != "" {
					after = " " + after
				}
				return false, nil, after, nil
			}
		}
	}
	for {
		line, err := b.readLine()
		if err != nil {
			return false, nil, "", err
		}
		rest, found := strings.CutPrefix(line, tag+" ")
		if !found {
			untagged = append(untagged, line)
			continue
		}
		status, after, _ := strings.Cut(rest, " ")
		if after != "" {
			after = " " + after
		}
		return strings.EqualFold(status, "OK"), untagged, after, nil
	}
}

// readIMAPCommand reads one command: its tag, its name in upper case and
// its arguments, with quoted strings unquoted and literals read in.
func readIMAPCommand(l *lineConn) (tag, name string, args []string, err error) {
	tokens, err := readTokens(l, "+ Ready for literal data")
	if err != nil {
		return "", "", nil, err
	}
	if len(tokens) == 0 {
		return "", "", nil, nil
	}
	tag = tokens[0]
	if len(tokens) > 1 {
		name = strings.ToUpper(tokens[1])
		args = tokens[2:]
	}
	return tag, name, args, nil
}

// readTokens reads one command line as tokens, reading in literals. A
// synchronizing literal ({n}) is answered with cont before its data is
// sent; ManageSieve has no such answer (cont "").
func readTokens(l *lineConn, cont string) ([]string, error) {
	line, err := l.readLine()
	if err != nil {
		return nil, err
	}
	var tokens []string
	total := len(line)
	for {
		toks, literal, plus, perr := imapTokens(line)
		if perr != nil {
			return nil, perr
		}
		tokens = append(tokens, toks...)
		if literal < 0 {
			return tokens, nil
		}
		if !plus && cont != "" {
			if err := l.writeLine(cont); err != nil {
				return nil, err
			}
		}
		data, err := l.readN(literal)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, data)
		if line, err = l.readLine(); err != nil {
			return nil, err
		}
		total += literal + len(line)
		if total > routerLine {
			return nil, errLineTooLong
		}
	}
}

// imapTokens splits a line into atoms and quoted strings. A trailing
// literal announcement ({n} or {n+}) is returned as its length, else -1.
func imapTokens(line string) (tokens []string, literal int, plus bool, err error) {
	i := 0
	for i < len(line) {
		switch line[i] {
		case ' ':
			i++
		case '"':
			var b strings.Builder
			i++
			for {
				if i >= len(line) {
					return nil, -1, false, errors.New("unterminated quoted string")
				}
				ch := line[i]
				if ch == '\\' && i+1 < len(line) {
					b.WriteByte(line[i+1])
					i += 2
					continue
				}
				i++
				if ch == '"' {
					break
				}
				b.WriteByte(ch)
			}
			tokens = append(tokens, b.String())
		case '{':
			end := strings.IndexByte(line[i:], '}')
			if end < 0 || i+end != len(line)-1 {
				return nil, -1, false, errors.New("malformed literal")
			}
			spec := line[i+1 : i+end]
			spec, plus = strings.CutSuffix(spec, "+")
			n, err := strconv.Atoi(spec)
			if err != nil || n < 0 {
				return nil, -1, false, errors.New("malformed literal")
			}
			return tokens, n, plus, nil
		default:
			j := i
			for j < len(line) && line[j] != ' ' {
				j++
			}
			tokens = append(tokens, line[i:j])
			i = j
		}
	}
	return tokens, -1, false, nil
}
