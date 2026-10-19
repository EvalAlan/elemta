package mailbox

// ManageSieve (RFC 5804): how the webmail, Thunderbird and other clients
// upload and activate Sieve scripts. Scripts are checked by compiling them
// with the same interpreter delivery uses, so a script that is accepted
// here will run.

import (
	"bufio"
	"bytes"
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
	"unicode"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// sieveExtensions is what the interpreter supports, as advertised.
const sieveExtensions = "fileinto envelope encoded-character comparator-i;octet comparator-i;ascii-casemap comparator-i;ascii-numeric comparator-i;unicode-casemap " +
	"imap4flags variables relational copy reject ereject subaddress environment body regex mailbox date vacation vacation-seconds"

const (
	sieveLineLimit    = 8 << 10
	sieveIdleTimeout  = 5 * time.Minute
	sieveMaxNameBytes = 128
)

type sieveSession struct {
	s       *Service
	conn    net.Conn
	r       *bufio.Reader
	w       *bufio.Writer
	tls     bool
	account *Account
}

func (s *Service) serveManageSieve(ln net.Listener, tlsConfig *tls.Config) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = conn.Close() }()
			ss := &sieveSession{s: s, conn: conn, r: bufio.NewReaderSize(conn, 4096), w: bufio.NewWriter(conn)}
			ss.run(tlsConfig)
		}()
	}
}

func (ss *sieveSession) run(tlsConfig *tls.Config) {
	ss.capabilities(tlsConfig)
	ss.ok("", "Elemta ManageSieve ready")
	for {
		_ = ss.conn.SetDeadline(time.Now().Add(sieveIdleTimeout))
		args, err := ss.readCommand()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				ss.bye("Protocol error: " + err.Error())
			}
			return
		}
		if len(args) == 0 {
			ss.no("", "Empty command")
			continue
		}
		cmd := strings.ToUpper(args[0])
		args = args[1:]
		ctx, cancel := context.WithTimeout(ss.s.ctx, 30*time.Second)
		done := ss.handle(ctx, cmd, args, tlsConfig)
		cancel()
		if done {
			return
		}
	}
}

// handle runs one command and reports whether the session is over.
func (ss *sieveSession) handle(ctx context.Context, cmd string, args []string, tlsConfig *tls.Config) bool {
	switch cmd {
	case "LOGOUT":
		ss.ok("", "Bye")
		return true
	case "NOOP":
		ss.ok("", "Done")
		return false
	case "CAPABILITY":
		ss.capabilities(tlsConfig)
		ss.ok("", "Capability completed")
		return false
	case "STARTTLS":
		if tlsConfig == nil || ss.tls {
			ss.no("", "STARTTLS isn't available")
			return false
		}
		ss.ok("", "Begin TLS negotiation")
		tc := tls.Server(ss.conn, tlsConfig)
		if err := tc.HandshakeContext(ctx); err != nil {
			return true
		}
		ss.conn, ss.tls = tc, true
		ss.r, ss.w = bufio.NewReaderSize(tc, 4096), bufio.NewWriter(tc)
		// RFC 5804 2.2: capabilities again after TLS.
		ss.capabilities(tlsConfig)
		ss.ok("", "TLS active")
		return false
	case "AUTHENTICATE":
		ss.authenticate(ctx, args)
		return false
	case "UNAUTHENTICATE":
		ss.account = nil
		ss.ok("", "Signed out")
		return false
	}
	if ss.account == nil {
		ss.no("", "Sign in first")
		return false
	}
	acct := ss.account.ID
	e := ss.s.engine
	switch cmd {
	case "LISTSCRIPTS":
		scripts, err := e.Scripts(ctx, acct)
		if err != nil {
			ss.no("TRYLATER", "Temporarily unavailable")
			return false
		}
		for _, sc := range scripts {
			line := quote(sc.Name)
			if sc.Active {
				line += " ACTIVE"
			}
			ss.line(line)
		}
		ss.ok("", "Listscripts completed")
	case "GETSCRIPT":
		if !ss.argc(args, 1) {
			return false
		}
		sc, err := e.Script(ctx, acct, args[0])
		if errors.Is(err, ErrNotFound) {
			ss.no("NONEXISTENT", "No such script")
			return false
		} else if err != nil {
			ss.no("TRYLATER", "Temporarily unavailable")
			return false
		}
		ss.line(literal(sc.Script))
		ss.ok("", "Getscript completed")
	case "PUTSCRIPT", "CHECKSCRIPT":
		name, script := "", ""
		if cmd == "PUTSCRIPT" {
			if !ss.argc(args, 2) {
				return false
			}
			name, script = args[0], args[1]
			if !validScriptName(name) {
				ss.no("", "Invalid script name")
				return false
			}
		} else {
			if !ss.argc(args, 1) {
				return false
			}
			script = args[0]
		}
		if len(script) > ss.s.cfg.Sieve.MaxScriptBytes {
			ss.no("QUOTA/MAXSIZE", "Script too large")
			return false
		}
		if _, err := compileSieve(script); err != nil {
			ss.no("", "Script error: "+err.Error())
			return false
		}
		if cmd == "CHECKSCRIPT" {
			ss.ok("", "Script is valid")
			return false
		}
		if err := e.PutScript(ctx, acct, name, script, ss.s.cfg.Sieve.MaxScripts); errors.Is(err, ErrScriptLimit) {
			ss.no("QUOTA/MAXSCRIPTS", "Too many scripts")
			return false
		} else if err != nil {
			ss.no("TRYLATER", "Temporarily unavailable")
			return false
		}
		ss.ok("", "Putscript completed")
	case "SETACTIVE":
		if !ss.argc(args, 1) {
			return false
		}
		if err := e.SetActive(ctx, acct, args[0]); errors.Is(err, ErrNotFound) {
			ss.no("NONEXISTENT", "No such script")
		} else if err != nil {
			ss.no("TRYLATER", "Temporarily unavailable")
		} else {
			ss.ok("", "Setactive completed")
		}
	case "DELETESCRIPT":
		if !ss.argc(args, 1) {
			return false
		}
		switch err := e.DeleteScript(ctx, acct, args[0]); {
		case errors.Is(err, ErrNotFound):
			ss.no("NONEXISTENT", "No such script")
		case errors.Is(err, ErrScriptActive):
			ss.no("ACTIVE", "The active script can't be deleted")
		case err != nil:
			ss.no("TRYLATER", "Temporarily unavailable")
		default:
			ss.ok("", "Deletescript completed")
		}
	case "RENAMESCRIPT":
		if !ss.argc(args, 2) {
			return false
		}
		if !validScriptName(args[1]) {
			ss.no("", "Invalid script name")
			return false
		}
		switch err := e.RenameScript(ctx, acct, args[0], args[1]); {
		case errors.Is(err, ErrNotFound):
			ss.no("NONEXISTENT", "No such script")
		case errors.Is(err, ErrExists):
			ss.no("ALREADYEXISTS", "A script with that name exists")
		case err != nil:
			ss.no("TRYLATER", "Temporarily unavailable")
		default:
			ss.ok("", "Renamescript completed")
		}
	case "HAVESPACE":
		if !ss.argc(args, 2) {
			return false
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 0 {
			ss.no("", "Invalid size")
		} else if n > ss.s.cfg.Sieve.MaxScriptBytes {
			ss.no("QUOTA/MAXSIZE", "Script too large")
		} else {
			ss.ok("", "Putscript would succeed")
		}
	default:
		ss.no("", "Unknown command")
	}
	return false
}

func (ss *sieveSession) argc(args []string, n int) bool {
	if len(args) != n {
		ss.no("", fmt.Sprintf("Expected %d arguments", n))
		return false
	}
	return true
}

func (ss *sieveSession) capabilities(tlsConfig *tls.Config) {
	ss.line(`"IMPLEMENTATION" "Elemta"`)
	ss.line(`"SIEVE" ` + quote(sieveExtensions))
	if ss.tls || ss.s.cfg.Server.AllowPlaintextAuth {
		ss.line(`"SASL" "PLAIN"`)
	} else {
		ss.line(`"SASL" ""`)
	}
	if tlsConfig != nil && !ss.tls {
		ss.line(`"STARTTLS"`)
	}
	ss.line(`"MAXREDIRECTS" ` + quote(strconv.Itoa(ss.s.cfg.Sieve.MaxRedirects)))
	ss.line(`"VERSION" "1.0"`)
}

func (ss *sieveSession) authenticate(ctx context.Context, args []string) {
	if ss.account != nil {
		ss.no("", "Already signed in")
		return
	}
	if !ss.tls && !ss.s.cfg.Server.AllowPlaintextAuth {
		ss.no("ENCRYPT-NEEDED", "Use STARTTLS first")
		return
	}
	if len(args) == 0 || !strings.EqualFold(args[0], "PLAIN") {
		ss.no("", "Only PLAIN is supported")
		return
	}
	var response string
	if len(args) > 1 {
		response = args[1]
	} else {
		ss.line(`""`)
		line, err := ss.readCommand()
		if err != nil || len(line) != 1 {
			ss.no("", "Authentication cancelled")
			return
		}
		response = line[0]
	}
	raw, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		ss.no("", "Invalid response")
		return
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) != 3 || (len(parts[0]) > 0 && !bytes.Equal(parts[0], parts[1])) {
		ss.no("", "Invalid PLAIN response")
		return
	}
	// ManageSieve is internal-only in deployments (the webmail edits
	// filters), so it is not a listener the requirement covers.
	a, err := ss.s.login(ctx, string(parts[1]), string(parts[2]), false, "")
	if err == nil && a.Policy != nil && !a.Policy.Filters {
		ss.no("", mailpolicy.FiltersOffMessage)
		return
	}
	if err != nil {
		if !errors.Is(err, ErrCredentials) {
			ss.no("TRYLATER", "Temporarily unavailable")
			return
		}
		ss.no("", "Authentication failed")
		return
	}
	ss.account = &a
	ss.ok("", "Signed in")
}

// readCommand reads one command line into words, with quoted strings and
// literals ({n} or {n+}) decoded.
func (ss *sieveSession) readCommand() ([]string, error) {
	var out []string
	for {
		line, err := ss.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > sieveLineLimit {
			return nil, errors.New("line too long")
		}
		if err != nil {
			return nil, err
		}
		s := strings.TrimRight(string(line), "\r\n")
		words, lit, err := parseSieveWords(s)
		if err != nil {
			return nil, err
		}
		out = append(out, words...)
		if lit < 0 {
			return out, nil
		}
		if lit > ss.s.cfg.Sieve.MaxScriptBytes+1024 {
			return nil, errors.New("literal too large")
		}
		buf := make([]byte, lit)
		if _, err := io.ReadFull(ss.r, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf))
		// The rest of the command follows the literal on the same line.
	}
}

// parseSieveWords splits a command line. It returns the literal length
// when the line ends with one, or -1.
func parseSieveWords(s string) ([]string, int, error) {
	var out []string
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ':
			i++
		case '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, 0, errors.New("unterminated string")
			}
			out = append(out, b.String())
			i = j + 1
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 || i+end != len(s)-1 {
				return nil, 0, errors.New("bad literal")
			}
			n, err := strconv.Atoi(strings.TrimSuffix(s[i+1:i+end], "+"))
			if err != nil || n < 0 {
				return nil, 0, errors.New("bad literal length")
			}
			return out, n, nil
		default:
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, -1, nil
}

func validScriptName(name string) bool {
	if name == "" || len(name) > sieveMaxNameBytes {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func literal(s string) string {
	return "{" + strconv.Itoa(len(s)) + "}\r\n" + s
}

func (ss *sieveSession) line(s string) {
	_, _ = ss.w.WriteString(s + "\r\n")
}

func (ss *sieveSession) respond(kind, code, text string) {
	line := kind
	if code != "" {
		line += " (" + code + ")"
	}
	if text != "" {
		line += " " + quote(text)
	}
	ss.line(line)
	_ = ss.w.Flush()
}

func (ss *sieveSession) ok(code, text string) { ss.respond("OK", code, text) }
func (ss *sieveSession) no(code, text string) { ss.respond("NO", code, text) }
func (ss *sieveSession) bye(text string)      { ss.respond("BYE", "", text) }
