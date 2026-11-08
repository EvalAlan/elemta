package mailbox

// LMTP through the router: the MTA delivers to the router as to a mailbox
// server, and each recipient is passed to its own cell. RCPT is answered
// with the cell's own answer, so the MTA's recipient check (an LMTP probe
// that stops after RCPT) still learns whether a mailbox exists; after DATA
// each recipient gets its cell's reply, in the order given, so a message
// for three cells is three deliveries whose outcomes the MTA sees
// separately, exactly as from one server.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
)

func (r *Router) lmtpServer() *smtp.Server {
	s := smtp.NewServer(&lmtpRouterBackend{r: r})
	s.LMTP = true
	s.Domain = "elemta-router"
	s.MaxMessageBytes = int64(r.cfg.Router.MaxMessageMB) << 20
	s.MaxLineLength = int(min(s.MaxMessageBytes, 1<<30))
	s.MaxRecipients = 100
	s.ReadTimeout = time.Minute
	s.WriteTimeout = time.Minute
	s.TLSConfig = r.tls
	s.EnableDSN = true
	s.EnableSMTPUTF8 = true
	return s
}

type lmtpRouterBackend struct{ r *Router }

func (b *lmtpRouterBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &lmtpRouterSession{r: b.r, conn: c, cells: map[string]*cellLMTP{}}, nil
}

type lmtpRouterSession struct {
	r    *Router
	conn *smtp.Conn
	from string
	opts *smtp.MailOptions
	// cells holds the open connection to each cell this session used.
	cells map[string]*cellLMTP
	// rcpts are the accepted recipients, in order, with their cells.
	rcpts []routedRcpt
}

type routedRcpt struct {
	to   string
	cell *cellLMTP
}

func (s *lmtpRouterSession) Mail(from string, opts *smtp.MailOptions) error {
	s.reset()
	s.from, s.opts = from, opts
	return nil
}

func (s *lmtpRouterSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	ctx, cancel := context.WithTimeout(s.r.ctx, 30*time.Second)
	defer cancel()
	cell, err := s.r.cellFor(ctx, to)
	if err != nil {
		s.r.log.Warn("router: finding a recipient's cell", "error", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 3}, Message: "Mailbox temporarily unavailable"}
	}
	c := s.cells[cell.Name]
	if c == nil || c.broken {
		if c != nil {
			c.close()
		}
		c, err = s.r.dialLMTP(ctx, cell)
		if err != nil {
			s.r.log.Warn("router: connecting to a cell's LMTP", "cell", cell.Name, "error", err)
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 1}, Message: "Mailbox temporarily unavailable"}
		}
		s.cells[cell.Name] = c
	}
	if !c.inMail {
		if err := c.mail(s.from, s.opts); err != nil {
			return err
		}
	}
	if err := c.rcpt(to, opts); err != nil {
		return err
	}
	s.rcpts = append(s.rcpts, routedRcpt{to: to, cell: c})
	return nil
}

// Data is SMTP's; an LMTP server is always given LMTPData.
func (s *lmtpRouterSession) Data(r io.Reader) error {
	return errors.New("LMTP needs per-recipient replies")
}

func (s *lmtpRouterSession) LMTPData(r io.Reader, status smtp.StatusCollector) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Each cell gets the message once, for its recipients, all at once.
	type result struct {
		cell    *cellLMTP
		replies []error
	}
	byCell := map[*cellLMTP][]string{}
	var order []*cellLMTP
	for _, rc := range s.rcpts {
		if _, seen := byCell[rc.cell]; !seen {
			order = append(order, rc.cell)
		}
		byCell[rc.cell] = append(byCell[rc.cell], rc.to)
	}
	results := make(chan result, len(order))
	for _, c := range order {
		go func(c *cellLMTP) {
			results <- result{cell: c, replies: c.data(body, len(byCell[c]))}
		}(c)
	}
	replies := map[*cellLMTP][]error{}
	for range order {
		res := <-results
		replies[res.cell] = res.replies
	}
	next := map[*cellLMTP]int{}
	for _, rc := range s.rcpts {
		i := next[rc.cell]
		next[rc.cell] = i + 1
		status.SetStatus(rc.to, replies[rc.cell][i])
	}
	s.rcpts = nil
	return nil
}

func (s *lmtpRouterSession) reset() {
	for _, c := range s.cells {
		if c.inMail {
			c.rset()
		}
	}
	s.rcpts, s.from, s.opts = nil, "", nil
}

func (s *lmtpRouterSession) Reset() { s.reset() }

func (s *lmtpRouterSession) Logout() error {
	for _, c := range s.cells {
		c.close()
	}
	s.cells = map[string]*cellLMTP{}
	return nil
}

// cellLMTP is the router's LMTP connection to one cell.
type cellLMTP struct {
	conn   net.Conn
	r      *bufio.Reader
	inMail bool
	broken bool
	// smtputf8 and dsn say what the cell offers.
	smtputf8, dsn bool
}

var tempUnavailable = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 2}, Message: "Mailbox temporarily unavailable"}

func (r *Router) dialLMTP(ctx context.Context, cell *routerCell) (*cellLMTP, error) {
	if cell.LMTP == "" {
		return nil, fmt.Errorf("cell %s has no LMTP address", cell.Name)
	}
	d := net.Dialer{Timeout: r.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", cell.LMTP)
	if err != nil {
		return nil, err
	}
	c := &cellLMTP{conn: conn, r: bufio.NewReader(conn)}
	fail := func(err error) (*cellLMTP, error) { _ = conn.Close(); return nil, err }
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if code, msg, err := c.reply(); err != nil || code != 220 {
		return fail(fmt.Errorf("greeting %d %s %v", code, msg, err))
	}
	exts, err := c.lhlo()
	if err != nil {
		return fail(err)
	}
	// TLS whenever the cell offers it; the cell decides whether it must.
	if exts["STARTTLS"] {
		if code, msg, err := c.cmd("STARTTLS"); err != nil || code != 220 {
			return fail(fmt.Errorf("STARTTLS %d %s %v", code, msg, err))
		}
		tc, err := r.startTLS(ctx, cell, conn)
		if err != nil {
			return nil, err
		}
		c.conn, c.r = tc, bufio.NewReader(tc)
		_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
		if exts, err = c.lhlo(); err != nil {
			return fail(err)
		}
	}
	c.smtputf8, c.dsn = exts["SMTPUTF8"], exts["DSN"]
	_ = c.conn.SetDeadline(time.Time{})
	return c, nil
}

// reply reads one reply, multi-line or not.
func (c *cellLMTP) reply() (int, string, error) {
	var msg []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return 0, "", fmt.Errorf("short reply %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", fmt.Errorf("bad reply %q", line)
		}
		msg = append(msg, line[4:])
		if line[3] == ' ' {
			return code, strings.Join(msg, "\n"), nil
		}
	}
}

func (c *cellLMTP) cmd(line string) (int, string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(time.Minute))
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.broken = true
		return 0, "", err
	}
	code, msg, err := c.reply()
	if err != nil {
		c.broken = true
	}
	return code, msg, err
}

func (c *cellLMTP) lhlo() (map[string]bool, error) {
	if _, err := io.WriteString(c.conn, "LHLO elemta-router\r\n"); err != nil {
		return nil, err
	}
	code, msg, err := c.reply()
	if err != nil || code != 250 {
		return nil, fmt.Errorf("LHLO %d %s %v", code, msg, err)
	}
	exts := map[string]bool{}
	for _, line := range strings.Split(msg, "\n")[1:] {
		exts[strings.ToUpper(strings.Fields(line + " ")[0])] = true
	}
	return exts, nil
}

// asError turns a cell's reply into what the MTA should see: nil for
// success, the cell's own code and text otherwise.
func asError(code int, msg string, err error) error {
	if err != nil {
		return tempUnavailable
	}
	if code >= 200 && code < 300 {
		return nil
	}
	e := &smtp.SMTPError{Code: code, EnhancedCode: smtp.NoEnhancedCode, Message: msg}
	if parts := strings.SplitN(msg, " ", 2); len(parts) == 2 {
		var ec smtp.EnhancedCode
		if n, _ := fmt.Sscanf(parts[0], "%d.%d.%d", &ec[0], &ec[1], &ec[2]); n == 3 {
			e.EnhancedCode, e.Message = ec, parts[1]
		}
	}
	return e
}

func (c *cellLMTP) mail(from string, o *smtp.MailOptions) error {
	line := "MAIL FROM:<" + from + ">"
	if o != nil {
		if o.Body != "" {
			line += " BODY=" + string(o.Body)
		}
		if o.UTF8 && c.smtputf8 {
			line += " SMTPUTF8"
		}
		if c.dsn {
			if o.Return != "" {
				line += " RET=" + string(o.Return)
			}
			if o.EnvelopeID != "" {
				line += " ENVID=" + xtext(o.EnvelopeID)
			}
		}
	}
	err := asError(c.cmd(line))
	if err == nil {
		c.inMail = true
	}
	return err
}

func (c *cellLMTP) rcpt(to string, o *smtp.RcptOptions) error {
	line := "RCPT TO:<" + to + ">"
	if o != nil && c.dsn {
		if len(o.Notify) > 0 {
			var n []string
			for _, v := range o.Notify {
				n = append(n, string(v))
			}
			line += " NOTIFY=" + strings.Join(n, ",")
		}
		if o.OriginalRecipient != "" {
			line += " ORCPT=" + string(o.OriginalRecipientType) + ";" + xtext(o.OriginalRecipient)
		}
	}
	return asError(c.cmd(line))
}

// data sends the message and returns one reply per recipient.
func (c *cellLMTP) data(body []byte, n int) []error {
	all := func(err error) []error {
		out := make([]error, n)
		for i := range out {
			out[i] = err
		}
		return out
	}
	defer func() { c.inMail = false }()
	if code, msg, err := c.cmd("DATA"); err != nil || code != 354 {
		if err == nil {
			c.rset()
		}
		return all(asError(code, msg, err))
	}
	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Minute))
	w := bufio.NewWriter(c.conn)
	if err := dotStuff(w, body); err != nil || w.Flush() != nil {
		c.broken = true
		return all(tempUnavailable)
	}
	out := make([]error, n)
	for i := range out {
		code, msg, err := c.reply()
		if err != nil {
			c.broken = true
			for j := i; j < n; j++ {
				out[j] = tempUnavailable
			}
			break
		}
		out[i] = asError(code, msg, nil)
	}
	return out
}

func (c *cellLMTP) rset() {
	_, _, _ = c.cmd("RSET")
	c.inMail = false
}

func (c *cellLMTP) close() {
	if !c.broken {
		_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c.conn, "QUIT\r\n")
	}
	_ = c.conn.Close()
}

// dotStuff writes body as DATA: lines starting with a dot get another,
// bare LFs become CRLF, and it ends with the lone dot.
func dotStuff(w *bufio.Writer, body []byte) error {
	for len(body) > 0 {
		line := body
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 && line[0] == '.' {
			if err := w.WriteByte('.'); err != nil {
				return err
			}
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	_, err := w.WriteString(".\r\n")
	return err
}

// xtext encodes a DSN parameter (RFC 3461).
func xtext(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < '!' || ch > '~' || ch == '+' || ch == '=' {
			fmt.Fprintf(&b, "+%02X", ch)
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}
