package mailbox

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// routerIdle bounds each read before sign-in.
	routerIdle = 60 * time.Second
	// routerLine bounds a line before sign-in, literals included.
	routerLine = 16 << 10
	// routerTries is how many failed sign-ins a connection gets.
	routerTries = 3
)

var errLineTooLong = errors.New("line too long")

// lineConn is a text-protocol connection: the client's before sign-in, or
// the router's to a cell while it signs in.
type lineConn struct {
	net.Conn
	br *bufio.Reader
	// secure is a TLS connection.
	secure bool
}

func newLineConn(c net.Conn) *lineConn {
	_, secure := c.(*tls.Conn)
	return &lineConn{Conn: c, br: bufio.NewReaderSize(c, 4096), secure: secure}
}

// readLine reads one line, without its CRLF.
func (l *lineConn) readLine() (string, error) {
	_ = l.SetReadDeadline(time.Now().Add(routerIdle))
	var b strings.Builder
	for {
		chunk, err := l.br.ReadSlice('\n')
		b.Write(chunk)
		if b.Len() > routerLine {
			return "", errLineTooLong
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
	return strings.TrimRight(b.String(), "\r\n"), nil
}

// readN reads n bytes (an IMAP literal).
func (l *lineConn) readN(n int) (string, error) {
	if n < 0 || n > routerLine {
		return "", errLineTooLong
	}
	_ = l.SetReadDeadline(time.Now().Add(routerIdle))
	buf := make([]byte, n)
	if _, err := io.ReadFull(l.br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func (l *lineConn) writeLine(s string) error {
	_ = l.SetWriteDeadline(time.Now().Add(routerIdle))
	_, err := io.WriteString(l.Conn, s+"\r\n")
	return err
}

// upgradeServer starts TLS as the server, after the client asked. Bytes
// the client sent after its STARTTLS before the handshake would be read as
// if they came over TLS, which is the classic STARTTLS injection, so any
// such bytes end the connection.
func (l *lineConn) upgradeServer(cfg *tls.Config) error {
	if l.br.Buffered() > 0 {
		return errors.New("data sent before the TLS handshake")
	}
	t := tls.Server(l.Conn, cfg)
	_ = t.SetDeadline(time.Now().Add(routerIdle))
	if err := t.Handshake(); err != nil {
		return err
	}
	_ = t.SetDeadline(time.Time{})
	l.Conn, l.br, l.secure = t, bufio.NewReaderSize(t, 4096), true
	return nil
}

// relay copies between a signed-in client and its cell until either
// ends. Whatever either side had already sent and the router had read
// ahead goes first.
func relay(client, cell *lineConn) {
	_ = client.SetDeadline(time.Time{})
	_ = cell.SetDeadline(time.Time{})
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = client.Close(); _ = cell.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(cell.Conn, client.br); closeBoth() }()
	go func() { defer wg.Done(); _, _ = io.Copy(client.Conn, cell.br); closeBoth() }()
	wg.Wait()
}

// saslPlain decodes a SASL PLAIN response: authzid, authcid, password.
func saslPlain(b []byte) (authz, user, password string, ok bool) {
	parts := strings.Split(string(b), "\x00")
	if len(parts) != 3 || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
