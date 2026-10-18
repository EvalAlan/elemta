package mailbox

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

type popTestClient struct {
	t *testing.T
	c net.Conn
	r *textproto.Reader
	w *bufio.Writer
}

func (p *popTestClient) command(command string, ok bool) string {
	p.t.Helper()
	if _, err := fmt.Fprintf(p.w, "%s\r\n", command); err != nil {
		p.t.Fatal(err)
	}
	if err := p.w.Flush(); err != nil {
		p.t.Fatal(err)
	}
	line, err := p.r.ReadLine()
	if err != nil {
		p.t.Fatal(err)
	}
	prefix := "-ERR"
	if ok {
		prefix = "+OK"
	}
	if !strings.HasPrefix(line, prefix) {
		p.t.Fatalf("command %s: %s", strings.Fields(command)[0], line)
	}
	return line
}
func (p *popTestClient) multiline(command string) []byte {
	p.t.Helper()
	p.command(command, true)
	b, err := p.r.ReadDotBytes()
	if err != nil {
		p.t.Fatal(err)
	}
	return b
}
func popTestService(t *testing.T, e *Engine, a Account) (*Service, string, *tls.Config) {
	t.Helper()
	cert, key := writeCert(t, t.TempDir(), "mail.example.com")
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.TLSCert = cert
	cfg.Server.TLSKey = key
	s, err := newService(cfg, e, testAuth{a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.servePOP3(ln) }()
	t.Cleanup(func() {
		s.cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("POP3 shutdown stuck")
		}
	})
	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	return s, ln.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}
}
func dialPOPTest(t *testing.T, addr string) *popTestClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	p := &popTestClient{t: t, c: c, r: textproto.NewReader(bufio.NewReader(c)), w: bufio.NewWriter(c)}
	line, err := p.r.ReadLine()
	if err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting: %s %v", line, err)
	}
	return p
}
func (p *popTestClient) secure(config *tls.Config) {
	p.t.Helper()
	p.command("STLS", true)
	c := tls.Client(p.c, config)
	if err := c.Handshake(); err != nil {
		p.t.Fatal(err)
	}
	p.c = c
	p.r = textproto.NewReader(bufio.NewReader(c))
	p.w = bufio.NewWriter(c)
}
func (p *popTestClient) login(address string) {
	p.command("USER "+address, true)
	p.command("PASS testpass", true)
}
func TestPOP3TLSAndTransactions(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	raw := []byte("From: sender@example.net\r\nSubject: POP fixture\r\n\r\nfirst\r\n.dot line\r\nlast\r\n")
	if _, err := e.Append(ctx, a.ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	s, addr, tlsConfig := popTestService(t, e, a)
	_, otherAddr, otherTLS := popTestService(t, e, a)
	p := dialPOPTest(t, addr)
	p.command("USER "+a.Address, false)
	p.command("PASS testpass", false)
	capa := string(p.multiline("CAPA"))
	if !strings.Contains(capa, "STLS") || strings.Contains(capa, "USER") || !strings.Contains(capa, "AUTH-RESP-CODE") {
		t.Fatalf("cleartext capabilities: %s", capa)
	}
	p.secure(tlsConfig)
	p.command("PASS testpass", false)
	p.login(a.Address)
	if strings.Contains(string(p.multiline("CAPA")), "STLS") {
		t.Fatal("STLS offered inside TLS")
	}
	p.command("STLS", false)
	p.command("STAT", true)
	uid := string(p.multiline("UIDL"))
	p.command("UIDL 0", false)
	p.command("RETR 2", false)
	p.command("TOP 1 -1", false)
	expected := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if got := string(p.multiline("RETR 1")); got != expected {
		t.Fatalf("retrieval changed message: %q", got)
	}
	if got := string(p.multiline("TOP 1 0")); got != "From: sender@example.net\nSubject: POP fixture\n\n" {
		t.Fatalf("TOP headers: %q", got)
	}
	if got := string(p.multiline("TOP 1 2")); !strings.HasSuffix(got, "first\n.dot line\n") {
		t.Fatalf("TOP lines: %q", got)
	}
	other := dialPOPTest(t, otherAddr)
	other.secure(otherTLS)
	other.command("USER "+a.Address, true)
	// Valid credentials but a held lease: IN-USE, not an auth failure, so
	// clients retry rather than prompting for a new password.
	if line := other.command("PASS testpass", false); !strings.Contains(line, "[IN-USE]") {
		t.Fatalf("locked maildrop reply: %s", line)
	}
	if _, err := other.r.ReadLine(); err == nil {
		t.Fatal("connection stayed open after IN-USE")
	}
	p.command("DELE 1", true)
	p.command("DELE 1", false)
	p.command("RETR 1", false)
	p.command("RSET", true)
	if got := string(p.multiline("UIDL")); got != uid {
		t.Fatal("RSET changed UIDL")
	}
	// Concurrent delivery stays outside the numbering of this session.
	if _, err := e.Append(ctx, a.ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	p.command("RETR 2", false)
	p.command("DELE 1", true)
	_ = p.c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		if err := e.DB.QueryRow(`SELECT count(*) FROM mailbox_pop3_leases WHERE account=$1`, a.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease not released after disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	q := dialPOPTest(t, otherAddr)
	q.secure(otherTLS)
	q.login(a.Address)
	if got := string(q.multiline("UIDL")); !strings.HasPrefix(got, uid) {
		t.Fatalf("UIDL changed after reconnect: %q", got)
	}
	q.command("DELE 1", true)
	q.command("QUIT", true)
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(messages) != 1 {
		t.Fatalf("QUIT delete: %d %v", len(messages), err)
	}
	used, _, err := e.Quota(ctx, a.ID)
	if err != nil || used != int64(len(raw)) {
		t.Fatalf("quota after delete: %d %v", used, err)
	}
	// The public IMAP server must ignore the development plaintext setting.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.imapStartTLS.Serve(ln) }()
	defer func() { _ = s.imapStartTLS.Close(); _ = ln.Close(); <-done }()
	im, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := im.Login(a.Address, "testpass").Wait(); err == nil {
		t.Fatal("public IMAP accepted cleartext login")
	}
	_ = im.Close()
	im, err = imapclient.DialStartTLS(ln.Addr().String(), &imapclient.Options{TLSConfig: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if err := im.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
}
func TestPOP3ExpiredLeaseCannotDelete(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("Subject: test\r\n\r\nkeep\r\n"), nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	_, addr, config := popTestService(t, e, a)
	p := dialPOPTest(t, addr)
	p.secure(config)
	p.login(a.Address)
	p.command("DELE 1", true)
	if _, err := e.DB.Exec(`UPDATE mailbox_pop3_leases SET expires=now()-interval '1 second' WHERE account=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	p.command("QUIT", false)
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(messages) != 1 {
		t.Fatal("expired session deleted mail")
	}
}
