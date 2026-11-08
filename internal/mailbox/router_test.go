package mailbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// mapPlacer places addresses by a map; anything else is in the default
// cell. "@domain" asks for a domain.
type mapPlacer map[string]string

func (m mapPlacer) CellOf(_ context.Context, address string) (string, error) {
	address = strings.ToLower(address)
	if cell, ok := m[address]; ok {
		return cell, nil
	}
	_, domain, _ := strings.Cut(address, "@")
	return m["@"+domain], nil
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// testCell is one cell: a mailbox service on its own database, with every
// listener the router uses, taking PROXY headers from 127.0.0.1.
type testCell struct {
	name    string
	engine  *Engine
	service *Service
	account Account
	cfg     CellConfig
}

func newTestCell(t *testing.T, name, address, certFile, keyFile string) *testCell {
	t.Helper()
	base := os.Getenv("ELEMTA_TEST_MAILBOX_DSN")
	if base == "" {
		t.Skip("set ELEMTA_TEST_MAILBOX_DSN to disposable Postgres")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	db := "cell_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE DATABASE ` + pq.QuoteIdentifier(db)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE ` + pq.QuoteIdentifier(db) + ` WITH (FORCE)`) })
	dsn, _ := withDatabase(base, db)
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	bodies, err := NewFileBodies(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.WithDefaults()
	e, err := NewEngine(context.Background(), conn, bodies, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := Account{ID: uuid.NewString(), Address: address}
	if err := e.EnsureAccount(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	cfg.Server.IMAPListen = freePort(t)
	cfg.Server.IMAPSListen = freePort(t)
	cfg.Server.POP3Listen = freePort(t)
	cfg.Server.LMTPListen = freePort(t)
	cfg.Server.HTTPListen = freePort(t)
	cfg.Sieve.Listen = freePort(t)
	cfg.Server.TLSCert, cfg.Server.TLSKey = certFile, keyFile
	cfg.Server.ProxyProtocolFrom = []string{"127.0.0.1"}
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Admin.TokenEnv = "TEST_ROUTER_ADMIN_TOKEN"
	s, err := newService(cfg, e, mapAuth{address: a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		s.cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	waitFor(t, "cell "+name+" to listen", func() bool {
		select {
		case err := <-done:
			t.Fatalf("cell %s stopped: %v", name, err)
		default:
		}
		c, err := net.Dial("tcp", cfg.Server.HTTPListen)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	})
	return &testCell{name: name, engine: e, service: s, account: a, cfg: CellConfig{
		Name: name, IMAPS: cfg.Server.IMAPSListen, POP3: cfg.Server.POP3Listen, Sieve: cfg.Sieve.Listen,
		LMTP: cfg.Server.LMTPListen, HTTP: "http://" + cfg.Server.HTTPListen, TLSCAFile: certFile,
	}}
}

type routerRig struct {
	cellA, cellB *testCell
	router       *Router
	cfg          RouterConfig
	certFile     string
}

func newRouterRig(t *testing.T) *routerRig {
	t.Helper()
	t.Setenv("TEST_ROUTER_ADMIN_TOKEN", "admin-token")
	certFile, keyFile := writeCert(t, t.TempDir(), "cells")
	a := newTestCell(t, "a", "alice@a.example", certFile, keyFile)
	b := newTestCell(t, "b", "bob@b.example", certFile, keyFile)
	cfg := RouterConfig{
		Router: RouterServerConfig{
			IMAPListen: freePort(t), IMAPSListen: freePort(t), POP3Listen: freePort(t), SieveListen: freePort(t),
			LMTPListen: freePort(t), HTTPListen: freePort(t), TLSCert: certFile, TLSKey: keyFile,
			InternalNetworks: []string{"127.0.0.0/8"}, DefaultCell: "a",
		},
		Auth:  AuthConfig{LDAPURL: "ldap://unused", LDAPBase: "dc=unused"},
		Cells: []CellConfig{a.cfg, b.cfg},
	}.WithDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := newRouter(cfg, mapPlacer{"@b.example": "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	waitFor(t, "the router to listen", func() bool {
		c, err := net.Dial("tcp", cfg.Router.HTTPListen)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	})
	return &routerRig{cellA: a, cellB: b, router: r, cfg: cfg, certFile: certFile}
}

func (rig *routerRig) tlsConfig(t *testing.T) *tls.Config {
	pem, err := os.ReadFile(rig.certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func countMessages(t *testing.T, e *Engine, account string) int {
	t.Helper()
	var n int
	if err := e.DB.QueryRow(`SELECT count(*) FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1`, account).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Each user signs in through the router and reaches only their own cell;
// new mail reaches an idling session through it; a wrong password is
// refused without losing the connection.
func TestRouterIMAP(t *testing.T) {
	rig := newRouterRig(t)
	raw := []byte("From: x@example.com\r\nSubject: routed\r\n\r\nhello\r\n")
	for _, c := range []*testCell{rig.cellA, rig.cellB} {
		updates := make(chan uint32, 8)
		client, err := imapclient.DialTLS(rig.cfg.Router.IMAPSListen, &imapclient.Options{TLSConfig: rig.tlsConfig(t),
			UnilateralDataHandler: &imapclient.UnilateralDataHandler{Mailbox: func(d *imapclient.UnilateralDataMailbox) {
				if d.NumMessages != nil {
					updates <- *d.NumMessages
				}
			}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Login(c.account.Address, "wrong").Wait(); err == nil {
			t.Fatal("a wrong password was accepted")
		}
		if err := client.Login(c.account.Address, "testpass").Wait(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		cmd := client.Append("INBOX", int64(len(raw)), nil)
		_, _ = cmd.Write(raw)
		_ = cmd.Close()
		if _, err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Select("INBOX", nil).Wait(); err != nil {
			t.Fatal(err)
		}
		idle, err := client.Idle()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.engine.Append(context.Background(), c.account.ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-updates:
			if n != 2 {
				t.Errorf("%s: EXISTS %d", c.name, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: IDLE through the router missed new mail", c.name)
		}
		_ = idle.Close()
		_ = idle.Wait()
		_ = client.Logout().Wait()
		_ = client.Close()
	}
	if n := countMessages(t, rig.cellA.engine, rig.cellA.account.ID); n != 2 {
		t.Errorf("cell a holds %d messages, want 2", n)
	}
	if n := countMessages(t, rig.cellB.engine, rig.cellB.account.ID); n != 2 {
		t.Errorf("cell b holds %d messages, want 2", n)
	}

	// The internal listener: plaintext from an internal network, as the
	// webmail signs in, with AUTHENTICATE PLAIN this time.
	client, err := imapclient.DialInsecure(rig.cfg.Router.IMAPListen, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if !client.Caps().Has(imap.AuthCap("PLAIN")) {
		t.Fatal("the internal listener doesn't offer PLAIN to an internal client")
	}
	if err := client.Authenticate(plainClient{"bob@b.example", "testpass"}); err != nil {
		t.Fatal(err)
	}
	st, err := client.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil || *st.NumMessages != 2 {
		t.Fatalf("status through the internal listener: %+v %v", st, err)
	}
}

// plainClient is SASL PLAIN for imapclient.Authenticate.
type plainClient struct{ user, password string }

func (p plainClient) Start() (string, []byte, error) {
	return "PLAIN", []byte("\x00" + p.user + "\x00" + p.password), nil
}
func (p plainClient) Next([]byte) ([]byte, error) { return nil, fmt.Errorf("unexpected challenge") }

// One LMTP transaction with recipients in two cells and one nobody has:
// each is answered by its own cell, and each message lands in its cell.
func TestRouterLMTP(t *testing.T) {
	rig := newRouterRig(t)
	conn, err := net.Dial("tcp", rig.cfg.Router.LMTPListen)
	if err != nil {
		t.Fatal(err)
	}
	c := smtp.NewClientLMTP(conn)
	defer func() { _ = c.Close() }()
	if err := c.Hello("mta"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("sender@example.com", &smtp.MailOptions{EnvelopeID: "env-1"}); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"alice@a.example", "bob@b.example"} {
		if err := c.Rcpt(to, nil); err != nil {
			t.Fatalf("RCPT %s: %v", to, err)
		}
	}
	if err := c.Rcpt("nobody@b.example", nil); err == nil {
		t.Fatal("a recipient no cell has was accepted")
	} else if se, ok := err.(*smtp.SMTPError); !ok || se.Code/100 != 5 {
		t.Fatalf("unknown recipient: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "From: sender@example.com\r\nSubject: two cells\r\n\r\n.leading dot\r\nhi\r\n")
	replies, err := w.CloseWithLMTPResponse()
	if err != nil || len(replies) != 2 {
		t.Fatalf("per-recipient replies: %v %v", replies, err)
	}
	for _, cell := range []*testCell{rig.cellA, rig.cellB} {
		if n := countMessages(t, cell.engine, cell.account.ID); n != 1 {
			t.Errorf("cell %s holds %d messages, want 1", cell.name, n)
		}
	}
	// The dot-stuffed line arrived as it was sent.
	var key string
	if err := rig.cellB.engine.DB.QueryRow(`SELECT m.body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1`, rig.cellB.account.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	body, err := rig.cellB.engine.Bodies.Get(context.Background(), key, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("\r\n.leading dot\r\n")) {
		t.Errorf("body = %q", body)
	}
	// A second transaction on the same connection reuses the cells'.
	// (RSET first: go-smtp's client counts recipients until it.)
	if err := c.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("sender@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("bob@b.example", nil); err != nil {
		t.Fatal(err)
	}
	w, err = c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "Subject: again\r\n\r\nx\r\n")
	if _, err := w.CloseWithLMTPResponse(); err != nil {
		t.Fatal(err)
	}
	if n := countMessages(t, rig.cellB.engine, rig.cellB.account.ID); n != 2 {
		t.Errorf("cell b holds %d messages after the second delivery", n)
	}
}

// POP3 and ManageSieve sign in through the router at the right cell.
func TestRouterPOP3AndSieve(t *testing.T) {
	rig := newRouterRig(t)
	if _, err := rig.cellB.engine.Append(context.Background(), rig.cellB.account.ID, "INBOX", []byte("Subject: pop\r\n\r\nx\r\n"), nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", rig.cfg.Router.POP3Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(line string) string {
		t.Helper()
		if line != "" {
			if _, err := io.WriteString(conn, line+"\r\n"); err != nil {
				t.Fatal(err)
			}
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(reply)
	}
	say("")
	if reply := say("USER bob@b.example"); !strings.Contains(reply, "STLS") {
		t.Fatalf("USER before TLS: %q", reply)
	}
	if reply := say("STLS"); !strings.HasPrefix(reply, "+OK") {
		t.Fatal(reply)
	}
	tc := tls.Client(conn, rig.tlsConfig(t))
	conn, r = tc, bufio.NewReader(tc)
	say("USER bob@b.example")
	if reply := say("PASS testpass"); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("PASS: %q", reply)
	}
	if reply := say("STAT"); !strings.HasPrefix(reply, "+OK 1 ") {
		t.Fatalf("STAT through the router: %q", reply)
	}
	say("QUIT")

	// ManageSieve, as the webmail uses it: plaintext from inside.
	sc, err := net.Dial("tcp", rig.cfg.Router.SieveListen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.Close() }()
	sr := bufio.NewReader(sc)
	readTo := func(prefix string) []string {
		t.Helper()
		var lines []string
		for {
			line, err := sr.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			line = strings.TrimSpace(line)
			lines = append(lines, line)
			if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") {
				if !strings.HasPrefix(line, prefix) {
					t.Fatalf("ManageSieve: %q", lines)
				}
				return lines
			}
		}
	}
	readTo("OK")
	auth := base64.StdEncoding.EncodeToString([]byte("\x00alice@a.example\x00testpass"))
	_, _ = io.WriteString(sc, `AUTHENTICATE "PLAIN" "`+auth+`"`+"\r\n")
	readTo("OK")
	script := "keep;\r\n"
	_, _ = fmt.Fprintf(sc, "PUTSCRIPT \"routed\" {%d+}\r\n%s\r\n", len(script), script)
	readTo("OK")
	var n int
	if err := rig.cellA.engine.DB.QueryRow(`SELECT count(*) FROM mailbox_sieve_scripts WHERE account=$1`, rig.cellA.account.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the script isn't in cell a: %d %v", n, err)
	}
}

// The HTTP APIs: a user's requests go to their cell, a class of service
// is written to every cell, and lists come back from every cell.
func TestRouterHTTP(t *testing.T) {
	rig := newRouterRig(t)
	base := "http://" + rig.cfg.Router.HTTPListen
	do := func(method, path, body string, header map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if status, body := do(http.MethodPut, "/v1/admin/classes/staff", `{"name":"staff","description":"Staff"}`, nil); status != http.StatusOK {
		t.Fatalf("class: %d %s", status, body)
	}
	for _, c := range []*testCell{rig.cellA, rig.cellB} {
		if _, err := c.engine.Class(context.Background(), "staff"); err != nil {
			t.Errorf("cell %s lacks the class: %v", c.name, err)
		}
	}
	// A domain policy goes to the domain's cell only.
	if status, body := do(http.MethodPut, "/v1/admin/domains/b.example", `{"domain":"b.example","class":"staff"}`, nil); status != http.StatusOK {
		t.Fatalf("domain: %d %s", status, body)
	}
	status, body := do(http.MethodGet, "/v1/admin/domains", "", nil)
	var domains []map[string]any
	if status != http.StatusOK || json.Unmarshal([]byte(body), &domains) != nil || len(domains) != 1 || domains[0]["domain"] != "b.example" {
		t.Fatalf("domains from every cell: %d %s", status, body)
	}
	if ds, _ := rig.cellA.engine.Domains(context.Background()); len(ds) != 0 {
		t.Error("cell a got b.example's policy")
	}
	// The security API as the webmail calls it, signed in as the user.
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/security", nil)
	req.SetBasicAuth("bob@b.example", "testpass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("security API through the router: %d", resp.StatusCode)
	}
	// A cell named outright.
	if status, _ := do(http.MethodGet, "/v1/admin/classes", "", map[string]string{cellHeader: "nope"}); status != http.StatusBadRequest {
		t.Errorf("an unknown cell: %d", status)
	}
}

// The router's merging of cells' answers.
func TestMergeJSON(t *testing.T) {
	var merged any
	for cell, s := range map[string]string{"c1": `{"hits":[{"ref":"1"}],"total":1,"unindexed":0}`, "c9": `{"hits":[{"ref":"9"}],"total":2,"unindexed":1}`} {
		var v any
		_ = json.Unmarshal([]byte(s), &v)
		markRefs(v, cell)
		merged = mergeJSON(merged, v)
	}
	if h, _ := merged.(map[string]any)["hits"].([]any); len(h) == 2 && h[0].(map[string]any)["ref"] == "c9:9" {
		h[0], h[1] = h[1], h[0] // map order
	}
	out, _ := json.Marshal(merged)
	if string(out) != `{"hits":[{"ref":"c1:1"},{"ref":"c9:9"}],"total":3,"unindexed":1}` {
		t.Errorf("merged = %s", out)
	}
	var audit any
	_ = json.Unmarshal([]byte(`[{"at":"2026-01-01T00:00:00Z"},{"at":"2026-03-01T00:00:00Z"},{"at":"2026-02-01T00:00:00Z"}]`), &audit)
	got, _ := json.Marshal(newestFirst(audit, "2"))
	if string(got) != `[{"at":"2026-03-01T00:00:00Z"},{"at":"2026-02-01T00:00:00Z"}]` {
		t.Errorf("audit = %s", got)
	}
}

// STARTTLS injection: bytes pipelined after STARTTLS end the connection
// rather than being read as if they came over TLS.
func TestRouterSTARTTLSInjection(t *testing.T) {
	rig := newRouterRig(t)
	conn, err := net.Dial("tcp", rig.cfg.Router.POP3Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	_, _ = r.ReadString('\n')
	_, _ = io.WriteString(conn, "STLS\r\nUSER injected\r\n")
	reply, _ := r.ReadString('\n')
	if !strings.HasPrefix(reply, "+OK") {
		t.Fatal(reply)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.ReadByte(); err == nil {
		t.Error("the connection carried on after pipelined bytes")
	}
}

// The example configuration parses and passes the checks.
func TestRouterExampleConfig(t *testing.T) {
	c, err := LoadRouterConfig("../../config/mailbox-router.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Cells) != 2 || c.Router.DefaultCell != "a" || c.Auth.CacheSeconds != 30 {
		t.Errorf("config = %+v", c)
	}
}

// A cell serves only the mailboxes placed in it: with a stale placement
// (a move under way) a delivery is deferred and a sign-in refused, and no
// empty mailbox appears in the wrong cell.
func TestCellRefusesOtherCellsMailboxes(t *testing.T) {
	e, a := testEngine(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Cell = MailboxCellConfig{Name: "a"}
	service, imapAddr, lmtpAddr := startTestService(t, e, a, cfg)
	placement := mapPlacer{a.Address: "b"}
	service.cells = placement

	conn, err := net.Dial("tcp", lmtpAddr)
	if err != nil {
		t.Fatal(err)
	}
	c := smtp.NewClientLMTP(conn)
	defer func() { _ = c.Close() }()
	if err := c.Hello("mta"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("x@example.com", nil); err != nil {
		t.Fatal(err)
	}
	err = c.Rcpt(a.Address, nil)
	if se, ok := err.(*smtp.SMTPError); !ok || se.Code/100 != 4 {
		t.Fatalf("delivery to a mailbox placed elsewhere: %v", err)
	}
	client, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Login(a.Address, "testpass").Wait(); err == nil {
		t.Fatal("signed in to a mailbox placed in another cell")
	}
	// Placed here (or nowhere, in the default cell), it works.
	placement[a.Address] = "a"
	if err := client.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatalf("placed here: %v", err)
	}
	delete(placement, a.Address)
	service.cfg.Cell.Default = true
	if err := e.EnsureAccount(context.Background(), a); err != nil {
		t.Fatalf("unplaced, in the default cell: %v", err)
	}
	service.cfg.Cell.Default = false
	if err := e.EnsureAccount(context.Background(), a); !errors.Is(err, ErrOtherCell) {
		t.Fatalf("unplaced, in a cell that isn't the default: %v", err)
	}
}

// A shared mailbox is opened by signing in as "user|mailbox"; the session
// belongs in the mailbox's cell.
func TestRouterCellForSharedMailbox(t *testing.T) {
	r, err := newRouter(RouterConfig{Router: RouterServerConfig{DefaultCell: "a"}, Cells: []CellConfig{{Name: "a"}, {Name: "b"}}},
		mapPlacer{"@b.example": "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for user, want := range map[string]string{"x@b.example": "b", "x@a.example|team@b.example": "b", "x@b.example|team@a.example": "a", "y@elsewhere": "a"} {
		cell, err := r.cellFor(context.Background(), user)
		if err != nil || cell.Name != want {
			t.Errorf("cellFor(%s) = %v %v, want %s", user, cell, err, want)
		}
	}
}

// The webmail may also use STARTTLS on the internal listener, and a
// password that needs a literal.
func TestRouterIMAPStartTLS(t *testing.T) {
	rig := newRouterRig(t)
	client, err := imapclient.DialStartTLS(rig.cfg.Router.IMAPListen, &imapclient.Options{TLSConfig: rig.tlsConfig(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Login("alice@a.example", "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	// A shared-mailbox style user name with a quote and a backslash is
	// refused by the cell, not mangled by the router.
	c2, err := imapclient.DialInsecure(rig.cfg.Router.IMAPListen, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if err := c2.Login(`al"i\ce@a.example`, "pass\r\nword").Wait(); err == nil {
		t.Fatal("an odd user name signed in")
	}
	if err := c2.Login("alice@a.example", "testpass").Wait(); err != nil {
		t.Fatalf("after a refusal: %v", err)
	}
}
