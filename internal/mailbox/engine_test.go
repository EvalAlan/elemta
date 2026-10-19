package mailbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	smtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"
)

func testEngine(t *testing.T) (*Engine, Account) {
	t.Helper()
	dsn := os.Getenv("ELEMTA_TEST_MAILBOX_DSN")
	if dsn == "" {
		t.Skip("set ELEMTA_TEST_MAILBOX_DSN to disposable Postgres")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	bodies, err := NewFileBodies(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bodies.Close() })
	cfg := Config{}.WithDefaults()
	e, err := NewEngine(context.Background(), db, bodies, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := Account{ID: uuid.NewString(), Address: uuid.NewString() + "@example.com"}
	if err := e.EnsureAccount(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM mailbox_deliveries WHERE account=$1`, a.ID)
		_, _ = db.Exec(`DELETE FROM mailbox_folders WHERE account=$1`, a.ID)
		_, _ = db.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, a.ID)
	})
	return e, a
}
func TestFileBodies(t *testing.T) {
	root := t.TempDir()
	b, err := NewFileBodies(root)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	key := strings.Repeat("a", 32)
	if err := b.Put(ctx, key, []byte("exact\x00bytes\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, key, []byte("overwrite")); err == nil {
		t.Fatal("immutable body overwritten")
	}
	raw, err := b.Get(ctx, key, 100)
	if err != nil || string(raw) != "exact\x00bytes\r\n" {
		t.Fatalf("body %q %v", raw, err)
	}
	if _, err := b.Get(ctx, key, 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
	if err := b.Put(ctx, "../escape", nil); err == nil {
		t.Fatal("path traversal accepted")
	}
	// An attacker-controlled link inside the root must not escape it.
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := strings.Repeat("b", 32)
	if err := os.Symlink(outside, filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, link, 100); err == nil {
		t.Fatal("symlink escaped body root")
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestS3Mailbox(t *testing.T) {
	endpoint := os.Getenv("ELEMTA_TEST_MAILBOX_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set ELEMTA_TEST_MAILBOX_S3_ENDPOINT for S3 contract tests")
	}
	e, a := testEngine(t)
	ctx := context.Background()
	b, err := NewS3Bodies(BodyConfig{Endpoint: endpoint, Bucket: "mailbox-dev", Region: "us-east-1", AccessKeyEnv: "MAILBOX_S3_ACCESS_KEY", SecretKeyEnv: "MAILBOX_S3_SECRET_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Check(ctx); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(ctx, e.DB, b, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: S3 contract\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xffbytes\r\n")
	res, err := engine.Append(ctx, a.ID, "INBOX", raw, nil, time.Time{}, "s3-retry")
	if err != nil {
		t.Fatal(err)
	}
	_, messages, err := engine.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(messages) != 1 {
		t.Fatalf("S3 append %v %v", messages, err)
	}
	defer func() { _ = b.Delete(ctx, messages[0].Body) }()
	data, err := engine.Read(ctx, messages[0])
	if err != nil || !bytes.Equal(data, raw) {
		t.Fatalf("S3 exact bytes: %q %v", data, err)
	}
	if err := b.Put(ctx, messages[0].Body, []byte("overwrite")); err == nil {
		t.Fatal("S3 immutable body overwritten")
	}
	again, err := engine.Append(ctx, a.ID, "INBOX", raw, nil, time.Time{}, "s3-retry")
	if err != nil || again != res {
		t.Fatalf("S3 retry: %v %v", again, err)
	}
	if _, err := NewEngine(ctx, e.DB, e.Bodies, Config{}.WithDefaults()); err == nil {
		t.Fatal("switching to a store without the existing bodies succeeded")
	}
	restarted, err := NewEngine(ctx, e.DB, b, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Read(ctx, messages[0]); err != nil {
		t.Fatal(err)
	}
}
func TestEngineConcurrentAndDurable(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	folder, err := e.Folder(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	// Separate pools and engine objects model independent service processes.
	db, err := sql.Open("postgres", os.Getenv("ELEMTA_TEST_MAILBOX_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	other, err := NewEngine(ctx, db, e.Bodies, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := e
			if i%2 != 0 {
				target = other
			}
			_, err := target.Append(ctx, a.ID, "INBOX", []byte(fmt.Sprintf("Subject: message %d\r\n\r\nbody\r\n", i)), nil, time.Time{}, "")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, msgs, err := other.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(msgs) != 32 || f.Validity != folder.Validity || f.Next != 33 {
		t.Fatalf("snapshot: %+v messages=%d err=%v", f, len(msgs), err)
	}
	for i, m := range msgs {
		if m.UID != uint32(i+1) {
			t.Fatalf("UID collision/gap: %d", m.UID)
		}
		if _, err := e.Read(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	result, err := e.Append(ctx, a.ID, "INBOX", []byte("retry"), nil, time.Time{}, "delivery-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := other.Append(ctx, a.ID, "INBOX", []byte("retry"), nil, time.Time{}, "delivery-1")
	if err != nil || result != again {
		t.Fatalf("retry result: %v %v", again, err)
	}
	if _, err := other.Append(ctx, a.ID, "INBOX", []byte("different"), nil, time.Time{}, "delivery-1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry conflict: %v", err)
	}
	if err := e.Create(ctx, a.ID, "Archive"); err != nil {
		t.Fatal(err)
	}
	_, from, to, err := other.CopyMove(ctx, a.ID, "INBOX", "Archive", []uint32{result.UID}, true)
	if err != nil || len(from) != 1 || len(to) != 1 {
		t.Fatalf("move: %v %v %v", from, to, err)
	}
	if err := e.MutateFlags(ctx, a.ID, "Archive", to, []string{"\\Deleted"}, 1); err != nil {
		t.Fatal(err)
	}
	removed, err := other.Expunge(ctx, a.ID, "Archive", to)
	if err != nil || len(removed) != 1 {
		t.Fatalf("expunge: %v %v", removed, err)
	}
	again, err = e.Append(ctx, a.ID, "INBOX", []byte("retry"), nil, time.Time{}, "delivery-1")
	if err != nil || again != result {
		t.Fatal("retry resurrected moved/deleted delivery")
	}
	if err := e.DeleteFolder(ctx, a.ID, "Archive"); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(ctx, a.ID, "Archive"); err != nil {
		t.Fatal(err)
	}
	fresh, err := e.Folder(ctx, a.ID, "Archive")
	if err != nil || fresh.Validity == folder.Validity {
		t.Fatal("UIDVALIDITY reused")
	}
	used, _, err := e.Quota(ctx, a.ID)
	if err != nil || used <= 0 {
		t.Fatalf("quota accounting %d %v", used, err)
	}
	// A separately reinitialized engine sees committed state and UID counters.
	restarted, err := NewEngine(ctx, db, e.Bodies, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	f, msgs, err = restarted.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(msgs) != 32 || f.Next != 34 {
		t.Fatalf("restart lost state: %+v %d %v", f, len(msgs), err)
	}
}
func TestEngineQuotaIsolationAndGC(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	a.Quota = 5
	if err := e.EnsureAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	res, err := e.Append(ctx, a.ID, "INBOX", []byte("12345"), nil, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("6"), nil, time.Time{}, ""); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
	var staged, reserved int64
	if err := e.DB.QueryRow(`SELECT count(*) FROM mailbox_bodies WHERE state='staging'`).Scan(&staged); err != nil || staged != 0 {
		t.Fatalf("rejected quota write left %d staged bodies: %v", staged, err)
	}
	if err := e.DB.QueryRow(`SELECT reserved_bytes FROM mailbox_accounts WHERE id=$1`, a.ID).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatalf("rejected quota write left %d reserved bytes: %v", reserved, err)
	}
	if _, _, err := e.Snapshot(ctx, uuid.NewString(), "INBOX"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-account mailbox accessible")
	}
	if err := e.Create(ctx, a.ID, "Dest"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Dest", []uint32{res.UID}, false); !errors.Is(err, ErrQuota) {
		t.Fatalf("copy bypassed quota: %v", err)
	}
	_, msgs, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	body := msgs[0].Body
	if _, err := e.DB.Exec(`UPDATE mailbox_bodies SET expires=now()-interval '3 days' WHERE key=$1`, body); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GC(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Read(ctx, msgs[0]); err != nil {
		t.Fatal("GC deleted referenced body")
	}
	if err := e.MutateFlags(ctx, a.ID, "INBOX", []uint32{res.UID}, []string{"\\deleted"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{res.UID}); err != nil {
		t.Fatal(err)
	}
	used, _, err := e.Quota(ctx, a.ID)
	if err != nil || used != 0 {
		t.Fatalf("quota not reclaimed %d %v", used, err)
	}
	// An old upload deleted just now must survive: the grace runs from when
	// the body lost its last message, so yesterday's backup stays
	// restorable.
	if _, err := e.DB.Exec(`UPDATE mailbox_bodies SET expires=now()-interval '3 years' WHERE key=$1`, body); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GC(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Bodies.Get(ctx, body, 100); err != nil {
		t.Fatal("GC deleted a body as soon as its message was deleted")
	}
	if _, err := e.DB.Exec(`UPDATE mailbox_bodies SET orphaned_at=now()-interval '8 days' WHERE key=$1`, body); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GC(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Bodies.Get(ctx, body, 100); err == nil {
		t.Fatal("GC retained an unreferenced body past its grace")
	}
}

type testAuth struct{ account Account }

func (a testAuth) Login(_ context.Context, u, p string) (Account, error) {
	if u != a.account.Address || p != "testpass" {
		return Account{}, ErrCredentials
	}
	return a.account, nil
}
func (a testAuth) Resolve(_ context.Context, u string) (Account, error) {
	if u != a.account.Address {
		return Account{}, ErrCredentials
	}
	return a.account, nil
}
func startTestService(t *testing.T, e *Engine, a Account, override ...Config) (*Service, string, string) {
	t.Helper()
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	if len(override) > 0 {
		cfg = override[0].WithDefaults()
	}
	service, err := newService(cfg, e, testAuth{a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	imapLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lmtpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = service.imap.Serve(imapLn) }()
	go func() { defer wg.Done(); _ = service.lmtp.Serve(lmtpLn) }()
	t.Cleanup(func() { service.cancel(); _ = service.imap.Close(); _ = service.lmtp.Close(); wg.Wait() })
	return service, imapLn.Addr().String(), lmtpLn.Addr().String()
}
func TestProtocolReplicas(t *testing.T) {
	e, a := testEngine(t)
	_, first, lmtpAddr := startTestService(t, e, a)
	_, second, _ := startTestService(t, e, a)
	updates := make(chan uint32, 32)
	dial := func(addr string) *imapclient.Client {
		t.Helper()
		c, err := imapclient.DialInsecure(addr, &imapclient.Options{UnilateralDataHandler: &imapclient.UnilateralDataHandler{Mailbox: func(data *imapclient.UnilateralDataMailbox) {
			if data.NumMessages != nil {
				select {
				case updates <- *data.NumMessages:
				default:
				}
			}
		}}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := c.Login(a.Address, "testpass").Wait(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(first), dial(second)
	selected, err := c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	validity := selected.UIDValidity
	raw := []byte("From: sender@example.com\r\nTo: " + a.Address + "\r\nSubject: hello replicas\r\nMessage-ID: <replica-test@example.com>\r\n\r\nexact body\r\n")
	appendCmd := c2.Append("INBOX", int64(len(raw)), nil)
	if _, err := appendCmd.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := appendCmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	messages, err := c1.Fetch(imap.UIDSetNum(res.UID), &imap.FetchOptions{Flags: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}}}).Collect()
	if err != nil || len(messages) != 1 {
		t.Fatalf("fetch %v %v", messages, err)
	}
	if !bytes.Equal(messages[0].FindBodySection(&imap.FetchItemBodySection{Peek: true}), raw) {
		t.Fatal("raw bytes changed")
	}
	search, err := c1.UIDSearch(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "hello"}}}, nil).Wait()
	if err != nil || len(search.AllUIDs()) != 1 {
		t.Fatalf("search %v %v", search, err)
	}
	if err := c2.Create("Trash", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Move(imap.UIDSetNum(res.UID), "Trash").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Select("Trash", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c2.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := c2.Expunge().Close(); err != nil {
		t.Fatal(err)
	}
	// LMTP retries with a stable ENVID must not append twice.
	for range 2 {
		conn, err := net.DialTimeout("tcp", lmtpAddr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cl := smtp.NewClientLMTP(conn)
		if err := cl.Mail("sender@example.com", &smtp.MailOptions{EnvelopeID: "queue-retry-1"}); err != nil {
			t.Fatal(err)
		}
		if err := cl.Rcpt(a.Address, nil); err != nil {
			t.Fatal(err)
		}
		w, err := cl.Data()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		_ = cl.Close()
	}
	fresh, err := c1.Select("INBOX", nil).Wait()
	if err != nil || fresh.NumMessages != 1 || fresh.UIDValidity != validity {
		t.Fatalf("LMTP/restart state: %+v %v", fresh, err)
	}
	// Verify IDLE observes a write through a different session/replica.
drain:
	for {
		select {
		case <-updates:
		default:
			break drain
		}
	}
	idle, err := c1.Idle()
	if err != nil {
		t.Fatal(err)
	}
	cmd := c2.Append("INBOX", int64(len(raw)), nil)
	_, _ = io.Copy(cmd, bytes.NewReader(raw))
	_ = cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	observed := false
	for !observed {
		select {
		case n := <-updates:
			observed = n == 2
		case <-deadline:
			t.Fatal("IDLE missed append through the other replica")
		}
	}
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c1.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolStartTLS(t *testing.T) {
	e, a := testEngine(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.WithDefaults()
	cfg.Server.TLSCert = certPath
	cfg.Server.TLSKey = keyPath
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	_, addr, lmtpAddr := startTestService(t, e, a, cfg)
	plain, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Login(a.Address, "testpass").Wait(); err == nil {
		t.Fatal("plaintext IMAP authentication accepted")
	}
	_ = plain.Close()
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}
	client, err := imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", lmtpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	delivery := smtp.NewClientLMTP(conn)
	defer delivery.Close()
	if err := delivery.Mail("sender@example.com", nil); err == nil {
		t.Fatal("plaintext LMTP accepted in secure mode")
	}

	_ = delivery.Close()
	wire, err := net.DialTimeout("tcp", lmtpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	_ = wire.SetDeadline(time.Now().Add(5 * time.Second))
	protocol := textproto.NewConn(wire)
	if _, _, err := protocol.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Cmd("LHLO test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := protocol.ReadResponse(250); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Cmd("STARTTLS"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := protocol.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(wire, tlsConfig)
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	protocol = textproto.NewConn(secured)
	if _, err := protocol.Cmd("LHLO test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := protocol.ReadResponse(250); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Cmd("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := protocol.ReadResponse(250); err != nil {
		t.Fatal(err)
	}

}
