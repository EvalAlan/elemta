package mailbox

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/webmail"
	"github.com/emersion/go-smtp"
)

// fakeSubmission records mail the service sends.
type fakeSubmission struct {
	mu   sync.Mutex
	sent []sentMail
}

type sentMail struct {
	from string
	to   []string
	data []byte
}

type fakeSubmitSession struct {
	f    *fakeSubmission
	from string
	to   []string
}

func (s *fakeSubmitSession) Mail(from string, _ *smtp.MailOptions) error { s.from = from; return nil }
func (s *fakeSubmitSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}
func (s *fakeSubmitSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.f.mu.Lock()
	s.f.sent = append(s.f.sent, sentMail{from: s.from, to: s.to, data: b})
	s.f.mu.Unlock()
	return nil
}
func (s *fakeSubmitSession) Reset()        { s.from, s.to = "", nil }
func (s *fakeSubmitSession) Logout() error { return nil }

func (f *fakeSubmission) messages() []sentMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMail(nil), f.sent...)
}

func startFakeSubmission(t *testing.T) (*fakeSubmission, string) {
	t.Helper()
	f := &fakeSubmission{}
	srv := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) { return &fakeSubmitSession{f: f}, nil }))
	srv.Domain = "submit.test"
	srv.AllowInsecureAuth = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f, ln.Addr().String()
}

type sieveRig struct {
	t      *testing.T
	e      *Engine
	a      Account
	lmtp   string
	sieve  string
	submit *fakeSubmission
}

func newSieveRig(t *testing.T) *sieveRig {
	t.Helper()
	e, a := testEngine(t)
	submit, submitAddr := startFakeSubmission(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Sieve.SubmitAddr = submitAddr
	service, _, lmtpAddr := startTestService(t, e, a, cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = service.serveManageSieve(ln, nil) }()
	t.Cleanup(func() { _ = ln.Close() })
	return &sieveRig{t: t, e: e, a: a, lmtp: lmtpAddr, sieve: ln.Addr().String(), submit: submit}
}

// install uploads and activates a script with the webmail's own client.
func (r *sieveRig) install(script string) error {
	r.t.Helper()
	conn, err := webmail.ManageSieveDialer(r.sieve, "none", false)(context.Background(), r.a.Address, "testpass")
	if err != nil {
		r.t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Put("webmail", script); err != nil {
		return err
	}
	if err := conn.SetActive("webmail"); err != nil {
		r.t.Fatal(err)
	}
	got, err := conn.Get("webmail")
	if err != nil || got != script {
		r.t.Fatalf("GETSCRIPT = %q, %v", got, err)
	}
	list, err := conn.List()
	if err != nil || len(list) != 1 || !list[0].Active {
		r.t.Fatalf("LISTSCRIPTS = %+v, %v", list, err)
	}
	return nil
}

// deliver sends one message over LMTP and returns the recipient's status.
func (r *sieveRig) deliver(from, envid, raw string) *smtp.SMTPError {
	r.t.Helper()
	conn, err := net.DialTimeout("tcp", r.lmtp, time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	cl := smtp.NewClientLMTP(conn)
	defer func() { _ = cl.Close() }()
	if err := cl.Mail(from, &smtp.MailOptions{EnvelopeID: envid}); err != nil {
		r.t.Fatal(err)
	}
	if err := cl.Rcpt(r.a.Address, nil); err != nil {
		r.t.Fatal(err)
	}
	w, err := cl.Data()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := w.Write([]byte(raw)); err != nil {
		r.t.Fatal(err)
	}
	_, err = w.CloseWithLMTPResponse()
	if lmtpErr, ok := err.(smtp.LMTPDataError); ok {
		return lmtpErr[r.a.Address]
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return nil
}

func (r *sieveRig) count(folder string) int {
	r.t.Helper()
	_, msgs, err := r.e.Snapshot(context.Background(), r.a.ID, folder)
	if err != nil {
		return 0
	}
	return len(msgs)
}

func (r *sieveRig) msg(subject string) string {
	return "From: Bo <bo@example.com>\r\nTo: " + r.a.Address + "\r\nSubject: " + subject + "\r\nMessage-ID: <" + strings.NewReplacer(" ", "-", "#", "").Replace(subject) + "@example.com>\r\n\r\nHello\r\n"
}

func TestSieveWebmailFiltersAndVacation(t *testing.T) {
	r := newSieveRig(t)
	script := `require ["vacation", "regex", "fileinto", "mailbox", "imap4flags"];
if not anyof (exists "list-id", header :contains "precedence" ["bulk", "list", "junk"], exists "auto-submitted") {
  vacation :days 2 :subject "Away" "I'm out until Monday.";
}
if header :regex "subject" "^Invoice #[0-9]+$" {
  addflag "\\Flagged";
  fileinto :create "Finance";
}
`
	if err := r.install(script); err != nil {
		t.Fatal(err)
	}
	if st := r.deliver("bo@example.com", "q1", r.msg("Invoice #7")); st != nil {
		t.Fatalf("delivery = %v", st)
	}
	if r.count("Finance") != 1 || r.count("INBOX") != 0 {
		t.Fatalf("Finance=%d INBOX=%d", r.count("Finance"), r.count("INBOX"))
	}
	_, msgs, _ := r.e.Snapshot(context.Background(), r.a.ID, "Finance")
	if !hasFlag(msgs[0].Flags, "\\flagged") {
		t.Errorf("flags = %v", msgs[0].Flags)
	}
	sent := r.submit.messages()
	if len(sent) != 1 || sent[0].from != "" || sent[0].to[0] != "bo@example.com" {
		t.Fatalf("vacation = %+v", sent)
	}
	reply := string(sent[0].data)
	for _, want := range []string{"Subject: Away", "Auto-Submitted: auto-replied", "In-Reply-To: <Invoice-7@example.com>", "I'm out until Monday."} {
		if !strings.Contains(reply, want) {
			t.Errorf("reply lacks %q:\n%s", want, reply)
		}
	}
	// One reply per sender per period, and none to lists or bounces.
	r.deliver("bo@example.com", "q2", r.msg("Second"))
	r.deliver("list@example.com", "q3", "From: list@example.com\r\nTo: "+r.a.Address+"\r\nList-Id: <l.example.com>\r\nSubject: news\r\n\r\nx\r\n")
	r.deliver("", "q4", r.msg("Bounce"))
	r.deliver("cy@example.com", "q5", "From: cy@example.com\r\nTo: someone-else@example.com\r\nSubject: bcc\r\n\r\nx\r\n")
	if n := len(r.submit.messages()); n != 1 {
		t.Errorf("%d automatic replies, want 1", n)
	}
	if r.count("INBOX") != 4 {
		t.Errorf("INBOX = %d, want 4", r.count("INBOX"))
	}
}

func TestSieveRetryDoesntDuplicate(t *testing.T) {
	r := newSieveRig(t)
	if err := r.install(`require ["fileinto", "copy"]; fileinto :copy "INBOX"; redirect "elsewhere@example.net";`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if st := r.deliver("bo@example.com", "same-queue-id", r.msg("Forward me")); st != nil {
			t.Fatalf("delivery %d = %v", i, st)
		}
	}
	if r.count("INBOX") != 1 {
		t.Errorf("INBOX = %d after a retry, want 1", r.count("INBOX"))
	}
	sent := r.submit.messages()
	if len(sent) != 1 || sent[0].to[0] != "elsewhere@example.net" || sent[0].from != "bo@example.com" {
		t.Fatalf("redirects = %+v", sent)
	}
	if !bytes.HasPrefix(sent[0].data, []byte(redirectHeader+": "+r.a.Address)) {
		t.Errorf("redirect lacks the loop marker:\n%s", sent[0].data)
	}
	// A message this account already redirected isn't redirected again.
	r.deliver("bo@example.com", "loop", string(sent[0].data))
	if len(r.submit.messages()) != 1 {
		t.Error("redirect loop not stopped")
	}
}

func TestSieveRejectAndBrokenScripts(t *testing.T) {
	r := newSieveRig(t)
	if err := r.install(`require "reject"; if header :contains "subject" "spam" { reject "No thanks"; }`); err != nil {
		t.Fatal(err)
	}
	st := r.deliver("bo@example.com", "r1", r.msg("buy spam"))
	if st == nil || st.Code != 550 || !strings.Contains(st.Message, "No thanks") {
		t.Fatalf("reject = %v", st)
	}
	if r.count("INBOX") != 0 {
		t.Error("rejected mail was stored")
	}
	// ManageSieve refuses a script that doesn't compile.
	if err := r.install(`if header :bogus "x" { keep; }`); err == nil || !strings.Contains(err.Error(), "rejected") && !strings.Contains(err.Error(), "error") {
		t.Fatalf("broken script accepted: %v", err)
	}
	// A broken script that got in some other way keeps mail rather than
	// losing it.
	if _, err := r.e.DB.Exec(`UPDATE mailbox_sieve_scripts SET script='if bogus {',updated=now() WHERE account=$1`, r.a.ID); err != nil {
		t.Fatal(err)
	}
	if st := r.deliver("bo@example.com", "r2", r.msg("hello")); st != nil {
		t.Fatalf("delivery with broken script = %v", st)
	}
	if r.count("INBOX") != 1 {
		t.Errorf("INBOX = %d, want 1", r.count("INBOX"))
	}
}

func TestManageSieveParsing(t *testing.T) {
	words, lit, err := parseSieveWords(`PUTSCRIPT "my \"script\"" {12+}`)
	if err != nil || lit != 12 || len(words) != 2 || words[1] != `my "script"` {
		t.Fatalf("parse = %q %d %v", words, lit, err)
	}
	if _, _, err := parseSieveWords(`GETSCRIPT "unterminated`); err == nil {
		t.Error("unterminated string accepted")
	}
	for name, ok := range map[string]bool{"webmail": true, "a/b": false, "": false, "tab\there": false, strings.Repeat("x", 200): false} {
		if validScriptName(name) != ok {
			t.Errorf("validScriptName(%q) != %v", name, ok)
		}
	}
}

// Lines longer than RFC 5321 allows are real-world mail the MTA already
// accepted; they must be delivered, not bounced.
func TestLMTPAcceptsLongLines(t *testing.T) {
	r := newSieveRig(t)
	long := "From: a@example.com\r\nTo: " + r.a.Address + "\r\nSubject: long\r\n\r\n" + strings.Repeat("x", 50000) + "\r\n"
	if st := r.deliver("a@example.com", "long-1", long); st != nil {
		t.Fatalf("long line = %v", st)
	}
	if r.count("INBOX") != 1 {
		t.Fatal("long-line message not stored")
	}
}
