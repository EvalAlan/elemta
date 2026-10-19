package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
)

// directoryAuth is a small directory: accounts with aliases, some disabled.
type directoryAuth struct {
	accounts map[string]Account // by primary address
	aliases  map[string]string  // alias -> primary
	disabled map[string]bool
}

func (d directoryAuth) primary(u string) (string, bool) {
	u = strings.ToLower(u)
	if _, ok := d.accounts[u]; ok {
		return u, true
	}
	p, ok := d.aliases[u]
	return p, ok
}
func (d directoryAuth) Login(ctx context.Context, u, p string) (Account, error) {
	if p != "testpass" {
		return Account{}, ErrCredentials
	}
	return d.Resolve(ctx, u)
}
func (d directoryAuth) Resolve(_ context.Context, u string) (Account, error) {
	p, ok := d.primary(u)
	if !ok || d.disabled[p] {
		return Account{}, ErrCredentials
	}
	return d.accounts[p], nil
}
func (d directoryAuth) Exists(_ context.Context, u string) (bool, error) {
	_, ok := d.primary(u)
	return ok, nil
}

type addressingRig struct {
	t      *testing.T
	e      *Engine
	svc    *Service
	lmtp   string
	submit *fakeSubmission
	dir    directoryAuth
	domain string
}

func newAddressingRig(t *testing.T) *addressingRig {
	t.Helper()
	e, _ := testEngine(t)
	domain := "d" + uuid.NewString()[:8] + ".example"
	acct := func(local string) Account {
		a := Account{ID: uuid.NewString(), Address: local + "@" + domain}
		t.Cleanup(func() {
			_, _ = e.DB.Exec(`DELETE FROM mailbox_folders WHERE account=$1`, a.ID)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_deliveries WHERE account=$1`, a.ID)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, a.ID)
		})
		return a
	}
	dir := directoryAuth{accounts: map[string]Account{}, aliases: map[string]string{}, disabled: map[string]bool{}}
	for _, l := range []string{"ana", "ben", "gone"} {
		a := acct(l)
		dir.accounts[a.Address] = a
	}
	dir.aliases["benny@"+domain] = "ben@" + domain
	dir.disabled["gone@"+domain] = true
	submit, submitAddr := startFakeSubmission(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Sieve.SubmitAddr = submitAddr
	svc, err := newService(cfg, e, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = svc.lmtp.Serve(ln) }()
	t.Cleanup(func() {
		svc.cancel()
		_ = svc.lmtp.Close()
		_, _ = e.DB.Exec(`DELETE FROM mailbox_domain_routes WHERE domain LIKE $1`, "%"+domain)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_lists WHERE address LIKE $1`, "%@%"+domain)
	})
	return &addressingRig{t: t, e: e, svc: svc, lmtp: ln.Addr().String(), submit: submit, dir: dir, domain: domain}
}

func (r *addressingRig) addr(local string) string { return local + "@" + r.domain }

// send delivers one message over LMTP and returns each recipient's status
// (nil for success), or the RCPT refusal for a recipient refused there.
func (r *addressingRig) send(from, envid string, to []string, raw string) map[string]*smtp.SMTPError {
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
	out := map[string]*smtp.SMTPError{}
	var accepted []string
	for _, rcpt := range to {
		if err := cl.Rcpt(rcpt, nil); err != nil {
			var se *smtp.SMTPError
			if !errors.As(err, &se) {
				r.t.Fatal(err)
			}
			out[rcpt] = se
			continue
		}
		accepted = append(accepted, rcpt)
	}
	if len(accepted) == 0 {
		return out
	}
	w, err := cl.Data()
	if err != nil {
		r.t.Fatal(err)
	}
	_, _ = w.Write([]byte(raw))
	_, err = w.CloseWithLMTPResponse()
	var lmtpErr smtp.LMTPDataError
	if errors.As(err, &lmtpErr) {
		for k, v := range lmtpErr {
			out[k] = v
		}
	} else if err != nil {
		r.t.Fatal(err)
	}
	for _, a := range accepted {
		if _, ok := out[a]; !ok {
			out[a] = nil
		}
	}
	return out
}

func (r *addressingRig) inbox(local string) []string {
	r.t.Helper()
	a := r.dir.accounts[r.addr(local)]
	_, msgs, err := r.e.Snapshot(context.Background(), a.ID, "INBOX")
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range msgs {
		raw, err := r.e.Bodies.Get(context.Background(), m.Body, 1<<20)
		if err == nil {
			out = append(out, string(raw))
		}
	}
	return out
}

func msgWith(subject string) string {
	return "From: someone@example.org\r\nSubject: " + subject + "\r\nMessage-ID: <" + uuid.NewString() + "@example.org>\r\n\r\nhello\r\n"
}

func TestAliasesCatchAllAndDomainAliases(t *testing.T) {
	r := newAddressingRig(t)
	ctx := context.Background()
	alias := "alias-" + r.domain
	if _, err := r.e.SetRoute(ctx, mailpolicy.DomainRoute{Domain: alias, AliasOf: r.domain}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = r.e.DB.Exec(`DELETE FROM mailbox_domain_routes WHERE domain=$1`, alias) })

	st := r.send("x@example.org", "", []string{r.addr("benny"), "ana@" + alias, r.addr("nobody")}, msgWith("routing"))
	if st[r.addr("benny")] != nil || st["ana@"+alias] != nil {
		t.Fatalf("alias or domain alias refused: %v", st)
	}
	if st[r.addr("nobody")] == nil || st[r.addr("nobody")].Code != 550 {
		t.Fatalf("unknown address without a catch-all: %v", st[r.addr("nobody")])
	}
	if len(r.inbox("ben")) != 1 || len(r.inbox("ana")) != 1 {
		t.Fatal("alias or domain alias didn't reach the account")
	}

	// A catch-all takes unknown names, here and at the alias domain, but
	// not a disabled account's address.
	if _, err := r.e.SetRoute(ctx, mailpolicy.DomainRoute{Domain: r.domain, CatchAll: r.addr("ana")}); err != nil {
		t.Fatal(err)
	}
	st = r.send("x@example.org", "", []string{r.addr("nobody"), "whoever@" + alias, r.addr("gone")}, msgWith("catch-all"))
	if st[r.addr("nobody")] != nil || st["whoever@"+alias] != nil {
		t.Fatalf("catch-all refused: %v", st)
	}
	if st[r.addr("gone")] == nil || st[r.addr("gone")].Code != 550 {
		t.Fatalf("a disabled account's mail went to the catch-all: %v", st[r.addr("gone")])
	}
	if got := len(r.inbox("ana")); got != 3 {
		t.Fatalf("ana has %d messages, want 3", got)
	}

	// Aliases don't chain, and a domain isn't its own alias.
	if _, err := r.e.SetRoute(ctx, mailpolicy.DomainRoute{Domain: "third-" + r.domain, AliasOf: alias}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("alias of an alias accepted: %v", err)
	}
	if _, err := r.e.SetRoute(ctx, mailpolicy.DomainRoute{Domain: r.domain, AliasOf: r.domain}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("self alias accepted: %v", err)
	}
}

func TestDistributionLists(t *testing.T) {
	r := newAddressingRig(t)
	ctx := context.Background()
	if _, err := r.e.PutList(ctx, mailpolicy.List{Address: r.addr("sub"), Members: []string{r.addr("benny")}}); err != nil {
		t.Fatal(err)
	}
	team := mailpolicy.List{Address: r.addr("team"), Name: "Team", Owner: r.addr("ana"), Posting: mailpolicy.PostMembers,
		Members: []string{r.addr("ana"), r.addr("ben"), "Ext@Remote.example", r.addr("sub"), r.addr("team-not-a-member-of-itself-check")}}
	if _, err := r.e.PutList(ctx, team); err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.PutList(ctx, mailpolicy.List{Address: r.addr("loop"), Members: []string{r.addr("loop")}}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("a list containing itself was accepted: %v", err)
	}

	// Posting: members only.
	st := r.send("outsider@example.org", "", []string{r.addr("team")}, msgWith("spam"))
	if st[r.addr("team")] == nil || st[r.addr("team")].Code != 550 {
		t.Fatalf("non-member post = %v", st[r.addr("team")])
	}
	if len(r.inbox("ana"))+len(r.inbox("ben"))+len(r.submit.messages()) != 0 {
		t.Fatal("a refused post was delivered")
	}

	// A member's post reaches each local member once (ben is on the list
	// and on the nested list through his alias), and one copy goes out to
	// the external member, with the owner as envelope sender.
	st = r.send(r.addr("ben"), "post-1", []string{r.addr("team")}, msgWith("hello team"))
	if st[r.addr("team")] != nil {
		t.Fatalf("member post = %v", st[r.addr("team")])
	}
	ana, ben := r.inbox("ana"), r.inbox("ben")
	if len(ana) != 1 || len(ben) != 1 {
		t.Fatalf("local copies: ana %d, ben %d (want 1 each)", len(ana), len(ben))
	}
	if !strings.Contains(ana[0], "List-Id: Team <team."+r.domain+">") || !strings.Contains(ana[0], listHeader+": "+r.addr("team")) {
		t.Errorf("list headers missing:\n%s", ana[0])
	}
	sent := r.submit.messages()
	if len(sent) != 1 || sent[0].from != r.addr("ana") || len(sent[0].to) != 2 {
		t.Fatalf("external copy = %+v", sent)
	}
	ext := strings.Join(sent[0].to, ",")
	if !strings.Contains(ext, "ext@remote.example") || !strings.Contains(ext, "team-not-a-member-of-itself-check@") {
		t.Errorf("external recipients = %v", sent[0].to)
	}

	// A retry of the same delivery adds nothing.
	r.send(r.addr("ben"), "post-1", []string{r.addr("team")}, msgWith("hello team"))
	if len(r.inbox("ana")) != 1 || len(r.submit.messages()) != 1 {
		t.Fatal("a retried list delivery was delivered again")
	}

	// A message the list has already handled (its marker) stops.
	r.send(r.addr("ben"), "", []string{r.addr("team")}, listHeader+": "+r.addr("team")+"\r\n"+msgWith("looped"))
	if len(r.inbox("ana")) != 1 {
		t.Fatal("a looped message was delivered again")
	}

	// Membership changes, and purging a member takes them off.
	if _, err := r.e.ChangeMembers(ctx, r.addr("team"), []string{"new@remote.example"}, []string{"ext@remote.example"}); err != nil {
		t.Fatal(err)
	}
	l, _ := r.e.List(ctx, r.addr("team"))
	if strings.Contains(strings.Join(l.Members, ","), "ext@remote.example") || !strings.Contains(strings.Join(l.Members, ","), "new@remote.example") {
		t.Errorf("members after change = %v", l.Members)
	}
	if _, err := r.e.PurgeAccount(ctx, r.addr("ben")); err != nil {
		t.Fatal(err)
	}
	l, _ = r.e.List(ctx, r.addr("team"))
	if strings.Contains(strings.Join(l.Members, ","), r.addr("ben")) {
		t.Error("purged account still on the list")
	}
}

func TestAddressingAdminAPI(t *testing.T) {
	r := newAddressingRig(t)
	r.svc.adminToken = "admin-secret"
	call := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-secret")
		w := httptest.NewRecorder()
		r.svc.http.Handler.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := call("PUT", "/v1/admin/lists/"+r.addr("benny"), `{"members":["x@example.org"]}`); code != http.StatusConflict {
		t.Fatalf("list on an alias's address = %d", code)
	}
	if code, out := call("PUT", "/v1/admin/lists/"+r.addr("all"), `{"name":"All","posting":"domain","members":["`+r.addr("ana")+`"]}`); code != http.StatusOK || out["member_count"].(float64) != 1 {
		t.Fatalf("create list = %d %v", code, out)
	}
	if code, _ := call("PUT", "/v1/admin/lists/"+r.addr("bad"), `{"posting":"everyone"}`); code != http.StatusBadRequest {
		t.Fatalf("bad posting value = %d", code)
	}
	for addr, kind := range map[string]string{r.addr("ana"): "account", r.addr("benny"): "alias", r.addr("all"): "list", r.addr("free"): "", r.addr("gone"): "account"} {
		if _, out := call("GET", "/v1/admin/addresses/"+addr, ""); out["kind"] != kind {
			t.Errorf("%s kind = %v, want %q", addr, out["kind"], kind)
		}
	}
	if code, out := call("PUT", "/v1/admin/routes/"+r.domain, `{"catch_all":"`+r.addr("ana")+`"}`); code != http.StatusOK || out["catch_all"] != r.addr("ana") {
		t.Fatalf("set catch-all = %d %v", code, out)
	}
	if code, _ := call("DELETE", "/v1/admin/lists/"+r.addr("all"), ""); code != http.StatusOK {
		t.Fatalf("delete list = %d", code)
	}
	if code, _ := call("DELETE", "/v1/admin/lists/"+r.addr("all"), ""); code != http.StatusNotFound {
		t.Fatalf("delete missing list = %d", code)
	}
}
