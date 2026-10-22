package mailbox

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// mailDirAuth is directoryAuth with the lists and domains a directory can
// carry (MailDirectory).
type mailDirAuth struct {
	directoryAuth
	lists   map[string]mailpolicy.List // by address
	domains map[string]DirectoryDomain
}

func (m mailDirAuth) DirectoryList(_ context.Context, address string) (mailpolicy.List, bool, error) {
	l, ok := m.lists[strings.ToLower(address)]
	return l, ok, nil
}

func (m mailDirAuth) DirectoryDomain(_ context.Context, domain string) (DirectoryDomain, bool, error) {
	d, ok := m.domains[strings.ToLower(domain)]
	return d, ok, nil
}

func newMailDirRig(t *testing.T, setup func(r *addressingRig, m *mailDirAuth)) (*addressingRig, *mailDirAuth) {
	t.Helper()
	m := &mailDirAuth{lists: map[string]mailpolicy.List{}, domains: map[string]DirectoryDomain{}}
	var rig *addressingRig
	rig = newAddressingRigWith(t, func(d directoryAuth) Authenticator {
		m.directoryAuth = d
		return m
	})
	if setup != nil {
		setup(rig, m)
	}
	return rig, m
}

func (r *addressingRig) setAccount(local string, change func(*Account)) {
	a := r.dir.accounts[r.addr(local)]
	change(&a)
	r.dir.accounts[r.addr(local)] = a
}

func TestDirectoryForwarding(t *testing.T) {
	r, _ := newMailDirRig(t, nil)
	r.setAccount("ana", func(a *Account) { a.Forward = []string{"far@remote.example"} })
	r.setAccount("ben", func(a *Account) { a.Forward = []string{"far@remote.example"}; a.ForwardKeepCopy = true })

	msg := msgWith("forward me")
	st := r.send("x@example.org", "fwd-1", []string{r.addr("ana"), r.addr("benny")}, msg)
	if st[r.addr("ana")] != nil || st[r.addr("benny")] != nil {
		t.Fatalf("forwarded delivery = %v", st)
	}
	if n := len(r.inbox("ana")); n != 0 {
		t.Errorf("ana kept %d messages without asking for a copy", n)
	}
	if n := len(r.inbox("ben")); n != 1 {
		t.Errorf("ben has %d messages, want the copy he asked for", n)
	}
	sent := r.submit.messages()
	if len(sent) != 2 || sent[0].to[0] != "far@remote.example" || sent[0].from != "x@example.org" {
		t.Fatalf("forwarded copies = %+v", sent)
	}
	if !strings.Contains(string(sent[0].data), redirectHeader+": ") {
		t.Error("forwarded copy has no loop marker")
	}

	// A retry of the same delivery forwards nothing again.
	r.send("x@example.org", "fwd-1", []string{r.addr("ana")}, msg)
	if len(r.submit.messages()) != 2 {
		t.Error("a retried delivery was forwarded again")
	}

	// More addresses than the class allows (three by default): only the
	// first ones get a copy.
	r.setAccount("ana", func(a *Account) {
		a.Forward = []string{"f1@remote.example", "f2@remote.example", "f3@remote.example", "f4@remote.example", "f5@remote.example"}
	})
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("many"))
	if got := len(r.submit.messages()); got != 2+mailpolicy.DefaultMaxForwardAddresses {
		t.Errorf("forwarded %d copies in all, want %d", got, 2+mailpolicy.DefaultMaxForwardAddresses)
	}
	r.setAccount("ana", func(a *Account) { a.Forward = []string{"far@remote.example"} })
	before := len(r.submit.messages())

	// Mail this account already forwarded that comes back stays here.
	r.send("x@example.org", "", []string{r.addr("ana")}, redirectHeader+": "+r.addr("ana")+"\r\n"+msgWith("came back"))
	if len(r.inbox("ana")) != 1 || len(r.submit.messages()) != before {
		t.Error("a forwarding loop wasn't stopped")
	}
}

func TestDirectoryListsAndDomains(t *testing.T) {
	r, m := newMailDirRig(t, nil)
	ctx := context.Background()
	m.lists[r.addr("crew")] = mailpolicy.List{Address: r.addr("crew"), Name: "Crew", Owner: r.addr("ana"), Posting: mailpolicy.PostAnyone,
		Members: []string{r.addr("ana"), "out@remote.example"}}
	// A database list with the same address loses to the directory's.
	if _, err := r.e.PutList(ctx, mailpolicy.List{Address: r.addr("crew"), Members: []string{r.addr("ben")}}); err != nil {
		t.Fatal(err)
	}
	st := r.send("x@example.org", "", []string{r.addr("crew")}, msgWith("to the crew"))
	if st[r.addr("crew")] != nil {
		t.Fatalf("directory list = %v", st[r.addr("crew")])
	}
	if len(r.inbox("ana")) != 1 || len(r.inbox("ben")) != 0 {
		t.Fatalf("directory list delivered to ana %d, ben %d", len(r.inbox("ana")), len(r.inbox("ben")))
	}
	if sent := r.submit.messages(); len(sent) != 1 || sent[0].to[0] != "out@remote.example" || sent[0].from != r.addr("ana") {
		t.Fatalf("external member copy = %+v", sent)
	}

	// A directory domain's catch-all replaces the database's, and its alias
	// routes another domain here.
	if _, err := r.e.SetRoute(ctx, mailpolicy.DomainRoute{Domain: r.domain, CatchAll: r.addr("ana")}); err != nil {
		t.Fatal(err)
	}
	alias := "dir-alias-" + r.domain
	m.domains[r.domain] = DirectoryDomain{Domain: r.domain, CatchAll: r.addr("ben")}
	m.domains[alias] = DirectoryDomain{Domain: alias, AliasOf: r.domain}
	r.svc.dirMail = directoryMail{} // the first delivery cached "no entry"
	st = r.send("x@example.org", "", []string{r.addr("nobody"), "ana@" + alias}, msgWith("routing"))
	if st[r.addr("nobody")] != nil || st["ana@"+alias] != nil {
		t.Fatalf("directory routing = %v", st)
	}
	if len(r.inbox("ben")) != 1 || len(r.inbox("ana")) != 2 {
		t.Fatalf("catch-all and alias: ben %d (want 1), ana %d (want 2)", len(r.inbox("ben")), len(r.inbox("ana")))
	}

	if info, err := r.svc.addressInfo(ctx, r.addr("crew")); err != nil || info.Kind != "list" {
		t.Errorf("directory list's address = %+v, %v", info, err)
	}
}

func TestDirectoryClasses(t *testing.T) {
	r, m := newMailDirRig(t, nil)
	ctx := context.Background()
	domainClass := testClass(t, r.e, mailpolicy.Settings{MessagesPerHour: iptr(20)})
	accountClass := testClass(t, r.e, mailpolicy.Settings{MessagesPerHour: iptr(30)})
	override := testClass(t, r.e, mailpolicy.Settings{MessagesPerHour: iptr(40)})
	m.domains[r.domain] = DirectoryDomain{Domain: r.domain, Class: domainClass}
	r.setAccount("ben", func(a *Account) { a.DirectoryClass = accountClass })
	r.setAccount("ana", func(a *Account) { a.DirectoryClass = "no-such-class" })

	for local, want := range map[string]string{"ana": domainClass, "ben": accountClass} {
		eff, err := r.e.EffectivePolicy(ctx, r.addr(local), 0)
		if err != nil {
			t.Fatal(err)
		}
		if eff.Class != want {
			t.Errorf("%s class = %q, want %q", local, eff.Class, want)
		}
	}
	// A class the dashboard sets on the account still wins.
	if _, err := r.e.DB.Exec(`INSERT INTO mailbox_account_policy(address,class,settings) VALUES($1,$2,'{}')`, r.addr("ben"), override); err != nil {
		t.Fatal(err)
	}
	r.svc.dirMail = directoryMail{} // forget what was read
	if eff, _ := r.e.EffectivePolicy(ctx, r.addr("ben"), 0); eff.Class != override {
		t.Errorf("dashboard override lost to the directory: %q", eff.Class)
	}
}

func TestDirectorySendAs(t *testing.T) {
	r, m := newMailDirRig(t, nil)
	r.svc.adminToken = "admin-secret"
	m.lists[r.addr("crew")] = mailpolicy.List{Address: r.addr("crew")}
	r.setAccount("ana", func(a *Account) { a.SendAs = []string{r.addr("crew"), "@brand.example"} })
	allowed := func(mailbox, member string) bool {
		req := httptest.NewRequest("GET", "/v1/admin/share-access?send=true&mailbox="+mailbox+"&member="+member, nil)
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer admin-secret")
		w := httptest.NewRecorder()
		r.svc.http.Handler.ServeHTTP(w, req)
		var out map[string]bool
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out["allowed"]
	}
	for _, c := range []struct {
		mailbox, member string
		want            bool
	}{
		{r.addr("crew"), r.addr("ana"), true},
		{"news@brand.example", r.addr("ana"), true},
		{r.addr("crew"), r.addr("ben"), false},
		{r.addr("ben"), r.addr("ana"), false},
		{"news@other.example", r.addr("ana"), false},
	} {
		if got := allowed(c.mailbox, c.member); got != c.want {
			t.Errorf("%s sending as %s = %v, want %v", c.member, c.mailbox, got, c.want)
		}
	}
}

func TestDirectoryBaseDefault(t *testing.T) {
	for base, want := range map[string]string{
		"ou=people,dc=example,dc=com": "dc=example,dc=com",
		"dc=example,dc=com":           "dc=example,dc=com",
		"ou=people,dc=com":            "ou=people,dc=com",
		"not a dn":                    "not a dn",
	} {
		if got := directoryBase(base); got != want {
			t.Errorf("directoryBase(%q) = %q, want %q", base, got, want)
		}
	}
}
