package mailbox

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func TestClientKey(t *testing.T) {
	for addr, want := range map[string]string{
		"203.0.113.9:143":            "203.0.113.9",
		"[2001:db8:1:2:3:4:5:6]:993": "2001:db8:1:2::",
		"[2001:db8:1:2:9:9:9:9]:993": "2001:db8:1:2::",
		"[2001:db8:1:3::1]:993":      "2001:db8:1:3::",
		"[::ffff:203.0.113.9]:143":   "203.0.113.9",
	} {
		tcp, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := clientKey(tcp); got != want {
			t.Errorf("clientKey(%s) = %q, want %q", addr, got, want)
		}
	}
	if got := clientKey(nil); got != "" {
		t.Errorf("clientKey(nil) = %q", got)
	}
}

// A user must not be lockable by someone who only knows their address.
func TestFailedLoginsBlockTheClientNotTheAccount(t *testing.T) {
	r := newSieveRig(t)
	ctx := context.Background()
	const attacker, user = "203.0.113.9", "198.51.100.20"
	login := func(password, client string) error {
		t.Helper()
		_, err := r.svc.login(ctx, r.a.Address, password, true, mailpolicy.IMAP, client)
		return err
	}
	_, appPassword, err := r.e.CreateAppPassword(ctx, r.a.ID, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginFailureLimit; i++ {
		if err := login("wrong", attacker); !errors.Is(err, ErrCredentials) {
			t.Fatalf("failure %d = %v", i+1, err)
		}
	}
	if err := login("testpass", attacker); !errors.Is(err, ErrCredentials) {
		t.Fatalf("the blocked client signed in: %v", err)
	}
	if err := login("testpass", user); err != nil {
		t.Fatalf("the account's password from another client: %v", err)
	}
	if err := login(appPassword, attacker); err != nil {
		t.Fatalf("an app password from a blocked client: %v", err)
	}
	if err := login(appPassword, user); err != nil {
		t.Fatalf("an app password from another client: %v", err)
	}
}

// The webmail signs everyone in from one address and limits them itself by
// their real one. Counting it here would make that one address everybody's.
func TestInternalSignInsDontCountAgainstTheClient(t *testing.T) {
	r := newSieveRig(t)
	ctx := context.Background()
	for i := 0; i < loginFailureLimit+5; i++ {
		if _, err := r.svc.login(ctx, r.a.Address, "wrong", false, "", ""); !errors.Is(err, ErrCredentials) {
			t.Fatalf("failure %d = %v", i+1, err)
		}
	}
	if _, err := r.svc.login(ctx, r.a.Address, "testpass", false, "", ""); err != nil {
		t.Fatalf("an internal sign-in after failures: %v", err)
	}
	if ok, err := r.svc.allowLogin(r.a.Address); err != nil || ok {
		t.Fatalf("the account's own count wasn't kept: %v, %v", ok, err)
	}
}

// Failures on the mail protocols reach the shared engine, which is what lets a
// block on one protocol stop an attacker moving to another.
func TestMailFailuresReachTheSharedEngine(t *testing.T) {
	r := newSieveRig(t)
	ctx := context.Background()
	p := abuse.DefaultPolicy()
	p.FailuresPerAddress = 3
	if err := r.svc.abuse.Publish(ctx, p); err != nil {
		t.Fatal(err)
	}
	const client = "203.0.113.50"
	for i := 0; i < 3; i++ {
		_, _ = r.svc.login(ctx, r.a.Address, "wrong", true, mailpolicy.POP3, client)
	}
	if _, blocked := r.svc.abuse.Blocked(client); !blocked {
		t.Fatal("repeated failures didn't block the address")
	}
	// The webmail's hop has no client of its own and must not be blocked.
	for i := 0; i < 5; i++ {
		_, _ = r.svc.login(ctx, r.a.Address, "wrong", false, "", "")
	}
	if blocks := r.svc.abuse.Blocks(); len(blocks) != 1 {
		t.Fatalf("blocks = %+v", blocks)
	}
}
