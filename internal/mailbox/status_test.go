package mailbox

import (
	"context"
	"testing"
)

func TestAccountStatusRules(t *testing.T) {
	for _, c := range []struct {
		status             string
		login, deliver, su bool
	}{
		{"", true, true, false},
		{"active", true, true, false},
		{"Active", true, true, false},
		{"suspended", false, true, true},
		{"disabled", false, false, false},
		{"something-else", false, false, false},
	} {
		login, _ := statusAllows(c.status, false)
		deliver, su := statusAllows(c.status, true)
		if login != c.login || deliver != c.deliver || su != c.su {
			t.Errorf("%q: login %v deliver %v suspended %v", c.status, login, deliver, su)
		}
	}
}

// The delivery lookup returns suspended accounts (they keep receiving mail),
// and app-password sign-in goes through it, so it must refuse them itself.
func TestSuspendedAccountRefusesAppPasswords(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	ctx := context.Background()
	_, password, err := e.CreateAppPassword(ctx, a.ID, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.login(ctx, a.Address, password, true, "", ""); err != nil {
		t.Fatalf("app password before suspension: %v", err)
	}
	suspended := a
	suspended.Suspended = true
	s.auth = testAuth{suspended}
	if _, err := s.login(ctx, a.Address, password, true, "", ""); err == nil {
		t.Fatal("a suspended account signed in with an app password")
	}
	if got, err := s.auth.Resolve(ctx, a.Address); err != nil || got.ID != a.ID {
		t.Fatalf("a suspended account no longer resolves for delivery: %v", err)
	}
}
