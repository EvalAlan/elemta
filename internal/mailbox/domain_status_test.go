package mailbox

import (
	"context"
	"errors"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

type fixedStatuses map[string]string

func (f fixedStatuses) DomainStatus(_ context.Context, domain string) (string, error) {
	if s, ok := f[domain]; ok {
		return s, nil
	}
	return mailpolicy.DomainActive, nil
}

type oneAccount struct{ Account }

func (o oneAccount) Login(context.Context, string, string) (Account, error) { return o.Account, nil }
func (o oneAccount) Resolve(context.Context, string) (Account, error)       { return o.Account, nil }
func (o oneAccount) Exists(context.Context, string) (bool, error)           { return true, nil }

func TestDomainStatusGatesSignInAndDelivery(t *testing.T) {
	ctx := context.Background()
	inner := oneAccount{Account{ID: "1", Address: "dana@example.com"}}
	for _, tc := range []struct {
		name, status          string
		login, deliver, flags bool
	}{
		{"active", mailpolicy.DomainActive, true, true, false},
		{"suspended", mailpolicy.DomainSuspended, false, true, true},
		{"disabled", mailpolicy.DomainDisabled, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := domainStatusAuth{inner, fixedStatuses{"example.com": tc.status}}
			if _, err := a.Login(ctx, "dana@example.com", "pw"); (err == nil) != tc.login {
				t.Fatalf("login err = %v, want allowed=%v", err, tc.login)
			}
			got, err := a.Resolve(ctx, "dana@example.com")
			if (err == nil) != tc.deliver {
				t.Fatalf("resolve err = %v, want allowed=%v", err, tc.deliver)
			}
			if err != nil && !errors.Is(err, ErrCredentials) {
				t.Fatalf("resolve err = %v, want ErrCredentials", err)
			}
			// Suspended is what ends a session that is already open.
			if got.Suspended != tc.flags {
				t.Fatalf("suspended = %v, want %v", got.Suspended, tc.flags)
			}
		})
	}
}

func TestDomainStatusCoversAliasAddressElsewhere(t *testing.T) {
	a := domainStatusAuth{oneAccount{Account{ID: "1", Address: "dana@example.com"}}, fixedStatuses{"closed.example": mailpolicy.DomainDisabled}}
	if _, err := a.Resolve(context.Background(), "dana@closed.example"); !errors.Is(err, ErrCredentials) {
		t.Fatalf("alias in a disabled domain resolved: %v", err)
	}
	if _, err := a.Resolve(context.Background(), "dana@example.com"); err != nil {
		t.Fatalf("the healthy address was refused: %v", err)
	}
}

func TestDomainStatusIsStored(t *testing.T) {
	ctx := context.Background()
	e, _ := testEngine(t)
	const domain = "status-test.example"
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_domain_status WHERE domain=$1`, domain) })
	check := func(want string) {
		t.Helper()
		if got, err := e.DomainStatus(ctx, domain); err != nil || got != want {
			t.Fatalf("status = %q, %v, want %q", got, err, want)
		}
	}
	check(mailpolicy.DomainActive)
	for _, status := range []string{mailpolicy.DomainSuspended, mailpolicy.DomainDisabled} {
		if _, err := e.SetDomainStatus(ctx, mailpolicy.DomainStatus{Domain: domain, Status: status}); err != nil {
			t.Fatal(err)
		}
		check(status)
	}
	if _, err := e.SetDomainStatus(ctx, mailpolicy.DomainStatus{Domain: domain, Status: "closed"}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Fatalf("bad status = %v", err)
	}
	if _, err := e.SetDomainStatus(ctx, mailpolicy.DomainStatus{Domain: domain, Status: mailpolicy.DomainActive}); err != nil {
		t.Fatal(err)
	}
	check(mailpolicy.DomainActive)
	if listed, err := e.DomainStatuses(ctx); err != nil {
		t.Fatal(err)
	} else {
		for _, d := range listed {
			if d.Domain == domain {
				t.Fatal("an active domain is still listed")
			}
		}
	}
}
