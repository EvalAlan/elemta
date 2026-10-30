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
