package mailbox

import (
	"context"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// listingAuth is testAuth that can also list a domain's accounts.
type listingAuth struct {
	testAuth
	accounts []DirectoryEntry
	calls    *int
}

func (a listingAuth) Directory(_ context.Context, domain string) ([]DirectoryEntry, error) {
	*a.calls++
	var out []DirectoryEntry
	for _, e := range a.accounts {
		if strings.HasSuffix(e.Address, "@"+domain) {
			out = append(out, e)
		}
	}
	return out, nil
}

func TestCompanyDirectory(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	domain := a.Address[strings.LastIndexByte(a.Address, '@')+1:]
	for _, l := range []mailpolicy.List{{Address: "dir-team@" + domain, Name: "Team"}, {Address: "dir-other@elsewhere.example", Name: "Other"}} {
		if _, err := e.PutList(ctx, l); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.DeleteList(context.Background(), l.Address) })
	}
	calls := 0
	s := &Service{engine: e, auth: listingAuth{testAuth: testAuth{a}, calls: &calls, accounts: []DirectoryEntry{
		{Address: "lee@" + domain, Name: "Lee", Kind: "account"},
		{Address: "mallory@elsewhere.example", Name: "Mallory", Kind: "account"},
	}}}
	got, err := s.directory(ctx, a.Address)
	if err != nil {
		t.Fatal(err)
	}
	has := map[string]string{}
	for _, d := range got {
		has[d.Address] = d.Kind
	}
	if has["lee@"+domain] != "account" || has["dir-team@"+domain] != "list" {
		t.Errorf("own domain missing: %+v", got)
	}
	if _, leak := has["mallory@elsewhere.example"]; leak {
		t.Errorf("another domain's account leaked: %+v", got)
	}
	if _, leak := has["dir-other@elsewhere.example"]; leak {
		t.Errorf("another domain's list leaked: %+v", got)
	}
	if _, err := s.directory(ctx, a.Address); err != nil || calls != 1 {
		t.Errorf("second lookup went to the directory again (%d calls, %v)", calls, err)
	}
}
