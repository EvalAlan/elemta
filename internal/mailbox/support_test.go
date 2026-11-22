package mailbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/google/uuid"
)

func TestSupportAPI(t *testing.T) {
	e, owner := testEngine(t)
	ctx := context.Background()
	// The second account exists in the directory and has never been used.
	fresh := Account{ID: uuid.NewString(), Address: "fresh-" + uuid.NewString()[:8] + "@example.com"}
	s, err := newService(Config{}.WithDefaults(), e, shareAuth{owner: owner, member: fresh}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cancel)
	s.adminToken = "test-token"
	call := func(method, path string, out any) int {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		if out != nil && w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
		}
		return w.Code
	}

	first, secret, err := e.CreateAppPassword(ctx, owner.ID, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.CreateAppPassword(ctx, owner.ID, "Laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.DB.Exec(`UPDATE mailbox_accounts SET used_bytes=4096 WHERE id=$1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := e.appPasswordAccount(ctx, owner.Address, secret); err != nil || !ok {
		t.Fatalf("app password before revoking: %v %v", ok, err)
	}

	base := "/v1/admin/accounts/" + owner.Address
	var got mailpolicy.AccountSecurity
	if code := call(http.MethodGet, base+"/security", &got); code != http.StatusOK || got.UsedBytes != 4096 || len(got.AppPasswords) != 2 || got.AppPasswords[0].LastUsed == nil || got.TOTP || got.Passkeys != 0 {
		t.Fatalf("security = %d %+v", code, got)
	}
	var empty mailpolicy.AccountSecurity
	if code := call(http.MethodGet, "/v1/admin/accounts/"+fresh.Address+"/security", &empty); code != http.StatusOK || empty.UsedBytes != 0 || len(empty.AppPasswords) != 0 {
		t.Fatalf("never used = %d %+v", code, empty)
	}
	if code := call(http.MethodGet, "/v1/admin/accounts/nobody@example.com/security", nil); code != http.StatusNotFound {
		t.Fatalf("no such account = %d", code)
	}
	// An ID belongs to one account: naming it under another's changes nothing.
	if code := call(http.MethodDelete, fmt.Sprintf("/v1/admin/accounts/%s/app-passwords/%d", fresh.Address, first.ID), nil); code != http.StatusNotFound {
		t.Fatalf("revoked through another account = %d", code)
	}
	if code := call(http.MethodDelete, fmt.Sprintf("%s/app-passwords/%d", base, first.ID), nil); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if _, ok, err := e.appPasswordAccount(ctx, owner.Address, secret); err != nil || ok {
		t.Fatalf("a revoked app password still signs in: %v %v", ok, err)
	}
	var all struct{ Revoked int64 }
	if code := call(http.MethodDelete, base+"/app-passwords", &all); code != http.StatusOK || all.Revoked != 1 {
		t.Fatalf("revoke all = %d %+v", code, all)
	}

	used := func() (int64, bool) {
		var list []mailpolicy.Usage
		if code := call(http.MethodGet, "/v1/admin/usage", &list); code != http.StatusOK {
			t.Fatalf("usage = %d", code)
		}
		for _, u := range list {
			if u.Address == owner.Address {
				return u.UsedBytes, true
			}
		}
		return 0, false
	}
	if n, ok := used(); !ok || n != 4096 {
		t.Fatalf("usage = %d %v", n, ok)
	}
	// The copy a move leaves behind isn't counted.
	if _, err = e.DB.Exec(`UPDATE mailbox_accounts SET writable=false WHERE id=$1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := used(); ok {
		t.Fatal("a moved account's old copy is counted")
	}
}
