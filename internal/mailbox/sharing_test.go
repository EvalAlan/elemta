package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"

	"github.com/google/uuid"
)

func TestSharedMailboxGrantUsesImmutableIdentity(t *testing.T) {
	e, owner := testEngine(t)
	ctx := context.Background()
	member := Account{ID: uuid.NewString(), Address: "member-" + uuid.NewString()[:8] + "@example.com"}
	if _, err := e.GrantShare(ctx, owner, member, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, member.ID) })
	if grants, err := e.SharesForMember(ctx, member.ID); err != nil || len(grants) != 1 || !grants[0].CanSend {
		t.Fatalf("member's grants = %+v, %v", grants, err)
	}
	if allowed, err := e.HasShare(ctx, owner.ID, member.ID, true); err != nil || !allowed {
		t.Fatalf("send permission = %t, %v", allowed, err)
	}
	recycled := Account{ID: uuid.NewString(), Address: member.Address}
	if err := e.EnsureAccount(ctx, recycled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, recycled.ID) })
	if allowed, err := e.HasShare(ctx, owner.ID, recycled.ID, false); err != nil || allowed {
		t.Fatalf("recycled address inherited permission = %t, %v", allowed, err)
	}
	if err := e.RevokeShare(ctx, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := e.HasShare(ctx, owner.ID, member.ID, false); err != nil || allowed {
		t.Fatalf("revoked permission = %t, %v", allowed, err)
	}
}

func TestSharedMailboxAdminAndMemberAPI(t *testing.T) {
	e, owner := testEngine(t)
	member := Account{ID: uuid.NewString(), Address: "member-" + uuid.NewString()[:8] + "@example.com"}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, member.ID) })
	s, err := newService(Config{}.WithDefaults(), e, shareAuth{owner: owner, member: member}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cancel)
	s.adminToken = "test-token"
	call := func(method, path, token, body string, asMember bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:5000"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if asMember {
			r.SetBasicAuth(member.Address, "member-password")
		}
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		return w
	}
	path := "/v1/admin/accounts/" + owner.Address + "/shares/" + member.Address
	if w := call(http.MethodPut, path, "wrong", `{"can_send":true}`, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong admin token = %d", w.Code)
	}
	if w := call(http.MethodPut, path, "test-token", `{"can_send":true}`, false); w.Code != http.StatusOK {
		t.Fatalf("grant = %d %s", w.Code, w.Body.String())
	}
	w := call(http.MethodGet, "/v1/security/shares", "", "", true)
	var grants []Share
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &grants) != nil || len(grants) != 1 || !grants[0].CanSend {
		t.Fatalf("member's grants = %d %s", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/v1/admin/share-access?mailbox="+owner.Address+"&member="+member.Address+"&send=true", "test-token", "", false)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatalf("send access = %d %s", w.Code, w.Body.String())
	}
	if w := call(http.MethodDelete, path, "test-token", "", false); w.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/v1/security/shares", "", "", true)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), owner.Address) {
		t.Fatalf("revoked grant remains = %d %s", w.Code, w.Body.String())
	}
}

type shareAuth struct{ owner, member Account }

func (a shareAuth) Login(_ context.Context, user, password string) (Account, error) {
	if user == a.member.Address && password == "member-password" {
		return a.member, nil
	}
	return Account{}, ErrCredentials
}
func (a shareAuth) Resolve(_ context.Context, address string) (Account, error) {
	switch address {
	case a.owner.Address:
		return a.owner, nil
	case a.member.Address:
		return a.member, nil
	default:
		return Account{}, ErrCredentials
	}
}
func (a shareAuth) Exists(_ context.Context, address string) (bool, error) {
	return address == a.owner.Address || address == a.member.Address, nil
}

func TestSharedMailboxLoginUsesMemberCredentials(t *testing.T) {
	e, owner := testEngine(t)
	ctx := context.Background()
	member := Account{ID: uuid.NewString(), Address: "member-" + uuid.NewString()[:8] + "@example.com"}
	if _, err := e.GrantShare(ctx, owner, member, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, member.ID) })
	s, err := newService(Config{}.WithDefaults(), e, shareAuth{owner: owner, member: member}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cancel)
	login := member.Address + "|" + owner.Address
	if got, err := s.login(ctx, login, "member-password", true, mailpolicy.IMAP, ""); err != nil || got.ID != owner.ID {
		t.Fatalf("shared sign-in = %+v, %v", got, err)
	}
	if _, err := s.login(ctx, login, "wrong", true, mailpolicy.IMAP, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("wrong member password = %v", err)
	}
	if _, err := s.login(ctx, login, "member-password", true, mailpolicy.POP3, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("shared POP3 sign-in = %v", err)
	}
	if err := e.RevokeShare(ctx, owner.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.login(ctx, login, "member-password", true, mailpolicy.IMAP, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("revoked shared sign-in = %v", err)
	}
}
