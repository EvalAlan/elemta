package mailbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdministratorAccessIsScopedAuditedAndExpires(t *testing.T) {
	e, account := testEngine(t)
	ctx := context.Background()
	actor := "test-admin-" + account.ID
	t.Cleanup(func() {
		_, _ = e.DB.Exec(`DELETE FROM mailbox_admin_access WHERE account=$1`, account.ID)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_audit WHERE actor=$1`, actor)
	})
	token, expires, err := e.CreateAdminAccess(ctx, account, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !expires.After(time.Now().Add(59*time.Minute)) || expires.After(time.Now().Add(time.Hour)) {
		t.Fatalf("token expiry %s is not one hour", expires)
	}
	id, gotActor, gotExpiry, err := e.adminAccess(ctx, token)
	if err != nil || id != account.ID || gotActor != actor || !gotExpiry.Equal(expires) {
		t.Fatalf("token scope: id=%q actor=%q expiry=%s error=%v", id, gotActor, gotExpiry, err)
	}
	var action, target, domain string
	err = e.DB.QueryRowContext(ctx, `SELECT action,target,domain FROM mailbox_audit WHERE actor=$1 ORDER BY id DESC LIMIT 1`, actor).Scan(&action, &target, &domain)
	if err != nil || action != "mailbox-open" || target != account.Address || domain != "example.com" {
		t.Fatalf("audit: action=%q target=%q domain=%q error=%v", action, target, domain, err)
	}
	if _, _, _, err := e.adminAccess(ctx, token+"wrong"); !errors.Is(err, ErrCredentials) {
		t.Fatalf("wrong token: %v", err)
	}
	if _, err := e.DB.ExecContext(ctx, `UPDATE mailbox_admin_access SET expires=now()-interval '1 second' WHERE token_hash=$1`, adminTokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.adminAccess(ctx, token); !errors.Is(err, ErrCredentials) {
		t.Fatalf("expired token: %v", err)
	}
}
