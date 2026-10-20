package mailbox

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func TestAuditLog(t *testing.T) {
	e, _ := testEngine(t)
	ctx := context.Background()
	marker := "audit-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_audit WHERE actor=$1`, marker) })

	var ids []int64
	for _, target := range []string{"dana@one.example", "one.example", "staff", "lee@two.example"} {
		got, err := e.Audit(ctx, mailpolicy.AuditEntry{Actor: marker, Source: "dashboard", Action: "account-create", Target: target, Detail: "quota 0"})
		if err != nil {
			t.Fatal(err)
		}
		if got.ID == 0 || got.At.IsZero() {
			t.Fatalf("stored entry %+v", got)
		}
		ids = append(ids, got.ID)
	}
	if _, err := e.Audit(ctx, mailpolicy.AuditEntry{Action: "x"}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("an entry without an actor: %v", err)
	}

	all, err := e.AuditLog(ctx, mailpolicy.AuditQuery{Actor: marker})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 || all[0].ID != ids[3] || all[0].Domain != "two.example" || all[1].Domain != "" {
		t.Fatalf("newest first with domains filled in: %+v", all)
	}
	one, err := e.AuditLog(ctx, mailpolicy.AuditQuery{Actor: marker, Domains: []string{"ONE.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 2 || one[0].Target != "one.example" || one[1].Target != "dana@one.example" {
		t.Fatalf("domain filter: %+v", one)
	}
	page, err := e.AuditLog(ctx, mailpolicy.AuditQuery{Actor: marker, Before: ids[2], Limit: 1, Target: "ONE", Action: "account-"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != ids[1] {
		t.Fatalf("paging with filters: %+v", page)
	}
}
