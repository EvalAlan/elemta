package abuse

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// Many addresses guessing at one account shield it: a right password from a
// network it hasn't used is held back, its owner's network isn't, and nothing
// is ever refused for an account with no history to go on.
func TestTargetedAccountIsShielded(t *testing.T) {
	ctx := context.Background()
	p := DefaultPolicy()
	p.AddressesPerAccount = 3
	p.FailuresPerAddress = 100
	p.AccountsPerAddress = 0
	run := func(t *testing.T, e *Engine, account string) {
		e.RecordSignIn(ctx, "198.51.100.20:4000", "imap", account) // the owner, at home
		for i := 1; i <= 2; i++ {
			e.Failure(ctx, fmt.Sprintf("203.0.%d.1:5000", i), "imap", account)
		}
		if e.Shielded(ctx, "192.0.2.9:1", account) {
			t.Fatal("shielded below the limit")
		}
		e.Failure(ctx, "203.0.3.1:5000", "imap", account)
		if !e.Shielded(ctx, "192.0.2.9:1", account) {
			t.Fatal("a new network got in during the attack")
		}
		if e.Shielded(ctx, "198.51.100.77:1", account) {
			t.Fatal("the owner's /24 was held back")
		}
		if e.Shielded(ctx, "192.0.2.9:1", "other-"+account) {
			t.Fatal("another account was shielded")
		}
	}
	t.Run("local", func(t *testing.T) {
		e := testEngine(t, p)
		run(t, e, "dana@example.com")
		// No history: nothing to compare against, so never refused.
		for i := 1; i <= 3; i++ {
			e.Failure(ctx, fmt.Sprintf("203.0.%d.1:5000", i), "imap", "new@example.com")
		}
		if e.Shielded(ctx, "192.0.2.9:1", "new@example.com") {
			t.Fatal("an account with no history was shielded")
		}
		// Log mode records and holds nothing back.
		q := p
		q.Mode = ModeLog
		logged := testEngine(t, q)
		logged.RecordSignIn(ctx, "198.51.100.20:4000", "imap", "dana@example.com")
		for i := 1; i <= 3; i++ {
			logged.Failure(ctx, fmt.Sprintf("203.0.%d.1:5000", i), "imap", "dana@example.com")
		}
		if logged.Shielded(ctx, "192.0.2.9:1", "dana@example.com") {
			t.Fatal("log mode held a sign-in back")
		}
	})
	t.Run("valkey", func(t *testing.T) {
		addr := os.Getenv("ELEMTA_TEST_VALKEY_ADDR")
		if addr == "" {
			t.Skip("ELEMTA_TEST_VALKEY_ADDR not set")
		}
		// Two services: the attack counted on one shields on the other.
		mailbox, smtp := New("mailbox", addr, nil), New("mta", addr, nil)
		for _, e := range []*Engine{mailbox, smtp} {
			if err := e.Publish(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		account := fmt.Sprintf("target-%d@example.com", time.Now().UnixNano())
		mailbox.RecordSignIn(ctx, "198.51.100.20:4000", "imap", account)
		for i := 1; i <= 3; i++ {
			mailbox.Failure(ctx, fmt.Sprintf("203.0.%d.1:5000", i), "imap", account)
		}
		if !smtp.Shielded(ctx, "192.0.2.9:1", account) || smtp.Shielded(ctx, "198.51.100.5:1", account) {
			t.Fatal("the shield didn't reach the other service")
		}
		found := false
		for _, a := range smtp.Alerts(ctx) {
			found = found || a.Account == account && a.Kind == AlertTargeted
		}
		if !found {
			t.Fatal("no alert for the attack")
		}
	})
}
