package mailbox

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func TestRetentionAndLegalHold(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_held WHERE account=$1`, a.ID)
	})
	for _, f := range []string{"Trash", "Junk"} {
		if err := e.Create(ctx, a.ID, f); err != nil && !errors.Is(err, ErrExists) {
			t.Fatal(err)
		}
	}
	put := func(folder, subject string, date time.Time) uint32 {
		t.Helper()
		res, err := e.Append(ctx, a.ID, folder, []byte("Subject: "+subject+"\r\n\r\nFrom the start\r\n"), nil, date, "")
		if err != nil {
			t.Fatal(err)
		}
		return res.UID
	}
	now := time.Now()
	old := now.AddDate(-2, 0, 0)
	put("Trash", "trashed long ago", now)
	put("Trash", "trashed today", now)
	put("Junk", "junk", now)
	put("INBOX", "ancient", old)
	put("INBOX", "recent", now)
	// Trash age counts from arrival in the folder, not the message date.
	if _, err := e.DB.Exec(`UPDATE mailbox_messages SET added=now()-interval '40 days' WHERE folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name='Trash') AND uid=1`, a.ID); err != nil {
		t.Fatal(err)
	}
	count := func(folder string) int {
		_, msgs, err := e.Snapshot(ctx, a.ID, folder)
		if err != nil {
			t.Fatal(err)
		}
		return len(msgs)
	}

	// No rules: nothing happens.
	if rep, err := e.Retention(ctx, now); err != nil || rep.Deleted != 0 {
		t.Fatalf("without rules: %+v %v", rep, err)
	}
	class := testClass(t, e, mailpolicy.Settings{TrashDays: iptr(30), JunkDays: iptr(0), RetentionDays: iptr(365)})
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class}); err != nil {
		t.Fatal(err)
	}

	// On legal hold, retention leaves everything alone.
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class, Settings: mailpolicy.Settings{LegalHold: bptr(true)}}); err != nil {
		t.Fatal(err)
	}
	if rep, _ := e.Retention(ctx, now); rep.Deleted != 0 {
		t.Fatalf("retention ran on a held account: %+v", rep)
	}
	// What a held user deletes is kept, body and all, and purge is refused.
	if _, err := e.expunge(ctx, a.ID, "INBOX", []uint32{2}, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteFolder(ctx, a.ID, "Junk"); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.HeldCount(ctx, a.Address); n != 2 {
		t.Fatalf("held %d messages, want 2", n)
	}
	if _, err := e.DB.Exec(`UPDATE mailbox_bodies SET orphaned_at=now()-interval '30 days' WHERE key IN (SELECT body FROM mailbox_held WHERE account=$1)`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GC(ctx); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if n, err := e.ExportHeld(ctx, a.Address, &buf); err != nil || n != 2 {
		t.Fatalf("export = %d, %v", n, err)
	}
	if !strings.Contains(buf.String(), "Subject: recent") || !strings.Contains(buf.String(), "Subject: junk") || !strings.Contains(buf.String(), `X-Elemta-Held: folder="Junk"; folder deleted`) || !strings.Contains(buf.String(), "\n>From the start") {
		t.Errorf("mbox export (bodies must survive GC, From lines quoted):\n%s", buf.String())
	}
	if _, err := e.PurgeAccount(ctx, a.Address); !errors.Is(err, ErrInUse) {
		t.Fatalf("purge of a held account: %v", err)
	}

	// Hold lifted: retention empties old Trash and old mail everywhere,
	// and keeps the rest.
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class}); err != nil {
		t.Fatal(err)
	}
	rep, err := e.Retention(ctx, now)
	if err != nil || rep.Deleted != 2 {
		t.Fatalf("retention = %+v, %v", rep, err)
	}
	if count("Trash") != 1 || count("INBOX") != 0 {
		t.Errorf("after retention: Trash %d (want 1), INBOX %d (want 0: the recent one was deleted while held, the ancient one by age)", count("Trash"), count("INBOX"))
	}
}
