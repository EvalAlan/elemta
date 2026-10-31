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

func TestUserFolderRetention(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address) })
	for _, name := range []string{"Trash", "Junk", "Sent", "Projects"} {
		if err := e.Create(ctx, a.ID, name); err != nil {
			t.Fatal(err)
		}
		for _, subject := range []string{"old", "new"} {
			if _, err := e.Append(ctx, a.ID, name, []byte("Subject: "+subject+"\r\n\r\nbody\r\n"), nil, time.Now(), ""); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.DB.Exec(`UPDATE mailbox_messages SET added=now()-interval '20 days' WHERE folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name=$2) AND uid=1`, a.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.SetFolderRetentions(ctx, a.ID, []FolderRetention{{Name: "Sent", Days: 10}, {Name: "missing", Days: 10}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("atomic update with a missing folder: %v", err)
	}
	if got, err := e.Folder(ctx, a.ID, "Sent"); err != nil || got.RetentionDays != 0 {
		t.Fatalf("partial update left Sent at %d days: %v", got.RetentionDays, err)
	}
	if _, err := e.SetFolderRetentions(ctx, a.ID, []FolderRetention{{Name: "Trash", Days: 30}, {Name: "Junk", Days: 10}, {Name: "Sent", Days: 30}, {Name: "Projects", Days: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Rename(ctx, a.ID, "Projects", "Projects-Renamed"); err != nil {
		t.Fatal(err)
	}
	if got, err := e.Folder(ctx, a.ID, "Projects-Renamed"); err != nil || got.RetentionDays != 10 {
		t.Fatalf("rename lost retention: %d, %v", got.RetentionDays, err)
	}
	class := testClass(t, e, mailpolicy.Settings{TrashDays: iptr(10), SentDays: iptr(10)})
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class, Settings: mailpolicy.Settings{LegalHold: bptr(true)}}); err != nil {
		t.Fatal(err)
	}
	if rep, err := e.Retention(ctx, time.Now()); err != nil || rep.Deleted != 0 {
		t.Fatalf("legal hold did not stop user retention: %+v, %v", rep, err)
	}
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class}); err != nil {
		t.Fatal(err)
	}
	if rep, err := e.Retention(ctx, time.Now()); err != nil || rep.Deleted != 4 {
		t.Fatalf("folder retention deleted %d messages, want four: %v", rep.Deleted, err)
	}
	for _, name := range []string{"Trash", "Junk", "Sent", "Projects-Renamed"} {
		_, messages, err := e.Snapshot(ctx, a.ID, name)
		if err != nil || len(messages) != 1 {
			t.Errorf("%s retained %d messages, want one: %v", name, len(messages), err)
		}
	}
}

func TestRetentionKeepsApplicationData(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address) })
	if err := e.Create(ctx, a.ID, "Settings"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Append(ctx, a.ID, "Settings", []byte("Subject: preferences\r\n\r\nbody\r\n"), nil, time.Now().AddDate(-1, 0, 0), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetFolderRetentions(ctx, a.ID, []FolderRetention{{Name: "Settings", Days: 1}}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Fatalf("application data retention accepted: %v", err)
	}
	class := testClass(t, e, mailpolicy.Settings{RetentionDays: iptr(1)})
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class}); err != nil {
		t.Fatal(err)
	}
	if rep, err := e.Retention(ctx, time.Now()); err != nil || rep.Deleted != 0 {
		t.Fatalf("application data expired: %+v, %v", rep, err)
	}
}

func TestQuarantineExpiresByDefault(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address) })
	if err := e.Create(ctx, a.ID, quarantineFolder); err != nil {
		t.Fatal(err)
	}
	put := func(age string) {
		t.Helper()
		res, err := e.Append(ctx, a.ID, quarantineFolder, []byte("Subject: held\r\n\r\nbody\r\n"), nil, time.Time{}, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.DB.Exec(`UPDATE mailbox_messages SET added=now()-$1::interval WHERE uid=$2 AND folder=(SELECT id FROM mailbox_folders WHERE account=$3 AND name=$4)`, age, res.UID, a.ID, quarantineFolder); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		_, msgs, err := e.Snapshot(ctx, a.ID, quarantineFolder)
		if err != nil {
			t.Fatal(err)
		}
		return len(msgs)
	}
	put("31 days")
	put("29 days")
	// Nobody set a rule: held mail still goes after 30 days.
	if _, err := e.Retention(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Fatalf("%d left after the default 30 days, want 1", got)
	}
	// A class can keep it for longer.
	put("31 days")
	class := testClass(t, e, mailpolicy.Settings{QuarantineDays: iptr(90)})
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Retention(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Fatalf("%d left under a 90 day class, want 2", got)
	}
	// Legal hold keeps everything.
	put("400 days")
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: class, Settings: mailpolicy.Settings{LegalHold: bptr(true)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Retention(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 3 {
		t.Fatalf("%d left under legal hold, want 3", got)
	}
}
