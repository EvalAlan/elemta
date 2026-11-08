package mailbox

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// cellEngine is an engine on a database of its own, as a cell has.
func cellEngine(t *testing.T, compress bool) *Engine {
	t.Helper()
	base := os.Getenv("ELEMTA_TEST_MAILBOX_DSN")
	if base == "" {
		t.Skip("set ELEMTA_TEST_MAILBOX_DSN to disposable Postgres")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := "move_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE DATABASE ` + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE ` + pq.QuoteIdentifier(name) + ` WITH (FORCE)`) })
	dsn, _ := withDatabase(base, name)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	files, err := NewFileBodies(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var bodies BodyStore = files
	if compress {
		bodies = &compressedBodies{BodyStore: files, compress: true}
	}
	e, err := NewEngine(context.Background(), db, bodies, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMoveAccount(t *testing.T) {
	ctx := context.Background()
	src, dst := cellEngine(t, false), cellEngine(t, true)
	a := Account{ID: uuid.NewString(), Address: "mover@example.com"}
	colleague := Account{ID: uuid.NewString(), Address: "stays@example.com"}
	for _, acc := range []Account{a, colleague} {
		if err := src.EnsureAccount(ctx, acc); err != nil {
			t.Fatal(err)
		}
	}
	for i, subject := range []string{"one", "two", "three"} {
		var flags []string
		if i == 0 {
			flags = []string{`\Seen`, "$Work"}
		}
		raw := []byte("From: x@example.com\r\nSubject: " + subject + "\r\n\r\nbody " + subject + "\r\n")
		if _, err := src.Append(ctx, a.ID, "INBOX", raw, flags, time.Now(), "tok-"+subject); err != nil {
			t.Fatal(err)
		}
	}
	if err := src.Create(ctx, a.ID, "Projects/2026"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Append(ctx, a.ID, "Projects/2026", []byte("Subject: p\r\n\r\np\r\n"), nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	// A gap in the UIDs, as deleted mail leaves.
	if _, err := src.DB.Exec(`DELETE FROM mailbox_messages WHERE uid=2 AND folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name='INBOX')`, a.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO mailbox_sieve_scripts(account,name,script,active) VALUES($1,'main','keep;',true)`,
		`INSERT INTO mailbox_security(account,protocols_off) VALUES($1,'{pop3}')`,
		`INSERT INTO mailbox_passkeys(account,credential_id,credential,name,host) VALUES($1,'cred','{}','Laptop','mail.example.com')`,
		`INSERT INTO mailbox_session_tokens(token_hash,account,passkey,expires,absolute_expires) VALUES('h1',$1,(SELECT id FROM mailbox_passkeys WHERE account=$1),now()+interval '1 day',now()+interval '30 days')`,
		`INSERT INTO mailbox_shares(mailbox,member,can_send) VALUES($1,'` + colleague.ID + `',false)`,
	} {
		if _, err := src.DB.Exec(q, a.ID); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// A passkey already in the destination, so the moved one's ID differs.
	other := Account{ID: uuid.NewString(), Address: "resident@example.com"}
	if err := dst.EnsureAccount(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.DB.Exec(`INSERT INTO mailbox_passkeys(account,credential_id,credential,name,host) VALUES($1,'other','{}','Phone','mail.example.com')`, other.ID); err != nil {
		t.Fatal(err)
	}
	before, err := src.Folders(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}

	var steps []string
	r, err := MoveAccount(ctx, src, dst, "Mover@Example.com", func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("move: %v (%v)", err, steps)
	}
	if r.Messages != 3 || r.Bodies != 3 || r.Folders != len(before) || r.Skipped["mailbox_shares"] != 1 {
		t.Errorf("report = %+v", r)
	}

	// Folders keep UIDVALIDITY, next UID and MODSEQ; messages their UIDs and flags.
	after, err := dst.Folders(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Folder{}
	for _, f := range after {
		byName[f.Name] = f
	}
	for _, f := range before {
		g := byName[f.Name]
		if g.Validity != f.Validity || g.Next != f.Next || g.ModSeq != f.ModSeq {
			t.Errorf("%s: %+v became %+v", f.Name, f, g)
		}
	}
	inbox := byName["INBOX"]
	byUID, err := dst.MessagesByUID(ctx, inbox.ID, []uint32{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	var uids []uint32
	for _, uid := range []uint32{1, 2, 3} {
		m, ok := byUID[uid]
		if !ok {
			continue
		}
		uids = append(uids, m.UID)
		if m.UID == 1 && !slices.ContainsFunc(m.Flags, func(f string) bool { return strings.EqualFold(f, `\Seen`) }) {
			t.Errorf("flags lost: %v", m.Flags)
		}
		raw, err := dst.Bodies.Get(ctx, m.Body, m.Size)
		if err != nil || !matchesBody(raw, m.Size, m.Checksum) {
			t.Errorf("body of %d: %v", m.UID, err)
		}
	}
	if !slices.Equal(uids, []uint32{1, 3}) || inbox.Next != 4 {
		t.Errorf("uids = %v, next %d", uids, inbox.Next)
	}
	// Search finds moved mail: its summary came along.
	var summaries int
	if err := dst.DB.QueryRow(`SELECT count(*) FROM mailbox_summaries s JOIN mailbox_messages m ON m.body=s.body JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1`, a.ID).Scan(&summaries); err != nil || summaries != 3 {
		t.Errorf("summaries = %d %v", summaries, err)
	}
	// Settings, and a session signed in with a passkey that now has a new ID.
	var script string
	var protocolsOff []string
	if err := dst.DB.QueryRow(`SELECT script FROM mailbox_sieve_scripts WHERE account=$1`, a.ID).Scan(&script); err != nil || script != "keep;" {
		t.Errorf("filter: %q %v", script, err)
	}
	if err := dst.DB.QueryRow(`SELECT protocols_off FROM mailbox_security WHERE account=$1`, a.ID).Scan(pq.Array(&protocolsOff)); err != nil || !slices.Equal(protocolsOff, []string{"pop3"}) {
		t.Errorf("security: %v %v", protocolsOff, err)
	}
	var sessionKey, passkey string
	if err := dst.DB.QueryRow(`SELECT t.passkey::text, p.id::text FROM mailbox_session_tokens t JOIN mailbox_passkeys p ON p.id=t.passkey WHERE t.account=$1 AND p.account=$1`, a.ID).Scan(&sessionKey, &passkey); err != nil || sessionKey != passkey {
		t.Errorf("session's passkey: %s %s %v", sessionKey, passkey, err)
	}
	// Deliveries already received are still recognised as duplicates.
	if res, err := dst.Append(ctx, a.ID, "INBOX", []byte("From: x@example.com\r\nSubject: one\r\n\r\nbody one\r\n"), nil, time.Now(), "tok-one"); err != nil || !res.Duplicate {
		t.Errorf("a retried delivery: %+v %v", res, err)
	}
	// New mail in the new cell continues the UIDs.
	if res, err := dst.Append(ctx, a.ID, "INBOX", []byte("Subject: new\r\n\r\nnew\r\n"), nil, time.Now(), ""); err != nil || res.UID != 4 || res.Validity != inbox.Validity {
		t.Errorf("new mail: %+v %v", res, err)
	}

	// The source is frozen, and a second move refuses to overwrite.
	if _, err := src.Append(ctx, a.ID, "INBOX", []byte("Subject: late\r\n\r\nx\r\n"), nil, time.Now(), ""); !errors.Is(err, ErrReadOnly) {
		t.Errorf("the source took mail after the move: %v", err)
	}
	if _, err := MoveAccount(ctx, src, dst, a.Address, nil); !errors.Is(err, errMoveTarget) {
		t.Errorf("moving onto a live copy: %v", err)
	}
	// An unfinished copy (read-only in the destination) is cleared and redone.
	if _, err := dst.DB.Exec(`UPDATE mailbox_accounts SET writable=false WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.DB.Exec(`DELETE FROM mailbox_messages WHERE uid=3 AND folder=$1`, inbox.ID); err != nil {
		t.Fatal(err)
	}
	r, err = MoveAccount(ctx, src, dst, a.Address, nil)
	if err != nil || r.Messages != 3 {
		t.Fatalf("redo: %+v %v", r, err)
	}
}

// What is scheduled or snoozed moves with the account, and from the moment
// the source is read-only only the destination acts on it.
func TestMoveAccountCarriesScheduledAndSnoozed(t *testing.T) {
	ctx := context.Background()
	src, dst := cellEngine(t, false), cellEngine(t, true)
	a := Account{ID: uuid.NewString(), Address: "later@example.com"}
	if err := src.EnsureAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	sendAt := time.Now().Add(-time.Second).Truncate(time.Millisecond)
	if _, err := src.ScheduleSend(ctx, a.ID, []byte("Subject: s\r\n\r\ns\r\n"), a.Address, []string{"x@example.net"}, sendAt); err != nil {
		t.Fatal(err)
	}
	res, err := src.Append(ctx, a.ID, "INBOX", []byte("Subject: z\r\n\r\nz\r\n"), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(-time.Second).Truncate(time.Millisecond)
	if _, err := src.Snooze(ctx, a.ID, "INBOX", []uint32{res.UID}, until); err != nil {
		t.Fatal(err)
	}
	r, err := MoveAccount(ctx, src, dst, a.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rows["mailbox_scheduled_sends"] != 1 || r.Rows["mailbox_snoozes"] != 1 {
		t.Errorf("rows moved: %v", r.Rows)
	}
	sends, err := dst.ScheduledSends(ctx, a.ID)
	if err != nil || len(sends) != 1 || !sends[0].SendAt.Equal(sendAt) || sends[0].From != a.Address {
		t.Fatalf("scheduled in the destination: %+v, %v", sends, err)
	}
	snoozes, err := dst.Snoozes(ctx, a.ID)
	if err != nil || len(snoozes) != 1 || snoozes[0].ReturnTo != "INBOX" || !snoozes[0].Until.Equal(until) {
		t.Fatalf("snoozed in the destination: %+v, %v", snoozes, err)
	}
	// Both are due. The read-only source claims neither; the destination
	// claims both.
	if d, err := src.claimDueSends(ctx); err != nil || len(d) != 0 {
		t.Errorf("the source claimed sends %v (%v)", d, err)
	}
	if d, err := src.claimDueSnoozes(ctx); err != nil || len(d) != 0 {
		t.Errorf("the source claimed snoozes %v (%v)", d, err)
	}
	if d, err := dst.claimDueSends(ctx); err != nil || len(d) != 1 || d[0].folder != scheduledFolder {
		t.Errorf("the destination claimed sends %+v (%v)", d, err)
	}
	if d, err := dst.claimDueSnoozes(ctx); err != nil || len(d) != 1 || d[0].folder != snoozedFolder {
		t.Errorf("the destination claimed snoozes %+v (%v)", d, err)
	}
}
