package mailbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// restoreRig is a live account and a backup of it: a second database holding
// the metadata as it stood, and a directory of bodies exported from the store,
// which is what the backup script hands the restore command.
type restoreRig struct {
	e      *Engine
	a      Account
	source *sql.DB
	bodies *FileBodies
}

const restoreMessageFormat = "From: a@example.com\r\nSubject: %s\r\n\r\nbody %s\r\n"

func newRestoreRig(t *testing.T, e *Engine, a Account) *restoreRig {
	t.Helper()
	ctx := context.Background()
	name := "restore_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := e.DB.ExecContext(ctx, `CREATE DATABASE `+pq.QuoteIdentifier(name)); err != nil {
		t.Fatal(err)
	}
	dsn, err := withDatabase(os.Getenv("ELEMTA_TEST_MAILBOX_DSN"), name)
	if err != nil {
		t.Fatal(err)
	}
	source, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		_, _ = e.DB.ExecContext(context.Background(), `DROP DATABASE `+pq.QuoteIdentifier(name)+` WITH (FORCE)`)
	})
	for _, q := range []string{
		`CREATE TABLE mailbox_accounts(id TEXT, address TEXT)`,
		`CREATE TABLE mailbox_folders(id BIGINT, account TEXT, name TEXT)`,
		`CREATE TABLE mailbox_bodies(key TEXT, size BIGINT, checksum TEXT)`,
		`CREATE TABLE mailbox_messages(folder BIGINT, uid BIGINT, body TEXT, flags TEXT[], internal_date TIMESTAMPTZ)`,
	} {
		if _, err := source.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return &restoreRig{e: e, a: a, source: source}
}

// snapshot takes the backup, as mailbox-backup.sh does.
func (r *restoreRig) snapshot(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := r.source.ExecContext(ctx, `INSERT INTO mailbox_accounts VALUES($1,$2)`, r.a.ID, r.a.Address); err != nil {
		t.Fatal(err)
	}
	folders, err := r.e.Folders(ctx, r.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range folders {
		if _, err := r.source.ExecContext(ctx, `INSERT INTO mailbox_folders VALUES($1,$2,$3)`, f.ID, r.a.ID, f.Name); err != nil {
			t.Fatal(err)
		}
		_, messages, err := r.e.Snapshot(ctx, r.a.ID, f.Name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			if _, err := r.source.ExecContext(ctx, `INSERT INTO mailbox_bodies VALUES($1,$2,$3)`, m.Body, m.Size, m.Checksum); err != nil {
				t.Fatal(err)
			}
			if _, err := r.source.ExecContext(ctx, `INSERT INTO mailbox_messages VALUES($1,$2,$3,$4,$5)`, f.ID, m.UID, m.Body, pq.Array(m.Flags), m.Date); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := t.TempDir()
	var archive bytes.Buffer
	if _, err := r.e.ExportBodies(ctx, &archive, nil); err != nil {
		t.Fatal(err)
	}
	zipped, err := gzip.NewReader(&archive)
	if err != nil {
		t.Fatal(err)
	}
	files := tar.NewReader(zipped)
	for {
		h, err := files.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(files)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, h.Name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if r.bodies, err = NewFileBodies(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.bodies.Close() })
}

func (r *restoreRig) restore(t *testing.T, q RestoreRequest) RestoreReport {
	t.Helper()
	q.Source, q.Bodies, q.Address, q.Label = r.source, r.bodies, r.a.Address, "2026-10-31"
	report, err := r.e.RestoreAccount(context.Background(), q, nil)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func (r *restoreRig) subjects(t *testing.T, folder string) []string {
	t.Helper()
	ctx := context.Background()
	_, messages, err := r.e.Snapshot(ctx, r.a.ID, folder)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range messages {
		raw, err := r.e.Read(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.Split(strings.Split(string(raw), "Subject: ")[1], "\r\n")[0])
	}
	return out
}

func appendMessage(t *testing.T, e *Engine, a Account, folder, subject string, flags ...string) uint32 {
	t.Helper()
	raw := fmt.Sprintf(restoreMessageFormat, subject, subject)
	r, err := e.Append(context.Background(), a.ID, folder, []byte(raw), flags, time.Date(2026, 5, 4, 3, 2, 1, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	return r.UID
}

const restoredInbox = "Restored 2026-10-31/INBOX"

// A mailbox that lost one message gets that one back, beside what it has, and
// running the restore again changes nothing.
func TestRestoreBringsBackOnlyWhatIsGone(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	appendMessage(t, e, a, "INBOX", "kept")
	lost := appendMessage(t, e, a, "INBOX", "lost", `\Seen`, `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{lost}); err != nil {
		t.Fatal(err)
	}

	got := r.restore(t, RestoreRequest{})
	if got.Restored != 1 || got.Present != 1 || !got.Complete() {
		t.Fatalf("report %+v", got)
	}
	if s := r.subjects(t, restoredInbox); len(s) != 1 || s[0] != "lost" {
		t.Fatalf("restored %v", s)
	}
	if s := r.subjects(t, "INBOX"); len(s) != 1 || s[0] != "kept" {
		t.Fatalf("the live folder changed: %v", s)
	}
	_, messages, err := e.Snapshot(ctx, a.ID, restoredInbox)
	if err != nil {
		t.Fatal(err)
	}
	m := messages[0]
	if !m.Date.Equal(time.Date(2026, 5, 4, 3, 2, 1, 0, time.UTC)) {
		t.Fatalf("date %v", m.Date)
	}
	if len(m.Flags) != 1 || !strings.EqualFold(m.Flags[0], `\Seen`) {
		t.Fatalf("flags %v: \\Deleted must not come back", m.Flags)
	}

	again := r.restore(t, RestoreRequest{})
	if again.Restored != 0 || again.Repeated != 1 {
		t.Fatalf("second run %+v", again)
	}
	if dry := r.restore(t, RestoreRequest{DryRun: true}); dry.Restored != 0 || dry.Repeated != 1 {
		t.Fatalf("a dry run must count what is already back: %+v", dry)
	}
	if s := r.subjects(t, restoredInbox); len(s) != 1 {
		t.Fatalf("second run duplicated: %v", s)
	}
}

// Filing a message elsewhere since the backup isn't losing it.
func TestRestoreLeavesMovedMailAlone(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	if err := e.Create(ctx, a.ID, "Work"); err != nil {
		t.Fatal(err)
	}
	uid := appendMessage(t, e, a, "INBOX", "moved")
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Work", []uint32{uid}, true); err != nil {
		t.Fatal(err)
	}
	got := r.restore(t, RestoreRequest{})
	if got.Restored != 0 || got.Present != 1 {
		t.Fatalf("report %+v", got)
	}
	if _, err := e.Folder(ctx, a.ID, "Restored 2026-10-31"); err == nil {
		t.Fatal("a restore with nothing to do created a folder")
	}
}

func TestRestoreDryRunWritesNothing(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	uid := appendMessage(t, e, a, "INBOX", "lost", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{uid}); err != nil {
		t.Fatal(err)
	}
	got := r.restore(t, RestoreRequest{DryRun: true})
	if got.Restored != 1 || got.Bytes == 0 {
		t.Fatalf("report %+v", got)
	}
	if _, err := e.Folder(ctx, a.ID, restoredInbox); err == nil {
		t.Fatal("a dry run created a folder")
	}
}

// Webmail's data folders and Junk stay out unless asked for, and a mistyped
// folder is an error rather than an empty success.
func TestRestoreFolderSelection(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	for _, f := range []string{"Calendar", "Junk", "Work"} {
		if err := e.Create(ctx, a.ID, f); err != nil {
			t.Fatal(err)
		}
		appendMessage(t, e, a, f, "in "+f)
	}
	r := newRestoreRig(t, e, a)
	r.snapshot(t)

	got := r.restore(t, RestoreRequest{All: true})
	if got.Restored != 1 || strings.Join(got.LeftOut, ",") != "Calendar,Junk" {
		t.Fatalf("report %+v", got)
	}
	if got := r.restore(t, RestoreRequest{All: true, Folders: []string{"Junk"}}); got.Restored != 1 {
		t.Fatalf("named folder: %+v", got)
	}
	_, err := e.RestoreAccount(ctx, RestoreRequest{Source: r.source, Bodies: r.bodies, Address: a.Address, Label: "x", Folders: []string{"Wrok"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "Wrok") {
		t.Fatalf("mistyped folder: %v", err)
	}
}

// Running out of quota stops the restore and says so, and raising it carries on.
func TestRestoreStopsAtQuotaAndCarriesOn(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	var uids []uint32
	for i := range 3 {
		uids = append(uids, appendMessage(t, e, a, "INBOX", fmt.Sprintf("m%d", i), `\Deleted`))
	}
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "INBOX", uids); err != nil {
		t.Fatal(err)
	}
	size := int64(len(fmt.Sprintf(restoreMessageFormat, "m0", "m0")))
	if _, err := e.DB.ExecContext(ctx, `UPDATE mailbox_accounts SET quota_bytes=$2 WHERE id=$1`, a.ID, size*2); err != nil {
		t.Fatal(err)
	}
	first := r.restore(t, RestoreRequest{})
	if first.Restored != 2 || !first.QuotaFull || first.Complete() {
		t.Fatalf("first %+v", first)
	}
	if _, err := e.DB.ExecContext(ctx, `UPDATE mailbox_accounts SET quota_bytes=0 WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	second := r.restore(t, RestoreRequest{})
	if second.Restored != 1 || second.Repeated != 2 || !second.Complete() {
		t.Fatalf("second %+v", second)
	}
}

// A body in neither the backup nor the store is reported, and the rest of the
// mailbox still comes back. The store is the fallback for a backup without it.
func TestRestoreReportsUnreadableAndUsesLiveStore(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	gone := appendMessage(t, e, a, "INBOX", "gone", `\Deleted`)
	live := appendMessage(t, e, a, "INBOX", "live")
	whole := appendMessage(t, e, a, "INBOX", "whole", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range messages {
		// "gone" is lost from both, "live" only from the backup.
		if m.UID == gone || m.UID == live {
			if err := r.bodies.Delete(ctx, m.Body); err != nil {
				t.Fatal(err)
			}
		}
		if m.UID == gone {
			if err := e.Bodies.Delete(ctx, m.Body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{gone, whole}); err != nil {
		t.Fatal(err)
	}
	got := r.restore(t, RestoreRequest{All: true})
	if got.Restored != 2 || len(got.Unreadable) != 1 || got.Complete() {
		t.Fatalf("report %+v", got)
	}
	if !strings.Contains(got.Unreadable[0], fmt.Sprintf("INBOX uid %d", gone)) {
		t.Fatalf("unreadable %v", got.Unreadable)
	}
}

// A backup of an encrypted store is bodies as stored: unreadable without the
// key, and readable with it, and restored mail is sealed under the current key.
func TestRestoreFromEncryptedStore(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	plain := e.Bodies
	e.Bodies = &encryptedBodies{BodyStore: plain, keys: testBodyKeys(t, "v1:"+b64(1))}
	uid := appendMessage(t, e, a, "INBOX", "secret", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := r.bodies.Get(ctx, messages[0].Body, messages[0].Size+bodyOverhead)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("secret")) {
		t.Fatal("the export holds plaintext")
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{uid}); err != nil {
		t.Fatal(err)
	}
	if got := r.restore(t, RestoreRequest{}); got.Restored != 1 || !got.Complete() {
		t.Fatalf("report %+v", got)
	}
	if s := r.subjects(t, restoredInbox); len(s) != 1 || s[0] != "secret" {
		t.Fatalf("restored %v", s)
	}
}

func TestRestoreNeedsTheAccountAndAudits(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	uid := appendMessage(t, e, a, "INBOX", "lost", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	_, err := e.RestoreAccount(ctx, RestoreRequest{Source: r.source, Bodies: r.bodies, Address: "nobody-" + a.Address, Label: "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("missing account: %v", err)
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{uid}); err != nil {
		t.Fatal(err)
	}
	r.restore(t, RestoreRequest{Actor: "alan"})
	var n int
	if err := e.DB.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_audit WHERE action='mailbox-restore' AND target=$1 AND actor='alan'`, strings.ToLower(a.Address)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d audit entries", n)
	}
}

func appendObject(t *testing.T, e *Engine, a Account, folder, id, title string, flags ...string) uint32 {
	t.Helper()
	if err := e.Create(context.Background(), a.ID, folder); err != nil && err != ErrExists {
		t.Fatal(err)
	}
	raw := fmt.Sprintf("X-Elemta-Object: %s\r\nSubject: %s\r\n\r\nversion of %s\r\n", id, title, title)
	r, err := e.Append(context.Background(), a.ID, folder, []byte(raw), flags, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	return r.UID
}

// Items return to the folder webmail reads them from, by ID, and an item the
// account still has keeps its current version.
func TestRestoreDataGoesBackInPlaceWithoutOverwriting(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	deleted := appendObject(t, e, a, "Calendar", "event-1", "deleted event", `\Deleted`)
	edited := appendObject(t, e, a, "Calendar", "event-2", "before the edit", `\Deleted`)
	contact := appendObject(t, e, a, "Contacts", "person-1", "contact", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "Calendar", []uint32{deleted, edited}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Expunge(ctx, a.ID, "Contacts", []uint32{contact}); err != nil {
		t.Fatal(err)
	}
	appendObject(t, e, a, "Calendar", "event-2", "after the edit")

	if got := r.restore(t, RestoreRequest{}); got.Objects != 0 || got.Restored != 0 {
		t.Fatalf("data came back unasked: %+v", got)
	}
	if got := r.restore(t, RestoreRequest{Data: true, DryRun: true}); got.Objects != 2 || got.ObjectsPresent != 1 {
		t.Fatalf("dry run %+v", got)
	}
	if s := r.subjects(t, "Calendar"); len(s) != 1 {
		t.Fatalf("the dry run wrote: %v", s)
	}
	got := r.restore(t, RestoreRequest{Data: true})
	if got.Objects != 2 || got.ObjectsPresent != 1 || !got.Complete() {
		t.Fatalf("report %+v", got)
	}
	if s := strings.Join(r.subjects(t, "Calendar"), ","); s != "after the edit,deleted event" {
		t.Fatalf("calendar holds %s", s)
	}
	if s := r.subjects(t, "Contacts"); len(s) != 1 {
		t.Fatalf("contacts hold %v", s)
	}
	if _, err := e.Folder(ctx, a.ID, "Restored 2026-10-31/Calendar"); err == nil {
		t.Fatal("an object went to the Restored folder")
	}
	again := r.restore(t, RestoreRequest{Data: true})
	if again.Objects != 0 || again.ObjectsPresent != 3 {
		t.Fatalf("second run %+v", again)
	}
}

// An edit that hadn't been expunged leaves two messages with one ID, and the
// newer is the item.
func TestRestoreDataTakesTheNewestVersion(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	old := appendObject(t, e, a, "Tasks", "task-1", "old", `\Deleted`)
	newer := appendObject(t, e, a, "Tasks", "task-1", "new", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "Tasks", []uint32{old, newer}); err != nil {
		t.Fatal(err)
	}
	if got := r.restore(t, RestoreRequest{Folders: []string{"Tasks"}}); got.Objects != 1 {
		t.Fatalf("report %+v", got)
	}
	if s := r.subjects(t, "Tasks"); len(s) != 1 || s[0] != "new" {
		t.Fatalf("tasks hold %v", s)
	}
}

// With objects in their own database the hidden folders are stale, and writing
// to them would do nothing but look like a restore.
func TestRestoreLeavesFoldersAloneWhenObjectsAreElsewhere(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	uid := appendObject(t, e, a, "Calendar", "event-1", "stale", `\Deleted`)
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	if _, err := e.Expunge(ctx, a.ID, "Calendar", []uint32{uid}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []RestoreRequest{{Data: true, ObjectsElsewhere: true}, {Folders: []string{"Calendar"}, ObjectsElsewhere: true}} {
		if got := r.restore(t, q); got.Objects != 0 {
			t.Fatalf("report %+v", got)
		}
	}
}

// Filters return switched off, a changed one comes back beside the live one,
// and a sender rule changed since the backup stays as it is now.
func TestRestoreFiltersAndSenderRules(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	for name, script := range map[string]string{"gone": "keep;", "changed": "stop;", "same": "keep;"} {
		if err := e.PutScript(ctx, a.ID, name, script, 10); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.SetActive(ctx, a.ID, "gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetSenderRules(ctx, a.ID, []string{"friend@example.com", "flip@example.com"}, nil, 10); err != nil {
		t.Fatal(err)
	}
	r := newRestoreRig(t, e, a)
	for _, q := range []string{
		`CREATE TABLE mailbox_sieve_scripts AS SELECT '` + a.ID + `'::text AS account, * FROM (VALUES ('gone','keep;'),('changed','stop;'),('same','keep;')) v(name,script)`,
		`CREATE TABLE mailbox_sender_rules AS SELECT '` + a.ID + `'::text AS account, * FROM (VALUES ('friend@example.com','allow'),('flip@example.com','allow')) v(entry,kind)`,
	} {
		if _, err := r.source.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	r.snapshot(t)
	if _, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_sieve_scripts WHERE account=$1 AND name='gone'`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.PutScript(ctx, a.ID, "changed", "discard;", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetSenderRules(ctx, a.ID, nil, []string{"flip@example.com"}, 10); err != nil {
		t.Fatal(err)
	}

	got := r.restore(t, RestoreRequest{Data: true})
	if got.Filters != 2 || got.SenderRules != 1 {
		t.Fatalf("report %+v", got)
	}
	gone, err := e.Script(ctx, a.ID, "gone")
	if err != nil || gone.Active {
		t.Fatalf("restored filter %+v %v: it must come back switched off", gone, err)
	}
	if s, err := e.Script(ctx, a.ID, "changed"); err != nil || s.Script != "discard;" {
		t.Fatalf("live filter overwritten: %+v %v", s, err)
	}
	if s, err := e.Script(ctx, a.ID, "changed-restored-2026-10-31"); err != nil || s.Script != "stop;" {
		t.Fatalf("backup's version: %+v %v", s, err)
	}
	rules, err := e.SenderRules(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rules.Allow, ",") != "friend@example.com" || strings.Join(rules.Block, ",") != "flip@example.com" {
		t.Fatalf("rules %+v", rules)
	}
	if again := r.restore(t, RestoreRequest{Data: true}); again.Filters != 0 || again.SenderRules != 0 {
		t.Fatalf("second run %+v", again)
	}
}

func TestWithDatabase(t *testing.T) {
	got, err := withDatabase("postgres://u:p@db:5432/mailbox?sslmode=require", "other")
	if err != nil || got != "postgres://u:p@db:5432/other?sslmode=require" {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := withDatabase("host=db dbname=mailbox", "other"); got != "host=db dbname=mailbox dbname=other" {
		t.Fatal(got)
	}
}
