package mailbox

// Restoring one account from a backup, while everyone else keeps working.
//
// A full restore replaces the store, so it can't answer "I deleted a folder
// last week". This puts one account's lost mail back beside what it has now,
// and never touches a message the account still holds: everything lands under
// a "Restored <label>" folder, because the person asking is the only one who
// can say whether a restored message should replace anything.
//
// Calendars, contacts, tasks and settings are different. Webmail keeps each
// one as a message in a hidden folder, identified by a header rather than by
// anything a person can see, so a copy elsewhere would be useless. With Data
// they go back in their own folders, but only those missing by ID: what is
// there now is newer, or was changed on purpose. Because this writes into live
// calendars, and could return an event someone deleted on purpose, it has to be
// asked for. Filters and sender rules come back the same way. Shares, app
// passwords and two-step settings never do: bringing access back could undo a
// revocation, which is not something a restore should do unasked.
//
// Mail goes back through Append rather than by copying rows. Body keys, UIDs
// and modification sequences belong to the store they were issued by, and
// Append already gets quota, the change journal, the search summary and
// encryption under the current key right.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/lib/pq"
)

// restoreFolderPrefix starts the top folder that restored mail lands under.
const restoreFolderPrefix = "Restored "

// objectHeader carries an object's ID (internal/webmail, objects.go).
const objectHeader = "X-Elemta-Object"

// RestoreRequest says what to restore, and from where.
type RestoreRequest struct {
	// Source is the backup's metadata, opened read-only in spirit: restoring
	// only ever selects from it.
	Source *sql.DB
	// Bodies holds the backup's copies, as they were stored. The live store
	// is tried after it, so a backup taken without bodies still restores
	// whatever cleanup hasn't removed yet.
	Bodies  BodyStore
	Address string
	// Label names the target folder, normally the backup's date.
	Label string
	// Folders limits the restore to these source folders. Empty means every
	// mail folder, which leaves out Junk and quarantine, plus webmail's data
	// unless Data is set. Naming a data folder restores it as Data would.
	Folders []string
	// Data also restores calendars, contacts, tasks, settings, filters and
	// sender rules.
	Data bool
	// ObjectsElsewhere says webmail keeps its objects in its own database,
	// so the hidden folders hold stale copies that must not come back here.
	// scripts/mailbox-restore-account.sh restores that database itself.
	ObjectsElsewhere bool
	// All restores messages the account still has, too. Off, only mail that
	// is gone comes back.
	All bool
	// DryRun reads every body it would restore and writes nothing.
	DryRun bool
	// Actor is recorded in the audit log.
	Actor string
}

// RestoreReport says what happened, message by message class.
type RestoreReport struct {
	// Target is the folder restored mail went under.
	Target string
	// Restored is messages written, or that would be on a dry run.
	Restored int
	// Bytes is their size.
	Bytes int64
	// Present is messages skipped because the account still has them.
	Present int
	// Repeated is messages an earlier run of this restore already put back.
	Repeated int
	// Objects is calendar, contact, task and settings items restored, and
	// ObjectsPresent those skipped because the account still has them.
	Objects, ObjectsPresent int
	// Filters is filter scripts restored, always switched off, and
	// SenderRules allowed or blocked senders restored.
	Filters, SenderRules int
	// Unreadable lists messages that couldn't be restored, with the reason.
	Unreadable []string
	// LeftOut lists source folders passed over by default.
	LeftOut []string
	// QuotaFull is set when the account ran out of quota and the restore
	// stopped there. Running it again after raising the quota carries on.
	QuotaFull bool
	// Free is the account's quota remaining before the restore, -1 if it has
	// no limit.
	Free int64
}

// Complete reports whether everything asked for came back.
func (r RestoreReport) Complete() bool { return len(r.Unreadable) == 0 && !r.QuotaFull }

// restoreMessage is one message as the backup recorded it.
type restoreMessage struct {
	uid      int64
	body     string
	size     int64
	checksum string
	flags    []string
	date     time.Time
}

// RestoreAccount puts an account's mail back from a backup. It is safe to run
// again: a message already restored into the same folder is not repeated, so
// a run stopped by quota or a crash carries on where it left off.
func (e *Engine) RestoreAccount(ctx context.Context, q RestoreRequest, progress func(done int)) (RestoreReport, error) {
	var r RestoreReport
	if q.Source == nil || q.Address == "" || q.Label == "" {
		return r, errors.New("restore needs a source, an address and a label")
	}
	r.Target = restoreFolderPrefix + q.Label
	if !validMailbox(r.Target) {
		return r, errors.New("invalid restore label")
	}
	account, err := e.restoreAccount(ctx, q.Address)
	if err != nil {
		return r, err
	}
	var source string
	// By identity first: an address can leave and return as a new account,
	// and an account can change address, and in both cases the person asking
	// means the mail of this address.
	err = q.Source.QueryRowContext(ctx, `SELECT id FROM mailbox_accounts WHERE id=$1 OR lower(address)=$2 ORDER BY id=$1 DESC LIMIT 1`, account, strings.ToLower(q.Address)).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("the backup has no account %s", q.Address)
	}
	if err != nil {
		return r, err
	}
	var quota, used, pending int64
	if err = e.DB.QueryRowContext(ctx, `SELECT quota_bytes,used_bytes,reserved_bytes FROM mailbox_accounts WHERE id=$1`, account).Scan(&quota, &used, &pending); err != nil {
		return r, err
	}
	r.Free = -1
	if quota > 0 {
		r.Free = max(quota-used-pending, 0)
	}
	folders, err := restoreFolders(ctx, q, source, &r)
	if err != nil {
		return r, err
	}
	bodies := e.keyed(q.Bodies)
	// put writes one message, and reports whether the restore must stop.
	put := func(f restoreSource, target string, m restoreMessage, raw []byte, token string, count *int) (bool, error) {
		if !q.DryRun {
			_, err := e.Append(ctx, account, target, raw, restoredFlags(m.flags), m.date, token)
			switch {
			case errors.Is(err, ErrQuota):
				r.QuotaFull = true
				return true, nil
			case errors.Is(err, ErrTooLarge):
				r.Unreadable = append(r.Unreadable, fmt.Sprintf("%s uid %d: larger than the message size limit", f.name, m.uid))
				return false, nil
			case err != nil:
				return true, err
			}
		}
		*count++
		r.Bytes += int64(len(raw))
		return false, nil
	}
	done := 0
	for _, f := range folders {
		messages, err := restoreMessages(ctx, q.Source, f.id)
		if err != nil {
			return r, err
		}
		if retentionDataFolder(f.name) {
			stop, err := e.restoreObjects(ctx, q, &r, account, f, messages, bodies, put)
			if stop || err != nil {
				return r, errors.Join(err, e.auditRestore(ctx, q, r))
			}
			continue
		}
		target := r.Target + "/" + f.name
		// Created on the first message that needs it, so that a restore with
		// nothing to do leaves nothing behind.
		var validity uint32
		for _, m := range messages {
			if err = ctx.Err(); err != nil {
				return r, err
			}
			done++
			if progress != nil && done%1000 == 0 {
				progress(done)
			}
			if !q.All {
				present, err := e.accountHasBody(ctx, account, m.body)
				if err != nil {
					return r, err
				}
				if present {
					r.Present++
					continue
				}
			}
			if validity == 0 {
				if validity, err = e.restoreFolderFor(ctx, q, account, r.Target, target); err != nil {
					return r, err
				}
			}
			token, repeated, err := e.restoreToken(ctx, account, validity, m.body)
			if err != nil {
				return r, err
			}
			if repeated {
				r.Repeated++
				continue
			}
			raw, err := e.restoreBody(ctx, bodies, m)
			if err != nil {
				if ctx.Err() != nil {
					return r, ctx.Err()
				}
				r.Unreadable = append(r.Unreadable, fmt.Sprintf("%s uid %d: %v", f.name, m.uid, err))
				continue
			}
			stop, err := put(f, target, m, raw, token, &r.Restored)
			if stop || err != nil {
				return r, errors.Join(err, e.auditRestore(ctx, q, r))
			}
		}
	}
	if q.Data {
		if err := e.restoreSettings(ctx, q, &r, account, source); err != nil {
			return r, errors.Join(err, e.auditRestore(ctx, q, r))
		}
	}
	return r, e.auditRestore(ctx, q, r)
}

// restoreObjects puts back the items of one data folder that the account no
// longer has. It reads everything both ways because an item's identity is in
// its headers, and these folders are small.
func (e *Engine) restoreObjects(ctx context.Context, q RestoreRequest, r *RestoreReport, account string, f restoreSource, messages []restoreMessage, bodies BodyStore,
	put func(restoreSource, string, restoreMessage, []byte, string, *int) (bool, error)) (bool, error) {
	live := map[string]bool{}
	_, current, err := e.Snapshot(ctx, account, f.name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return true, err
	}
	for _, m := range current {
		raw, err := e.Read(ctx, m)
		if err != nil {
			// Guessing here could duplicate an item the account has.
			return true, fmt.Errorf("reading %s uid %d: %w", f.name, m.UID, err)
		}
		live[objectIDOf(raw)] = true
	}
	var validity uint32
	seen := map[string]bool{}
	// Newest first: an edit is a new message, and a backup can catch the old
	// one not yet expunged.
	for i := len(messages) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		m := messages[i]
		raw, err := e.restoreBody(ctx, bodies, m)
		if err != nil {
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			r.Unreadable = append(r.Unreadable, fmt.Sprintf("%s uid %d: %v", f.name, m.uid, err))
			continue
		}
		id := objectIDOf(raw)
		if id == "" {
			// Not an object: a message someone filed here from a mail app.
			// Webmail ignores those, so nothing depends on bringing it back.
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if live[id] {
			r.ObjectsPresent++
			continue
		}
		if validity == 0 {
			if validity, err = e.restoreFolderFor(ctx, q, account, "", f.name); err != nil {
				return true, err
			}
		}
		token, repeated, err := e.restoreToken(ctx, account, validity, m.body)
		if err != nil {
			return true, err
		}
		if repeated {
			r.Repeated++
			continue
		}
		if stop, err := put(f, f.name, m, raw, token, &r.Objects); stop || err != nil {
			return true, err
		}
	}
	return false, nil
}

// objectIDOf returns a stored object's ID, empty for anything else.
func objectIDOf(raw []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(m.Header.Get(objectHeader))
}

// restoreSettings brings back filters and sender rules. These tables are newer
// than some backups, and a backup without them simply has none to give.
func (e *Engine) restoreSettings(ctx context.Context, q RestoreRequest, r *RestoreReport, account, source string) error {
	var hasScripts, hasRules bool
	if err := q.Source.QueryRowContext(ctx, `SELECT to_regclass('mailbox_sieve_scripts') IS NOT NULL, to_regclass('mailbox_sender_rules') IS NOT NULL`).Scan(&hasScripts, &hasRules); err != nil {
		return err
	}
	if hasScripts {
		if err := e.restoreFilters(ctx, q, r, account, source); err != nil {
			return err
		}
	}
	if !hasRules {
		return nil
	}
	rows, err := q.Source.QueryContext(ctx, `SELECT entry,kind FROM mailbox_sender_rules WHERE account=$1 ORDER BY entry`, source)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var entry, kind string
		if err := rows.Scan(&entry, &kind); err != nil {
			return err
		}
		// A rule the account has now keeps its current kind: unblocking a
		// sender since the backup was a decision.
		var present bool
		if err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_sender_rules WHERE account=$1 AND entry=$2)`, account, entry).Scan(&present); err != nil {
			return err
		}
		if present {
			continue
		}
		if !q.DryRun {
			if _, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_sender_rules(account,entry,kind) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, account, entry, kind); err != nil {
				return err
			}
		}
		r.SenderRules++
	}
	return rows.Err()
}

// restoreFilters restores scripts switched off, since a filter can move or
// reject mail and the account's filtering may have changed since. One whose
// name is taken by different text comes back beside it under a new name, so
// that neither version is lost.
func (e *Engine) restoreFilters(ctx context.Context, q RestoreRequest, r *RestoreReport, account, source string) error {
	rows, err := q.Source.QueryContext(ctx, `SELECT name,script FROM mailbox_sieve_scripts WHERE account=$1 ORDER BY name`, source)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, script string
		if err := rows.Scan(&name, &script); err != nil {
			return err
		}
		for _, candidate := range []string{name, name + "-restored-" + q.Label} {
			current, err := e.Script(ctx, account, candidate)
			if err == nil && current.Script == script {
				break
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil {
				continue
			}
			if !q.DryRun {
				// An operator's restore isn't held to the per-user limit.
				if err := e.PutScript(ctx, account, candidate, script, math.MaxInt32); err != nil {
					return err
				}
			}
			r.Filters++
			break
		}
	}
	return rows.Err()
}

// restoreAccount finds the live account. It won't create one: an address that
// has no account now may have been removed on purpose, and the directory
// decides who exists.
func (e *Engine) restoreAccount(ctx context.Context, address string) (string, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT id FROM mailbox_accounts WHERE lower(address)=$1 ORDER BY id LIMIT 2`, strings.ToLower(address))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no account %s: create it and sign in once, then restore", address)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("more than one account has the address %s", address)
}

type restoreSource struct {
	id   int64
	name string
}

// restoreFolders chooses the source folders. A folder named on the command
// line that the backup doesn't have is an error, not an empty result: a typo
// must not look like there was nothing to restore.
func restoreFolders(ctx context.Context, q RestoreRequest, account string, r *RestoreReport) ([]restoreSource, error) {
	rows, err := q.Source.QueryContext(ctx, `SELECT id,name FROM mailbox_folders WHERE account=$1 ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wanted := map[string]bool{}
	for _, name := range q.Folders {
		wanted[canonicalMailbox(name)] = false
	}
	var out []restoreSource
	for rows.Next() {
		var f restoreSource
		if err := rows.Scan(&f.id, &f.name); err != nil {
			return nil, err
		}
		if q.ObjectsElsewhere && retentionDataFolder(f.name) {
			if _, ok := wanted[f.name]; ok {
				wanted[f.name] = true
			}
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[f.name]; ok {
				wanted[f.name] = true
				out = append(out, f)
			}
			continue
		}
		// Nobody wants their spam back unasked, and data has to be asked for.
		if junkFolderName(f.name) || retentionDataFolder(f.name) && !q.Data {
			r.LeftOut = append(r.LeftOut, f.name)
			continue
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for name, found := range wanted {
		if !found {
			return nil, fmt.Errorf("the backup has no folder %q for this account", name)
		}
	}
	return out, nil
}

func restoreMessages(ctx context.Context, source *sql.DB, folder int64) ([]restoreMessage, error) {
	rows, err := source.QueryContext(ctx, `SELECT m.uid,m.body,b.size,b.checksum,m.flags,m.internal_date FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body WHERE m.folder=$1 ORDER BY m.uid`, folder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restoreMessage
	for rows.Next() {
		var m restoreMessage
		if err := rows.Scan(&m.uid, &m.body, &m.size, &m.checksum, pq.Array(&m.flags), &m.date); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// accountHasBody reports whether the account still has this message in any
// folder. Moving and copying share the body, so mail filed elsewhere since
// the backup still counts as present and isn't duplicated.
func (e *Engine) accountHasBody(ctx context.Context, account, body string) (bool, error) {
	var present bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1 AND m.body=$2)`, account, body).Scan(&present)
	return present, err
}

// restoreFolderFor creates the target, and its parent if it has one, and
// returns the target's UIDVALIDITY. The parent exists so that mail apps show
// the restore as one tree rather than as a folder whose parent is missing. A
// dry run creates nothing, and gets zero if the target isn't there yet.
func (e *Engine) restoreFolderFor(ctx context.Context, q RestoreRequest, account, parent, target string) (uint32, error) {
	if q.DryRun {
		f, err := e.Folder(ctx, account, target)
		if errors.Is(err, ErrNotFound) {
			return 0, nil
		}
		return f.Validity, err
	}
	for _, name := range []string{parent, target} {
		if name == "" {
			continue
		}
		if err := e.Create(ctx, account, name); err != nil && !errors.Is(err, ErrExists) {
			return 0, err
		}
	}
	f, err := e.Folder(ctx, account, target)
	return f.Validity, err
}

// restoreToken returns the delivery token for a body going into a folder, and
// whether an earlier run already put it there. The folder's identity is in the
// token so that deleting a restored folder and asking again restores it again.
func (e *Engine) restoreToken(ctx context.Context, account string, validity uint32, body string) (string, bool, error) {
	if validity == 0 {
		return "", false, nil
	}
	token := fmt.Sprintf("restore:%d:%s", validity, body)
	var seen bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_deliveries WHERE account=$1 AND token=$2)`, account, token).Scan(&seen)
	return token, seen, err
}

func (e *Engine) restoreBody(ctx context.Context, bodies BodyStore, m restoreMessage) ([]byte, error) {
	if m.size < 0 || m.size > 100<<20 {
		return nil, ErrTooLarge
	}
	var fromBackup error
	if bodies != nil {
		raw, err := bodies.Get(ctx, m.body, m.size)
		if err == nil && matchesBody(raw, m.size, m.checksum) {
			return raw, nil
		}
		fromBackup = err
		if err == nil {
			fromBackup = errors.New("checksum mismatch")
		}
	}
	raw, err := e.Bodies.Get(ctx, m.body, m.size)
	if err == nil && !matchesBody(raw, m.size, m.checksum) {
		err = errors.New("checksum mismatch")
	}
	if err != nil {
		return nil, errors.Join(fromBackup, err)
	}
	return raw, nil
}

// keyed gives a backup's store the same body keys as the live one, since a
// backup holds bodies exactly as they were stored.
func (e *Engine) keyed(s BodyStore) BodyStore {
	if s == nil {
		return nil
	}
	if c, ok := e.Bodies.(*encryptedBodies); ok {
		return &encryptedBodies{BodyStore: s, keys: c.keys}
	}
	return s
}

// restoredFlags drops \Deleted: mail marked for removal when the backup was
// taken would otherwise vanish at the next expunge of the restored folder.
func restoredFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		if !strings.EqualFold(f, `\Deleted`) {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) auditRestore(ctx context.Context, q RestoreRequest, r RestoreReport) error {
	if q.DryRun || r.Restored+r.Objects+r.Filters+r.SenderRules == 0 {
		return nil
	}
	actor := q.Actor
	if actor == "" {
		actor = "cli"
	}
	// Restoring reads a person's mail back into their account, so it is
	// recorded like any other administrator action on a mailbox. The context
	// may be the reason the restore stopped, and the record must still land.
	audit, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, err := e.Audit(audit, mailpolicy.AuditEntry{Actor: actor, Source: "cli", Action: "mailbox-restore", Target: strings.ToLower(q.Address),
		Detail: fmt.Sprintf("%d messages into %q, %d items, %d filters, %d sender rules", r.Restored, r.Target, r.Objects, r.Filters, r.SenderRules)})
	return err
}

// BodyExport is the result of ExportBodies.
type BodyExport struct {
	Bodies int
	Bytes  int64
}

// ExportBodies writes every body a backup could refer to as a gzipped tar with
// one file per key, the layout of a file store, so that the rest of backup and
// restore needn't care where bodies live. They stay as stored, encrypted if
// the store is: the backup is no more readable than the bucket.
//
// Run it after dumping the metadata. Only ready bodies are needed: one retires
// after body_grace_hours without any message, so no dump taken moments ago can
// refer to it, and retired rows outlive their objects as tombstones.
func (e *Engine) ExportBodies(ctx context.Context, w io.Writer, progress func(done int)) (BodyExport, error) {
	var r BodyExport
	rows, err := e.DB.QueryContext(ctx, `SELECT key,size FROM mailbox_bodies WHERE state='ready' AND store=$1 ORDER BY key`, e.Bodies.Identity())
	if err != nil {
		return r, err
	}
	type entry struct {
		key  string
		size int64
	}
	var todo []entry
	for rows.Next() {
		var x entry
		if err := rows.Scan(&x.key, &x.size); err != nil {
			rows.Close()
			return r, err
		}
		todo = append(todo, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	store := e.Bodies
	if c, ok := store.(*encryptedBodies); ok {
		store = c.BodyStore
	}
	zipped := gzip.NewWriter(w)
	archive := tar.NewWriter(zipped)
	for _, x := range todo {
		data, err := store.Get(ctx, x.key, x.size+bodyOverhead)
		if err != nil {
			// Cleanup may have retired it since the query, and then nothing
			// refers to it. Any other failure is a backup missing mail.
			var state string
			if qerr := e.DB.QueryRowContext(ctx, `SELECT state FROM mailbox_bodies WHERE key=$1`, x.key).Scan(&state); qerr == nil && state != "ready" {
				continue
			}
			return r, fmt.Errorf("body %s: %w", x.key, err)
		}
		if err := archive.WriteHeader(&tar.Header{Name: x.key, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return r, err
		}
		if _, err := archive.Write(data); err != nil {
			return r, err
		}
		r.Bodies++
		r.Bytes += int64(len(data))
		if progress != nil && r.Bodies%1000 == 0 {
			progress(r.Bodies)
		}
	}
	if err := archive.Close(); err != nil {
		return r, err
	}
	return r, zipped.Close()
}

// withDatabase returns the DSN pointed at another database on the same
// server, in either form lib/pq accepts.
func withDatabase(dsn, name string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid mailbox database configuration")
		}
		u.Path = "/" + name
		return u.String(), nil
	}
	// In keyword form the last setting wins.
	return dsn + " dbname=" + name, nil
}

// OpenRestoreSource opens a database on the mailbox's own Postgres server that
// a backup's metadata was loaded into.
func (s *Service) OpenRestoreSource(ctx context.Context, name string) (*sql.DB, error) {
	dsn, err := withDatabase(s.metadataDSN(), name)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, errors.New("invalid mailbox database configuration")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("restore source database %s: %w", name, err)
	}
	return db, nil
}
