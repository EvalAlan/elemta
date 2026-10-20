// Package migrate moves users onto Elemta from another mail system: mail
// over IMAP, calendars and contacts from iCalendar and vCard exports, and
// accounts, aliases and lists from a CSV (cmd/elemta/commands/migrate.go).
//
// Everything goes into the mailbox service through its admin API
// (mailpolicy.Client.Import), so it needs no destination passwords. Every
// item is imported under a key naming where it came from, and the mailbox
// stores a key once, so a migration that stops part way (a network blip, a
// full mailbox, an operator's Ctrl-C) is finished by running it again. A
// small state file per user also remembers how far each folder got, so a
// rerun doesn't download what it already copied.
package migrate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
)

// Importer stores messages in a mailbox; mailpolicy.Client is one.
type Importer interface {
	Import(ctx context.Context, m mailpolicy.Import) (mailpolicy.ImportResult, error)
}

// Source is the IMAP server to copy from.
type Source struct {
	Addr string // host:port
	// TLS is "imaps" (implicit, usually 993), "starttls" (usually 143) or
	// "none" (only for a trusted local network).
	TLS                string
	InsecureSkipVerify bool
	// User and Password sign in as the user. With Admin set, the
	// administrator's credentials sign in on the user's behalf instead
	// (SASL PLAIN with an authorization identity), as most servers allow
	// for migrations, so users' passwords aren't needed.
	User, Password string
	Admin          string
}

// Options tune a mail migration.
type Options struct {
	// StateDir keeps per-user progress; empty keeps none (every run then
	// lists all messages, and the import keys still prevent duplicates).
	StateDir string
	// MaxBytes skips larger messages without downloading them; the mailbox
	// refuses them anyway. Zero means 100 MiB.
	MaxBytes int64
	// Exclude lists source folders not to copy.
	Exclude []string
	// Batch is how many messages are downloaded at once. Zero means 25.
	Batch int
	Log   *slog.Logger
}

// FolderReport says what happened to one folder.
type FolderReport struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Copied   int    `json:"copied"`
	Skipped  int    `json:"skipped"` // copied by an earlier run
	TooLarge int    `json:"too_large"`
	Deleted  int    `json:"deleted"` // marked \Deleted at the source, not copied
	Failed   int    `json:"failed"`
}

// Report says what a user's mail migration did.
type Report struct {
	User    string         `json:"user"`
	Dest    string         `json:"dest"`
	Folders []FolderReport `json:"folders"`
	Error   string         `json:"error,omitempty"`
}

// Totals adds up the folders.
func (r Report) Totals() FolderReport {
	var t FolderReport
	for _, f := range r.Folders {
		t.Copied += f.Copied
		t.Skipped += f.Skipped
		t.TooLarge += f.TooLarge
		t.Deleted += f.Deleted
		t.Failed += f.Failed
	}
	return t
}

// state is a user's progress: per source folder, its UIDVALIDITY and the
// highest UID copied.
type state map[string]struct {
	Validity uint32 `json:"uidvalidity"`
	LastUID  uint32 `json:"last_uid"`
}

func statePath(dir, host, user, dest string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '/' || r == '\\' || r == ':' || r < 0x20 {
				return '_'
			}
			return r
		}, s)
	}
	return filepath.Join(dir, clean(host)+"__"+clean(user)+"__"+clean(dest)+".json")
}

func loadState(path string) state {
	st := state{}
	if path == "" {
		return st
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's own state directory
	if err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func saveState(path string, st state) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Dial signs in to the source server.
func Dial(ctx context.Context, src Source) (*imapclient.Client, error) {
	host, _, err := net.SplitHostPort(src.Addr)
	if err != nil {
		return nil, fmt.Errorf("source address: %w", err)
	}
	opts := &imapclient.Options{
		// #nosec G402 -- opt-in for a source with a self-signed certificate
		TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: src.InsecureSkipVerify},
		Dialer:    &net.Dialer{Timeout: 20 * time.Second},
	}
	var c *imapclient.Client
	switch src.TLS {
	case "imaps", "":
		c, err = imapclient.DialTLS(src.Addr, opts)
	case "starttls":
		c, err = imapclient.DialStartTLS(src.Addr, opts)
	case "none":
		c, err = imapclient.DialInsecure(src.Addr, opts)
	default:
		return nil, fmt.Errorf("source TLS must be imaps, starttls or none, not %q", src.TLS)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", src.Addr, err)
	}
	if src.Admin != "" {
		err = c.Authenticate(sasl.NewPlainClient(src.User, src.Admin, src.Password))
	} else {
		err = c.Login(src.User, src.Password).Wait()
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("sign in to %s as %s: %w", src.Addr, src.User, err)
	}
	return c, nil
}

// specialFolders maps a source folder's special use, or a name other
// systems commonly give it, to the folder the webmail uses for that role.
var specialUse = map[imap.MailboxAttr]string{
	imap.MailboxAttrSent: "Sent", imap.MailboxAttrDrafts: "Drafts", imap.MailboxAttrTrash: "Trash",
	imap.MailboxAttrJunk: "Junk", imap.MailboxAttrArchive: "Archive",
}
var commonNames = map[string]string{
	"sent items": "Sent", "sent messages": "Sent", "sent mail": "Sent", "sent": "Sent",
	"deleted items": "Trash", "deleted messages": "Trash", "trash": "Trash",
	"junk e-mail": "Junk", "junk email": "Junk", "junk": "Junk", "spam": "Junk", "bulk mail": "Junk",
	"drafts": "Drafts", "archive": "Archive", "archives": "Archive",
}

// targetFolder is where a source folder's mail goes: INBOX stays INBOX,
// special folders take the webmail's names, and everything else keeps its
// name with "/" between levels.
func targetFolder(l *imap.ListData) string {
	if strings.EqualFold(l.Mailbox, "INBOX") {
		return "INBOX"
	}
	for _, a := range l.Attrs {
		if name, ok := specialUse[a]; ok {
			return name
		}
	}
	name := l.Mailbox
	if l.Delim != 0 && l.Delim != '/' {
		name = strings.ReplaceAll(strings.ReplaceAll(name, "/", "_"), string(l.Delim), "/")
	}
	if !strings.Contains(name, "/") {
		if n, ok := commonNames[strings.ToLower(name)]; ok {
			return n
		}
	}
	return name
}

// Mail copies one user's mail from the source to dest, the account's
// primary address. A failure on one message is counted and the rest go on;
// a failure that makes going on pointless (the connection lost, the
// mailbox over quota) ends the run with the report so far.
func Mail(ctx context.Context, src Source, dest string, to Importer, o Options) (Report, error) {
	rep := Report{User: src.User, Dest: dest}
	if o.MaxBytes == 0 {
		o.MaxBytes = 100 << 20
	}
	if o.Batch == 0 {
		o.Batch = 25
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	host, _, _ := net.SplitHostPort(src.Addr)
	path := ""
	if o.StateDir != "" {
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			return rep, err
		}
		path = statePath(o.StateDir, host, src.User, dest)
	}
	st := loadState(path)
	c, err := Dial(ctx, src)
	if err != nil {
		return rep, err
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()
	folders, err := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true}).Collect()
	if err != nil {
		return rep, fmt.Errorf("list folders: %w", err)
	}
	for _, f := range folders {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if hasAttr(f.Attrs, imap.MailboxAttrNoSelect) || hasAttr(f.Attrs, imap.MailboxAttrNonExistent) || excluded(f.Mailbox, o.Exclude) {
			continue
		}
		fr := FolderReport{Source: f.Mailbox, Target: targetFolder(f)}
		err := copyFolder(ctx, c, src, host, dest, to, o, st, &fr)
		rep.Folders = append(rep.Folders, fr)
		if serr := saveState(path, st); serr != nil {
			o.Log.Warn("migration progress not saved", "error", serr)
		}
		if err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func hasAttr(attrs []imap.MailboxAttr, want imap.MailboxAttr) bool {
	for _, a := range attrs {
		if strings.EqualFold(string(a), string(want)) {
			return true
		}
	}
	return false
}

func excluded(name string, list []string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), name) {
			return true
		}
	}
	return false
}

func copyFolder(ctx context.Context, c *imapclient.Client, src Source, host, dest string, to Importer, o Options, st state, fr *FolderReport) error {
	sel, err := c.Select(fr.Source, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("open %s: %w", fr.Source, err)
	}
	progress := st[fr.Source]
	if progress.Validity != sel.UIDValidity {
		// The source renumbered the folder: its UIDs say nothing about
		// what was copied, so the folder is listed again from the start.
		progress.Validity, progress.LastUID = sel.UIDValidity, 0
	}
	if sel.NumMessages == 0 {
		st[fr.Source] = progress
		return nil
	}
	set := imap.UIDSet{imap.UIDRange{Start: imap.UID(progress.LastUID + 1), Stop: 0}}
	meta, err := c.Fetch(set, &imap.FetchOptions{UID: true, Flags: true, InternalDate: true, RFC822Size: true}).Collect()
	if err != nil {
		return fmt.Errorf("list %s: %w", fr.Source, err)
	}
	var want []*imapclient.FetchMessageBuffer
	for _, m := range meta {
		if uint32(m.UID) <= progress.LastUID {
			continue // "n:*" returns the last message even when it is below n
		}
		switch {
		case hasFlag(m.Flags, imap.FlagDeleted):
			fr.Deleted++
		case m.RFC822Size > o.MaxBytes:
			fr.TooLarge++
			o.Log.Info("message too large; not copied", "user", src.User, "folder", fr.Source, "uid", m.UID, "size", m.RFC822Size)
		default:
			want = append(want, m)
		}
	}
	section := &imap.FetchItemBodySection{Peek: true}
	for start := 0; start < len(want); start += o.Batch {
		batch := want[start:min(start+o.Batch, len(want))]
		uids := make([]imap.UID, len(batch))
		byUID := map[imap.UID]*imapclient.FetchMessageBuffer{}
		for i, m := range batch {
			uids[i], byUID[m.UID] = m.UID, m
		}
		bodies, err := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
		if err != nil {
			return fmt.Errorf("download from %s: %w", fr.Source, err)
		}
		for _, b := range bodies {
			m := byUID[b.UID]
			raw := b.FindBodySection(section)
			if m == nil || raw == nil {
				fr.Failed++
				continue
			}
			key := fmt.Sprintf("imap:%s:%s:%s:%d:%d", host, strings.ToLower(src.User), fr.Source, sel.UIDValidity, b.UID)
			res, err := to.Import(ctx, mailpolicy.Import{Address: dest, Folder: fr.Target, Flags: keepFlags(m.Flags), Date: m.InternalDate, Key: key, Raw: raw})
			switch {
			case err == nil && res.Duplicate:
				fr.Skipped++
			case err == nil:
				fr.Copied++
			case errors.Is(err, mailpolicy.ErrTooLarge):
				fr.TooLarge++
			case errors.Is(err, mailpolicy.ErrQuota):
				return fmt.Errorf("%s is over its quota after %d messages from %s; raise the quota and run again", dest, fr.Copied, fr.Source)
			case errors.Is(err, mailpolicy.ErrConflict):
				fr.Skipped++
			default:
				var apiErr *mailpolicy.APIError
				if errors.As(err, &apiErr) && apiErr.Status < 500 {
					fr.Failed++
					o.Log.Warn("message not copied", "user", src.User, "folder", fr.Source, "uid", b.UID, "error", err)
					continue
				}
				return fmt.Errorf("import into %s: %w", dest, err)
			}
		}
		// Progress moves only past a batch that completed, so a rerun
		// resumes at the first message that might be missing.
		progress.LastUID = uint32(batch[len(batch)-1].UID)
		st[fr.Source] = progress
	}
	st[fr.Source] = progress
	return nil
}

func hasFlag(flags []imap.Flag, want imap.Flag) bool {
	for _, f := range flags {
		if strings.EqualFold(string(f), string(want)) {
			return true
		}
	}
	return false
}

// keepFlags is the flags worth carrying over: read, answered, flagged,
// draft, and user keywords. \Recent belongs to the source session and
// \Deleted messages aren't copied at all.
func keepFlags(flags []imap.Flag) []string {
	var out []string
	for _, f := range flags {
		switch {
		case strings.EqualFold(string(f), `\Recent`), strings.EqualFold(string(f), string(imap.FlagDeleted)):
		default:
			out = append(out, string(f))
		}
	}
	return out
}
