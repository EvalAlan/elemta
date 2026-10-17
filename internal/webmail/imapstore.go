package webmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// imapStore is the Mailstore backed by an IMAP server.
type imapStore struct {
	c *imapclient.Client

	// folders caches the folder list so role lookups (where is Trash?) don't
	// cost a LIST per action. Folders() refreshes it.
	folders []Folder
}

// IMAPDialer returns a Dialer that connects to the IMAP server in cfg.
func IMAPDialer(cfg Config) Dialer {
	return func(ctx context.Context, username, password string) (Mailstore, error) {
		return dialIMAP(ctx, cfg, username, password)
	}
}

func dialIMAP(ctx context.Context, cfg Config, username, password string) (*imapStore, error) {
	host, _, err := net.SplitHostPort(cfg.IMAPAddr)
	if err != nil {
		return nil, fmt.Errorf("webmail: imap_addr: %w", err)
	}
	opts := &imapclient.Options{
		TLSConfig: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			// #nosec G402 -- opt-in for the dev stack's self-signed certificate; documented as dev-only
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		Dialer: &net.Dialer{Timeout: 10 * time.Second},
	}
	if deadline, ok := ctx.Deadline(); ok {
		opts.Dialer.Deadline = deadline
	}

	var c *imapclient.Client
	switch cfg.IMAPTLS {
	case TLSModeImplicit:
		c, err = imapclient.DialTLS(cfg.IMAPAddr, opts)
	case TLSModeNone:
		c, err = imapclient.DialInsecure(cfg.IMAPAddr, opts)
	default:
		c, err = imapclient.DialStartTLS(cfg.IMAPAddr, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("webmail: connect to IMAP %s: %w", cfg.IMAPAddr, err)
	}
	if err := c.Login(username, password).Wait(); err != nil {
		_ = c.Close()
		var imapErr *imap.Error
		if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo {
			return nil, ErrAuthFailed
		}
		return nil, fmt.Errorf("webmail: IMAP login: %w", err)
	}
	return &imapStore{c: c}, nil
}

func (s *imapStore) Close() error {
	// Logout is a courtesy; the connection is closed either way.
	_ = s.c.Logout().Wait()
	return s.c.Close()
}

func (s *imapStore) Folders(ctx context.Context) ([]Folder, error) {
	caps := s.c.Caps()
	opts := &imap.ListOptions{}
	// LIST-STATUS returns counts with the list in one round trip; without
	// it every folder costs a STATUS.
	listStatus := caps.Has(imap.CapListStatus) || caps.Has(imap.CapIMAP4rev2)
	if listStatus {
		opts.ReturnStatus = &imap.StatusOptions{NumMessages: true, NumUnseen: true}
	}
	if caps.Has(imap.CapSpecialUse) || caps.Has(imap.CapIMAP4rev2) {
		opts.ReturnSpecialUse = true
	}
	list, err := s.c.List("", "*", opts).Collect()
	if err != nil {
		return nil, fmt.Errorf("webmail: list folders: %w", err)
	}

	folders := make([]Folder, 0, len(list))
	for _, mb := range list {
		f := Folder{Name: mb.Mailbox, Display: mb.Mailbox, Selectable: true}
		if mb.Delim != 0 {
			parts := strings.Split(mb.Mailbox, string(mb.Delim))
			f.Display = parts[len(parts)-1]
			f.Depth = len(parts) - 1
		}
		for _, attr := range mb.Attrs {
			switch attr {
			case imap.MailboxAttrNoSelect, imap.MailboxAttrNonExistent:
				f.Selectable = false
			}
		}
		f.Role = roleOf(mb.Mailbox, mb.Attrs)
		status := mb.Status
		if status == nil && f.Selectable && !listStatus {
			status, err = s.c.Status(mb.Mailbox, &imap.StatusOptions{NumMessages: true, NumUnseen: true}).Wait()
			if err != nil {
				return nil, fmt.Errorf("webmail: status %q: %w", mb.Mailbox, err)
			}
		}
		if status != nil {
			if status.NumMessages != nil {
				f.Total = *status.NumMessages
			}
			if status.NumUnseen != nil {
				f.Unread = *status.NumUnseen
			}
		}
		folders = append(folders, f)
	}
	sortFolders(folders)
	s.folders = folders
	return folders, nil
}

// roleOf prefers the server's special-use attribute and falls back to the
// conventional English names, which is what most existing mailboxes use.
func roleOf(name string, attrs []imap.MailboxAttr) Role {
	if strings.EqualFold(name, "INBOX") {
		return RoleInbox
	}
	for _, attr := range attrs {
		switch attr {
		case imap.MailboxAttrDrafts:
			return RoleDrafts
		case imap.MailboxAttrSent:
			return RoleSent
		case imap.MailboxAttrJunk:
			return RoleJunk
		case imap.MailboxAttrTrash:
			return RoleTrash
		case imap.MailboxAttrArchive:
			return RoleArchive
		}
	}
	switch strings.ToLower(name) {
	case "drafts":
		return RoleDrafts
	case "sent", "sent items", "sent messages":
		return RoleSent
	case "junk", "spam":
		return RoleJunk
	case "trash", "deleted items", "deleted messages":
		return RoleTrash
	case "archive":
		return RoleArchive
	}
	return RoleNone
}

var roleOrder = map[Role]int{RoleInbox: 0, RoleDrafts: 1, RoleSent: 2, RoleArchive: 3, RoleJunk: 4, RoleTrash: 5}

// sortFolders puts the special folders first in a fixed order, then the rest
// by name, which keeps a parent directly above its children.
func sortFolders(folders []Folder) {
	sort.SliceStable(folders, func(i, j int) bool {
		ri, iok := roleOrder[folders[i].Role]
		rj, jok := roleOrder[folders[j].Role]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		}
		return strings.ToLower(folders[i].Name) < strings.ToLower(folders[j].Name)
	})
}

// roleFolder returns the name of the folder with role, or "" if there is none.
func (s *imapStore) roleFolder(ctx context.Context, role Role) (string, error) {
	if s.folders == nil {
		if _, err := s.Folders(ctx); err != nil {
			return "", err
		}
	}
	for _, f := range s.folders {
		if f.Role == role {
			return f.Name, nil
		}
	}
	return "", nil
}

// selectFolder selects folder unless it is already selected.
func (s *imapStore) selectFolder(folder string) (uint32, error) {
	if mb := s.c.Mailbox(); mb != nil && mb.Name == folder {
		return mb.NumMessages, nil
	}
	data, err := s.c.Select(folder, nil).Wait()
	if err != nil {
		var imapErr *imap.Error
		if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("webmail: select %q: %w", folder, err)
	}
	return data.NumMessages, nil
}

var summaryFetch = &imap.FetchOptions{
	UID:          true,
	Flags:        true,
	Envelope:     true,
	InternalDate: true,
	RFC822Size:   true,
}

func (s *imapStore) List(ctx context.Context, folder, query string, page, pageSize int) (Page, error) {
	if page < 1 {
		page = 1
	}
	result := Page{Folder: folder, Page: page, PageSize: pageSize}
	total, err := s.selectFolder(folder)
	if err != nil {
		return result, err
	}

	var msgs []*imapclient.FetchMessageBuffer
	if query == "" {
		result.Total = int(total)
		// Sequence numbers are in arrival order, so the newest page is the
		// top of the range. That needs no SEARCH or SORT round trip.
		hi := int(total) - (page-1)*pageSize
		if hi < 1 {
			return result, nil
		}
		lo := hi - pageSize + 1
		if lo < 1 {
			lo = 1
		}
		var set imap.SeqSet
		set.AddRange(uint32(lo), uint32(hi)) // #nosec G115 -- bounded by the mailbox's uint32 message count
		msgs, err = s.c.Fetch(set, summaryFetch).Collect()
	} else {
		var data *imap.SearchData
		data, err = s.c.UIDSearch(&imap.SearchCriteria{Text: []string{query}}, nil).Wait()
		if err != nil {
			return result, fmt.Errorf("webmail: search %q: %w", folder, err)
		}
		uids := data.AllUIDs()
		sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
		result.Total = len(uids)
		start := (page - 1) * pageSize
		if start >= len(uids) {
			return result, nil
		}
		end := start + pageSize
		if end > len(uids) {
			end = len(uids)
		}
		msgs, err = s.c.Fetch(imap.UIDSetNum(uids[start:end]...), summaryFetch).Collect()
	}
	if err != nil {
		return result, fmt.Errorf("webmail: fetch %q: %w", folder, err)
	}

	sort.Slice(msgs, func(i, j int) bool { return msgs[i].UID > msgs[j].UID })
	result.Messages = make([]Summary, 0, len(msgs))
	for _, m := range msgs {
		result.Messages = append(result.Messages, toSummary(m))
	}
	return result, nil
}

func toSummary(m *imapclient.FetchMessageBuffer) Summary {
	sum := Summary{UID: uint32(m.UID), Size: m.RFC822Size, Date: m.InternalDate}
	if env := m.Envelope; env != nil {
		sum.Subject = env.Subject
		sum.From = toAddresses(env.From)
		sum.To = toAddresses(env.To)
		if !env.Date.IsZero() {
			sum.Date = env.Date
		}
	}
	for _, f := range m.Flags {
		switch f {
		case imap.FlagSeen:
			sum.Seen = true
		case imap.FlagFlagged:
			sum.Flagged = true
		case imap.FlagAnswered:
			sum.Answered = true
		case imap.FlagDraft:
			sum.Draft = true
		}
	}
	return sum
}

func toAddresses(in []imap.Address) []Address {
	out := make([]Address, 0, len(in))
	for i := range in {
		if in[i].IsGroupStart() || in[i].IsGroupEnd() {
			continue
		}
		out = append(out, Address{Name: in[i].Name, Email: in[i].Addr()})
	}
	return out
}

func (s *imapStore) Raw(ctx context.Context, folder string, uid uint32, maxBytes int64) ([]byte, error) {
	if _, err := s.selectFolder(folder); err != nil {
		return nil, err
	}
	set := imap.UIDSetNum(imap.UID(uid))
	sizes, err := s.c.Fetch(set, &imap.FetchOptions{UID: true, RFC822Size: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("webmail: fetch size: %w", err)
	}
	if len(sizes) == 0 {
		return nil, ErrNotFound
	}
	if maxBytes > 0 && sizes[0].RFC822Size > maxBytes {
		return nil, ErrTooLarge
	}
	// Peek, so that opening a message is an explicit SetSeen and not a side
	// effect of a prefetch or a download.
	section := &imap.FetchItemBodySection{Peek: true}
	msgs, err := s.c.Fetch(set, &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil {
		return nil, fmt.Errorf("webmail: fetch body: %w", err)
	}
	if len(msgs) == 0 {
		return nil, ErrNotFound
	}
	return msgs[0].FindBodySection(section), nil
}

func (s *imapStore) storeFlag(folder string, uid uint32, flag imap.Flag, on bool) error {
	if _, err := s.selectFolder(folder); err != nil {
		return err
	}
	op := imap.StoreFlagsDel
	if on {
		op = imap.StoreFlagsAdd
	}
	return s.c.Store(imap.UIDSetNum(imap.UID(uid)), &imap.StoreFlags{Op: op, Silent: true, Flags: []imap.Flag{flag}}, nil).Close()
}

func (s *imapStore) SetSeen(ctx context.Context, folder string, uid uint32, seen bool) error {
	return s.storeFlag(folder, uid, imap.FlagSeen, seen)
}

func (s *imapStore) SetFlagged(ctx context.Context, folder string, uid uint32, flagged bool) error {
	return s.storeFlag(folder, uid, imap.FlagFlagged, flagged)
}

func (s *imapStore) Move(ctx context.Context, folder string, uid uint32, dest string) error {
	if _, err := s.selectFolder(folder); err != nil {
		return err
	}
	if _, err := s.c.Move(imap.UIDSetNum(imap.UID(uid)), dest).Wait(); err != nil {
		return fmt.Errorf("webmail: move to %q: %w", dest, err)
	}
	return nil
}

func (s *imapStore) Delete(ctx context.Context, folder string, uid uint32) error {
	trash, err := s.roleFolder(ctx, RoleTrash)
	if err != nil {
		return err
	}
	if trash != "" && trash != folder {
		return s.Move(ctx, folder, uid, trash)
	}
	if err := s.storeFlag(folder, uid, imap.FlagDeleted, true); err != nil {
		return err
	}
	set := imap.UIDSetNum(imap.UID(uid))
	if s.c.Caps().Has(imap.CapUIDPlus) || s.c.Caps().Has(imap.CapIMAP4rev2) {
		return s.c.UIDExpunge(set).Close()
	}
	// Without UIDPLUS a plain EXPUNGE would also remove anything else the
	// user (or another client) had flagged \Deleted. That's the documented
	// IMAP behaviour and what every client without UIDPLUS does.
	return s.c.Expunge().Close()
}

// defaultRoleNames are the folders Append creates when an account has none.
var defaultRoleNames = map[Role]string{RoleSent: "Sent", RoleDrafts: "Drafts", RoleTrash: "Trash", RoleJunk: "Junk"}

func (s *imapStore) Append(ctx context.Context, role Role, raw []byte, seen, draft bool) error {
	name, err := s.roleFolder(ctx, role)
	if err != nil {
		return err
	}
	if name == "" {
		name = defaultRoleNames[role]
		if name == "" {
			return fmt.Errorf("webmail: no folder for role %q", role)
		}
		if err := s.c.Create(name, nil).Wait(); err != nil {
			var imapErr *imap.Error
			// ALREADYEXISTS (or a bare NO from older servers) means another
			// client created it since we listed; carry on and append.
			if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo {
				return fmt.Errorf("webmail: create %q: %w", name, err)
			}
		}
		s.folders = nil
	}
	var flags []imap.Flag
	if seen {
		flags = append(flags, imap.FlagSeen)
	}
	if draft {
		flags = append(flags, imap.FlagDraft)
	}
	cmd := s.c.Append(name, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: time.Now()})
	if _, err := bytes.NewReader(raw).WriteTo(cmd); err != nil {
		_ = cmd.Close()
		return fmt.Errorf("webmail: append to %q: %w", name, err)
	}
	if err := cmd.Close(); err != nil {
		return fmt.Errorf("webmail: append to %q: %w", name, err)
	}
	if _, err := cmd.Wait(); err != nil {
		return fmt.Errorf("webmail: append to %q: %w", name, err)
	}
	return nil
}

// isConnError reports whether err means the IMAP connection itself is gone,
// as opposed to the server refusing a command on a healthy connection.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	var imapErr *imap.Error
	if errors.As(err, &imapErr) {
		// BYE is the server hanging up; NO and BAD are command failures.
		return imapErr.Type == imap.StatusResponseTypeBye
	}
	var netErr net.Error
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.As(err, &netErr)
}
