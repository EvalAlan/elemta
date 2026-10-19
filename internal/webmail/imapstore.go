package webmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
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
	delim   string

	// objects caches each collection's parsed objects, keyed by the folder
	// state they were read at (see objects.go).
	objects map[Collection]*objectCache
}

// IMAPDialer returns a Dialer that connects to the IMAP server in cfg.
func IMAPDialer(cfg Config) Dialer {
	return func(ctx context.Context, username, password string) (Mailstore, error) {
		return dialIMAP(ctx, cfg, username, password)
	}
}

func dialIMAP(ctx context.Context, cfg Config, username, password string) (*imapStore, error) {
	return dialIMAPUpdates(ctx, cfg, username, password, nil)
}

func dialIMAPUpdates(ctx context.Context, cfg Config, username, password string, updates *imapclient.UnilateralDataHandler) (*imapStore, error) {
	host, _, err := net.SplitHostPort(cfg.IMAPAddr)
	if err != nil {
		return nil, fmt.Errorf("webmail: imap_addr: %w", err)
	}
	opts := &imapclient.Options{
		UnilateralDataHandler: updates,
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
			// A refusal for any other reason than the credentials (too
			// many connections, the server unavailable) mustn't read as a
			// wrong password, or count towards locking the account.
			switch imapErr.Code {
			case imap.ResponseCodeLimit, imap.ResponseCodeUnavailable, imap.ResponseCodeInUse:
				return nil, fmt.Errorf("%w: %s", ErrLoginRefused, imapErr.Text)
			}
			return nil, ErrAuthFailed
		}
		return nil, fmt.Errorf("webmail: IMAP login: %w", err)
	}
	return &imapStore{c: c, objects: map[Collection]*objectCache{}}, nil
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
		if mb.Delim != 0 {
			s.delim = string(mb.Delim)
		}
		// The object folders hold calendars, contacts and settings, not
		// mail; they stay out of the mail folder tree.
		if isObjectFolder(mb.Mailbox) {
			continue
		}
		f := Folder{Name: mb.Mailbox, Display: mb.Mailbox, Selectable: true}
		if mb.Delim != 0 {
			parts := strings.Split(mb.Mailbox, string(mb.Delim))
			f.Display = parts[len(parts)-1]
			f.Depth = len(parts) - 1
			f.Parent = strings.Join(parts[:len(parts)-1], string(mb.Delim))
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

func (s *imapStore) Delimiter(ctx context.Context) (string, error) {
	if s.delim == "" {
		if _, err := s.Folders(ctx); err != nil {
			return "", err
		}
	}
	if s.delim == "" {
		return "/", nil
	}
	return s.delim, nil
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
// by name, which keeps a parent directly above its children. Children of a
// special folder (INBOX/Receipts) sort straight after it.
func sortFolders(folders []Folder) {
	top := func(f Folder) Role {
		if f.Depth == 0 {
			return f.Role
		}
		for _, g := range folders {
			if g.Depth == 0 && strings.HasPrefix(f.Name, g.Name) && len(f.Name) > len(g.Name) {
				return g.Role
			}
		}
		return RoleNone
	}
	sort.SliceStable(folders, func(i, j int) bool {
		ri, iok := roleOrder[top(folders[i])]
		rj, jok := roleOrder[top(folders[j])]
		switch {
		case iok && jok && ri != rj:
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
	return s.reselect(folder)
}

// syncFolder selects folder and makes sure the connection has seen every
// message delivered since it last looked. Servers only announce new mail
// (EXISTS) in a command's response, so a connection that sat idle with the
// folder selected would otherwise list a stale count. A NOOP is the
// cheapest command that collects the announcements.
func (s *imapStore) syncFolder(folder string) (uint32, error) {
	if mb := s.c.Mailbox(); mb != nil && mb.Name == folder {
		if err := s.c.Noop().Wait(); err != nil {
			return 0, fmt.Errorf("webmail: noop: %w", err)
		}
		return s.c.Mailbox().NumMessages, nil
	}
	return s.reselect(folder)
}

func (s *imapStore) reselect(folder string) (uint32, error) {
	data, err := s.c.Select(folder, nil).Wait()
	if err != nil {
		if isNo(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("webmail: select %q: %w", folder, err)
	}
	return data.NumMessages, nil
}

// unselect drops the selected folder, which a rename or delete of that
// folder needs first.
func (s *imapStore) unselect() {
	if s.c.Mailbox() != nil {
		_ = s.c.Unselect().Wait()
	}
}

func isNo(err error) bool {
	var imapErr *imap.Error
	return errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo
}

var summaryFetch = &imap.FetchOptions{
	UID:           true,
	Flags:         true,
	Envelope:      true,
	InternalDate:  true,
	RFC822Size:    true,
	BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
}

// searchCriteria turns a ListQuery's filters into IMAP SEARCH criteria.
func searchCriteria(q ListQuery) *imap.SearchCriteria {
	c := &imap.SearchCriteria{}
	if q.Text != "" {
		c.Text = []string{q.Text}
	}
	if q.From != "" {
		c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: "From", Value: q.From})
	}
	if q.To != "" {
		c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: "To", Value: q.To})
	}
	if q.Subject != "" {
		c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: "Subject", Value: q.Subject})
	}
	if q.Unread {
		c.NotFlag = append(c.NotFlag, imap.FlagSeen)
	}
	if q.Flagged {
		c.Flag = append(c.Flag, imap.FlagFlagged)
	}
	if q.Answered {
		c.Flag = append(c.Flag, imap.FlagAnswered)
	}
	if q.Tag != "" {
		c.Flag = append(c.Flag, imap.Flag(q.Tag))
	}
	if q.HasAttachment {
		// IMAP has no attachment criterion. A multipart/mixed top level is
		// what almost every client produces for a message with files, so it
		// is the usual approximation.
		c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: "Content-Type", Value: "multipart/mixed"})
	}
	c.Since = q.Since
	c.Before = q.Before
	return c
}

func (s *imapStore) List(ctx context.Context, folder string, q ListQuery) (Page, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = defaultPageSize
	}
	result := Page{Folder: folder, Page: q.Page, PageSize: q.PageSize}
	total, err := s.syncFolder(folder)
	if err != nil {
		return result, err
	}

	caps := s.c.Caps()
	canSort := caps.Has(imap.Cap("SORT"))
	var msgs []*imapclient.FetchMessageBuffer
	var order []uint32 // UIDs in display order, when the server ordered them

	switch {
	case !q.Filtered() && (q.Sort == SortDate || !canSort):
		result.Total = int(total)
		// Sequence numbers are in arrival order, so a date-ordered page is
		// a slice of the range. That needs no SEARCH or SORT round trip.
		lo, hi := pageRange(int(total), q.Page, q.PageSize, q.Reverse)
		if hi < lo {
			return result, nil
		}
		var set imap.SeqSet
		set.AddRange(uint32(lo), uint32(hi)) // #nosec G115 -- bounded by the mailbox's uint32 message count
		msgs, err = s.c.Fetch(set, summaryFetch).Collect()
	default:
		var uids []uint32
		if canSort {
			key := map[Sort]imapclient.SortKey{SortDate: imapclient.SortKeyArrival, SortFrom: imapclient.SortKeyFrom, SortSubject: imapclient.SortKeySubject, SortSize: imapclient.SortKeySize}[q.Sort]
			// Date and size read newest/largest first by default; names A to Z.
			reverse := q.Sort == SortDate || q.Sort == SortSize
			if q.Reverse {
				reverse = !reverse
			}
			uids, err = s.c.UIDSort(&imapclient.SortOptions{
				SearchCriteria: searchCriteria(q),
				SortCriteria:   []imapclient.SortCriterion{{Key: key, Reverse: reverse}},
			}).Wait()
			if err != nil {
				return result, fmt.Errorf("webmail: sort %q: %w", folder, err)
			}
		} else {
			data, err := s.c.UIDSearch(searchCriteria(q), nil).Wait()
			if err != nil {
				return result, fmt.Errorf("webmail: search %q: %w", folder, err)
			}
			for _, u := range data.AllUIDs() {
				uids = append(uids, uint32(u))
			}
			sort.Slice(uids, func(i, j int) bool { return (uids[i] > uids[j]) != q.Reverse })
		}
		result.Total = len(uids)
		start := (q.Page - 1) * q.PageSize
		if start >= len(uids) {
			return result, nil
		}
		order = uids[start:min(start+q.PageSize, len(uids))]
		set := imap.UIDSet{}
		for _, u := range order {
			set.AddNum(imap.UID(u))
		}
		msgs, err = s.c.Fetch(set, summaryFetch).Collect()
	}
	if err != nil {
		return result, fmt.Errorf("webmail: fetch %q: %w", folder, err)
	}

	if order != nil {
		rank := make(map[uint32]int, len(order))
		for i, u := range order {
			rank[u] = i
		}
		sort.Slice(msgs, func(i, j int) bool { return rank[uint32(msgs[i].UID)] < rank[uint32(msgs[j].UID)] })
	} else {
		sort.Slice(msgs, func(i, j int) bool { return (msgs[i].UID > msgs[j].UID) != q.Reverse })
	}
	result.Messages = make([]Summary, 0, len(msgs))
	for _, m := range msgs {
		result.Messages = append(result.Messages, toSummary(m))
	}
	return result, nil
}

// pageRange returns the sequence numbers [lo, hi] of one page of a folder
// holding total messages, newest first unless oldestFirst.
func pageRange(total, page, size int, oldestFirst bool) (int, int) {
	if oldestFirst {
		lo := (page-1)*size + 1
		return lo, min(lo+size-1, total)
	}
	hi := total - (page-1)*size
	return max(hi-size+1, 1), hi
}

func toSummary(m *imapclient.FetchMessageBuffer) Summary {
	sum := Summary{UID: uint32(m.UID), Size: m.RFC822Size, Date: m.InternalDate}
	if env := m.Envelope; env != nil {
		sum.Subject = env.Subject
		if env.MessageID != "" {
			sum.MessageID = "<" + strings.Trim(env.MessageID, "<>") + ">"
		}
		sum.From = toAddresses(env.From)
		sum.To = toAddresses(env.To)
		if !env.Date.IsZero() {
			sum.Date = env.Date
		}
	}
	for _, f := range m.Flags {
		switch {
		case f == imap.FlagSeen:
			sum.Seen = true
		case f == imap.FlagFlagged:
			sum.Flagged = true
		case f == imap.FlagAnswered:
			sum.Answered = true
		case f == imap.FlagDraft:
			sum.Draft = true
		case strings.EqualFold(string(f), FlagForwarded):
			sum.Forwarded = true
		case strings.EqualFold(string(f), FlagSchedulingDone):
			sum.SchedulingDone = true
		case isTagKeyword(string(f)):
			sum.Tags = append(sum.Tags, string(f))
		}
	}
	sort.Strings(sum.Tags)
	if m.BodyStructure != nil {
		sum.HasAttachment = hasAttachment(m.BodyStructure)
		sum.Scheduling = schedulingMethod(m.BodyStructure)
	}
	return sum
}

// schedulingMethod is the method parameter of a message's text/calendar
// part, which iMIP (RFC 6047) requires, so invitation replies can be found
// from the list's body structures without downloading every message.
func schedulingMethod(bs imap.BodyStructure) string {
	method := ""
	bs.Walk(func(_ []int, part imap.BodyStructure) bool {
		single, ok := part.(*imap.BodyStructureSinglePart)
		if ok && strings.EqualFold(single.Type, "text") && strings.EqualFold(single.Subtype, "calendar") {
			for k, v := range single.Params {
				if strings.EqualFold(k, "method") {
					method = strings.ToUpper(strings.TrimSpace(v))
				}
			}
		}
		return method == ""
	})
	return method
}

// hasAttachment reports whether a body structure carries a file a user
// would call an attachment, as opposed to the text, HTML and cid: images of
// the body itself.
func hasAttachment(bs imap.BodyStructure) bool {
	found := false
	bs.Walk(func(_ []int, part imap.BodyStructure) bool {
		single, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if d := single.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
			found = true
		} else if single.Filename() != "" && !strings.EqualFold(single.Type, "image") && !strings.EqualFold(single.Type, "text") {
			found = true
		}
		return !found
	})
	return found
}

// isTagKeyword reports whether an IMAP keyword is a user tag. System flags
// start with a backslash, and $-prefixed keywords are protocol markers
// ($Forwarded, $MDNSent, $Junk) that the UI shows another way or not at all.
func isTagKeyword(k string) bool {
	return k != "" && k[0] != '\\' && k[0] != '$' && k != "NonJunk" && k != "Junk" && k != "*"
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

func uidSet(uids []uint32) imap.UIDSet {
	set := imap.UIDSet{}
	for _, u := range uids {
		set.AddNum(imap.UID(u))
	}
	return set
}

func (s *imapStore) SetFlags(ctx context.Context, folder string, uids []uint32, flags []string, on bool) error {
	if len(uids) == 0 || len(flags) == 0 {
		return nil
	}
	if _, err := s.selectFolder(folder); err != nil {
		return err
	}
	op := imap.StoreFlagsDel
	if on {
		op = imap.StoreFlagsAdd
	}
	fl := make([]imap.Flag, 0, len(flags))
	for _, f := range flags {
		fl = append(fl, imap.Flag(f))
	}
	if err := s.c.Store(uidSet(uids), &imap.StoreFlags{Op: op, Silent: true, Flags: fl}, nil).Close(); err != nil {
		return fmt.Errorf("webmail: store flags: %w", err)
	}
	return nil
}

func (s *imapStore) Move(ctx context.Context, folder string, uids []uint32, dest string) error {
	if len(uids) == 0 {
		return nil
	}
	if _, err := s.selectFolder(folder); err != nil {
		return err
	}
	if _, err := s.c.Move(uidSet(uids), dest).Wait(); err != nil {
		if isNo(err) {
			return ErrNotFound
		}
		return fmt.Errorf("webmail: move to %q: %w", dest, err)
	}
	return nil
}

func (s *imapStore) Delete(ctx context.Context, folder string, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	trash, err := s.roleFolder(ctx, RoleTrash)
	if err != nil {
		return err
	}
	if trash != "" && trash != folder {
		return s.Move(ctx, folder, uids, trash)
	}
	return s.expunge(folder, uids)
}

func (s *imapStore) Expunge(ctx context.Context, folder string, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	return s.expunge(folder, uids)
}

// expunge removes messages for good.
func (s *imapStore) expunge(folder string, uids []uint32) error {
	if err := s.SetFlags(context.Background(), folder, uids, []string{string(imap.FlagDeleted)}, true); err != nil {
		return err
	}
	if s.c.Caps().Has(imap.CapUIDPlus) || s.c.Caps().Has(imap.CapIMAP4rev2) {
		return s.c.UIDExpunge(uidSet(uids)).Close()
	}
	// Without UIDPLUS a plain EXPUNGE would also remove anything else the
	// user (or another client) had flagged \Deleted. That's the documented
	// IMAP behaviour and what every client without UIDPLUS does.
	return s.c.Expunge().Close()
}

func (s *imapStore) MarkAllRead(ctx context.Context, folder string) error {
	n, err := s.syncFolder(folder)
	if err != nil || n == 0 {
		return err
	}
	var all imap.SeqSet
	all.AddRange(1, 0) // 1:*
	if err := s.c.Store(all, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close(); err != nil {
		return fmt.Errorf("webmail: mark %q read: %w", folder, err)
	}
	return nil
}

func (s *imapStore) EmptyFolder(ctx context.Context, folder string) error {
	n, err := s.selectFolder(folder)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	var all imap.SeqSet
	all.AddRange(1, 0) // 1:*
	if err := s.c.Store(all, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		return fmt.Errorf("webmail: empty %q: %w", folder, err)
	}
	return s.c.Expunge().Close()
}

func (s *imapStore) EnsureFolders(ctx context.Context, roles []Role) error {
	folders, err := s.Folders(ctx)
	if err != nil {
		return err
	}
	have := map[Role]bool{}
	for _, f := range folders {
		have[f.Role] = true
	}
	for _, role := range roles {
		name := defaultRoleNames[role]
		if have[role] || name == "" {
			continue
		}
		if err := s.CreateFolder(ctx, name); err != nil && !errors.Is(err, ErrExists) {
			return err
		}
	}
	return nil
}

func (s *imapStore) CreateFolder(ctx context.Context, name string) error {
	if err := s.c.Create(name, nil).Wait(); err != nil {
		if isNo(err) {
			return ErrExists
		}
		return fmt.Errorf("webmail: create %q: %w", name, err)
	}
	// Subscribe so other clients, which mostly list subscribed folders
	// only, show it too.
	_ = s.c.Subscribe(name).Wait()
	s.folders = nil
	return nil
}

func (s *imapStore) RenameFolder(ctx context.Context, from, to string) error {
	s.unselect()
	if err := s.c.Rename(from, to, nil).Wait(); err != nil {
		if isNo(err) {
			return ErrExists
		}
		return fmt.Errorf("webmail: rename %q: %w", from, err)
	}
	_ = s.c.Unsubscribe(from).Wait()
	_ = s.c.Subscribe(to).Wait()
	s.folders = nil
	return nil
}

func (s *imapStore) DeleteFolder(ctx context.Context, name string) error {
	s.unselect()
	if err := s.c.Delete(name).Wait(); err != nil {
		if isNo(err) {
			return ErrNotFound
		}
		return fmt.Errorf("webmail: delete %q: %w", name, err)
	}
	_ = s.c.Unsubscribe(name).Wait()
	s.folders = nil
	return nil
}

func (s *imapStore) Tags(ctx context.Context, folder string) ([]string, error) {
	if _, err := s.selectFolder(folder); err != nil {
		return nil, err
	}
	var out []string
	if mb := s.c.Mailbox(); mb != nil {
		for _, f := range mb.Flags {
			if isTagKeyword(string(f)) {
				out = append(out, string(f))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// maxThreadIDs bounds how many Message-IDs one conversation search ORs
// together; long threads are matched on their most recent references.
const maxThreadIDs = 12

func (s *imapStore) Related(ctx context.Context, folders []string, ids []string) ([]Related, error) {
	if len(ids) > maxThreadIDs {
		ids = ids[len(ids)-maxThreadIDs:]
	}
	var tests []imap.SearchCriteria
	for _, id := range ids {
		for _, h := range []string{"Message-Id", "References", "In-Reply-To"} {
			tests = append(tests, imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: h, Value: id}}})
		}
	}
	if len(tests) == 0 {
		return nil, nil
	}
	criteria := orAll(tests)
	var out []Related
	for _, folder := range folders {
		if folder == "" {
			continue
		}
		if _, err := s.syncFolder(folder); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		data, err := s.c.UIDSearch(&criteria, nil).Wait()
		if err != nil {
			return nil, fmt.Errorf("webmail: conversation search %q: %w", folder, err)
		}
		uids := data.AllUIDs()
		if len(uids) == 0 {
			continue
		}
		if len(uids) > 100 {
			uids = uids[len(uids)-100:]
		}
		msgs, err := s.c.Fetch(imap.UIDSetNum(uids...), summaryFetch).Collect()
		if err != nil {
			return nil, fmt.Errorf("webmail: fetch conversation %q: %w", folder, err)
		}
		for _, m := range msgs {
			out = append(out, Related{Folder: folder, Summary: toSummary(m)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Date.Before(out[j].Date) })
	return out, nil
}

// orAll combines criteria with OR as a balanced tree, which keeps the
// command's nesting shallow.
func orAll(list []imap.SearchCriteria) imap.SearchCriteria {
	if len(list) == 1 {
		return list[0]
	}
	mid := len(list) / 2
	return imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{orAll(list[:mid]), orAll(list[mid:])}}}
}

// defaultRoleNames are the folders Append creates when an account has none.
var defaultRoleNames = map[Role]string{RoleSent: "Sent", RoleDrafts: "Drafts", RoleTrash: "Trash", RoleJunk: "Junk", RoleArchive: "Archive"}

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
		if err := s.ensureFolder(name); err != nil {
			return err
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
	_, err = s.appendRaw(name, raw, flags)
	return err
}

// ensureFolder creates name if it doesn't exist.
func (s *imapStore) ensureFolder(name string) error {
	if err := s.c.Create(name, nil).Wait(); err != nil {
		// ALREADYEXISTS (or a bare NO from older servers) means it exists,
		// perhaps created by another client since we listed; carry on.
		if !isNo(err) {
			return fmt.Errorf("webmail: create %q: %w", name, err)
		}
	}
	return nil
}

// appendRaw appends a message and returns its UID when the server reports
// it (UIDPLUS), or 0.
func (s *imapStore) appendRaw(folder string, raw []byte, flags []imap.Flag) (uint32, error) {
	cmd := s.c.Append(folder, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: time.Now()})
	if _, err := bytes.NewReader(raw).WriteTo(cmd); err != nil {
		_ = cmd.Close()
		return 0, fmt.Errorf("webmail: append to %q: %w", folder, err)
	}
	if err := cmd.Close(); err != nil {
		return 0, fmt.Errorf("webmail: append to %q: %w", folder, err)
	}
	data, err := cmd.Wait()
	if err != nil {
		return 0, fmt.Errorf("webmail: append to %q: %w", folder, err)
	}
	return uint32(data.UID), nil
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

// maxThreadSummaries bounds how many messages of one conversation are
// fetched to draw its row; the row needs only the latest few.
const maxThreadSummaries = 20

func (s *imapStore) ListThreads(ctx context.Context, folder string, q ListQuery) (ThreadPage, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = defaultPageSize
	}
	result := ThreadPage{Folder: folder, Page: q.Page, PageSize: q.PageSize}
	if _, err := s.syncFolder(folder); err != nil {
		return result, err
	}
	var threads [][]uint32
	if hasThreadReferences(s.c.Caps()) {
		data, err := s.c.UIDThread(&imapclient.ThreadOptions{Algorithm: imap.ThreadReferences, SearchCriteria: searchCriteria(q)}).Wait()
		if err != nil {
			return result, fmt.Errorf("webmail: thread %q: %w", folder, err)
		}
		for _, t := range data {
			threads = append(threads, flattenThread(t, nil))
		}
	} else {
		// Without THREAD every message is its own conversation.
		data, err := s.c.UIDSearch(searchCriteria(q), nil).Wait()
		if err != nil {
			return result, fmt.Errorf("webmail: search %q: %w", folder, err)
		}
		for _, u := range data.AllUIDs() {
			threads = append(threads, []uint32{uint32(u)})
		}
	}
	// Most recent activity first. UIDs grow with arrival, so a thread's
	// highest UID is its latest arrival, with no fetch needed to order.
	latest := func(t []uint32) uint32 {
		m := uint32(0)
		for _, u := range t {
			m = max(m, u)
		}
		return m
	}
	sort.Slice(threads, func(i, j int) bool { return (latest(threads[i]) > latest(threads[j])) != q.Reverse })
	result.Total = len(threads)
	start := (q.Page - 1) * q.PageSize
	if start >= len(threads) {
		return result, nil
	}
	threads = threads[start:min(start+q.PageSize, len(threads))]

	set := imap.UIDSet{}
	for i, t := range threads {
		sort.Slice(t, func(a, b int) bool { return t[a] < t[b] })
		threads[i] = t
		for _, u := range t[max(0, len(t)-maxThreadSummaries):] {
			set.AddNum(imap.UID(u))
		}
	}
	msgs, err := s.c.Fetch(set, summaryFetch).Collect()
	if err != nil {
		return result, fmt.Errorf("webmail: fetch %q: %w", folder, err)
	}
	byUID := make(map[uint32]Summary, len(msgs))
	for _, m := range msgs {
		byUID[uint32(m.UID)] = toSummary(m)
	}
	for _, t := range threads {
		c := Conversation{UIDs: t}
		seen := map[string]bool{}
		for _, u := range t {
			sum, ok := byUID[u]
			if !ok {
				continue
			}
			c.Messages = append(c.Messages, sum)
			if !sum.Seen {
				c.Unread++
			}
			c.Flagged = c.Flagged || sum.Flagged
			c.HasAttachment = c.HasAttachment || sum.HasAttachment
			if sum.Date.After(c.Latest.Date) || c.Latest.UID == 0 {
				c.Latest = sum
			}
			for _, a := range sum.From {
				key := strings.ToLower(a.Email)
				if !seen[key] && len(c.Participants) < 4 {
					seen[key] = true
					c.Participants = append(c.Participants, a)
				}
			}
		}
		if len(c.Messages) == 0 {
			continue
		}
		c.Subject = baseSubject(c.Messages[0].Subject)
		result.Conversations = append(result.Conversations, c)
	}
	return result, nil
}

func hasThreadReferences(caps imap.CapSet) bool {
	for _, a := range caps.ThreadAlgorithms() {
		if a == imap.ThreadReferences {
			return true
		}
	}
	return false
}

// flattenThread lists every UID in a thread tree.
func flattenThread(t imapclient.ThreadData, out []uint32) []uint32 {
	out = append(out, t.Chain...)
	for _, sub := range t.SubThreads {
		out = flattenThread(sub, out)
	}
	return out
}

var subjectPrefixRE = regexp.MustCompile(`(?i)^\s*((re|fwd?|aw|wg|sv|vs|antw|tr)\s*(\[\d+\])?\s*:\s*)+`)

// baseSubject strips reply and forward prefixes, in the languages mail
// clients commonly add them in, to give a conversation its title.
func baseSubject(s string) string {
	return strings.TrimSpace(subjectPrefixRE.ReplaceAllString(s, ""))
}
