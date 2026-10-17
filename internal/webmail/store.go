package webmail

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Role is the special use of a folder (RFC 6154), independent of its name.
type Role string

// Folder roles the UI treats specially.
const (
	RoleNone    Role = ""
	RoleInbox   Role = "inbox"
	RoleDrafts  Role = "drafts"
	RoleSent    Role = "sent"
	RoleJunk    Role = "junk"
	RoleTrash   Role = "trash"
	RoleArchive Role = "archive"
)

// Folder is one mailbox in the user's folder tree.
type Folder struct {
	Name       string // full IMAP name, used as the folder's identifier
	Display    string // last path segment, shown in the tree
	Parent     string // full name of the parent folder, "" at the top level
	Depth      int    // nesting level, 0 for top-level folders
	Role       Role
	Total      uint32
	Unread     uint32
	Selectable bool
}

// Address is a parsed mailbox address.
type Address struct {
	Name  string
	Email string
}

// Label is what the UI shows for an address: the name if there is one.
func (a Address) Label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.Email
}

// Summary is one row of a message list.
type Summary struct {
	UID           uint32
	MessageID     string
	From          []Address
	To            []Address
	Subject       string
	Date          time.Time
	Size          int64
	Seen          bool
	Flagged       bool
	Answered      bool
	Forwarded     bool
	Draft         bool
	HasAttachment bool
	Tags          []string // user keywords, see isTagKeyword
}

// Related is a message found in another place in a conversation.
type Related struct {
	Folder string
	Summary
}

// Page is a window of a folder's messages, newest first.
type Page struct {
	Folder   string
	Messages []Summary
	Total    int // messages matching, across all pages
	Page     int // 1-based
	PageSize int
}

// Conversation is one row of a threaded list: the messages of one thread
// in the folder, oldest first.
type Conversation struct {
	UIDs          []uint32
	Messages      []Summary // the most recent ones, oldest first, for display
	Latest        Summary
	Subject       string // the thread's subject, without Re:/Fwd:
	Participants  []Address
	Unread        int
	Flagged       bool
	HasAttachment bool
}

// Count is the number of messages in the conversation.
func (c Conversation) Count() int { return len(c.UIDs) }

// UIDList is the conversation's UIDs as one form value ("12,15,19").
func (c Conversation) UIDList() string {
	parts := make([]string, len(c.UIDs))
	for i, u := range c.UIDs {
		parts[i] = strconv.FormatUint(uint64(u), 10)
	}
	return strings.Join(parts, ",")
}

// ThreadPage is a window of a folder's conversations.
type ThreadPage struct {
	Folder        string
	Conversations []Conversation
	Total         int // conversations matching, across all pages
	Page          int
	PageSize      int
}

// Pages is the number of pages Total spans.
func (p ThreadPage) Pages() int { return Page{Total: p.Total, PageSize: p.PageSize}.Pages() }

// Pages is the number of pages Total spans.
func (p Page) Pages() int {
	if p.PageSize <= 0 || p.Total == 0 {
		return 1
	}
	return (p.Total + p.PageSize - 1) / p.PageSize
}

// Sort orders a message list. The zero value is newest first.
type Sort string

// Sort orders the list supports. Every one but date needs the server's SORT
// extension; without it the list falls back to arrival order.
const (
	SortDate    Sort = ""
	SortFrom    Sort = "from"
	SortSubject Sort = "subject"
	SortSize    Sort = "size"
)

// ListQuery selects and orders the messages of one folder. The zero value
// lists everything, newest first.
type ListQuery struct {
	Text          string // full-text match on headers and body
	From          string
	To            string
	Subject       string
	Unread        bool
	Flagged       bool
	Answered      bool
	HasAttachment bool
	Tag           string
	Since         time.Time // on or after this day
	Before        time.Time // before this day
	Sort          Sort
	Reverse       bool // oldest first, or Z to A
	Page          int  // 1-based
	PageSize      int
}

// Filtered reports whether q restricts the folder at all, as opposed to
// only paging and ordering it.
func (q ListQuery) Filtered() bool {
	return q.Text != "" || q.From != "" || q.To != "" || q.Subject != "" || q.Unread || q.Flagged ||
		q.Answered || q.HasAttachment || q.Tag != "" || !q.Since.IsZero() || !q.Before.IsZero()
}

// Flags the UI sets and clears. Tags are stored as IMAP keywords alongside them.
const (
	FlagSeen     = `\Seen`
	FlagFlagged  = `\Flagged`
	FlagAnswered = `\Answered`
	// FlagForwarded is the keyword most clients use to mark a forwarded
	// message (RFC 5788 registry).
	FlagForwarded = "$Forwarded"
)

// Mailstore is the webmail's view of one user's mailboxes. The IMAP
// implementation is the real one; handlers depend on this interface so they
// can be tested without a server.
//
// A Mailstore is used by one request at a time: IMAP's selected-mailbox state
// is per connection, so callers serialise access (see Session.withStore).
type Mailstore interface {
	Folders(ctx context.Context) ([]Folder, error)
	// List returns one page of folder matching q.
	List(ctx context.Context, folder string, q ListQuery) (Page, error)
	// ListThreads returns one page of folder's conversations matching q,
	// most recent activity first. Each conversation lists every matching
	// message in it.
	ListThreads(ctx context.Context, folder string, q ListQuery) (ThreadPage, error)
	// Raw returns the full RFC 5322 source of a message, without marking it
	// read. maxBytes caps the download; ErrTooLarge reports a bigger message.
	Raw(ctx context.Context, folder string, uid uint32, maxBytes int64) ([]byte, error)
	// SetFlags adds (on) or removes flags and tags on messages.
	SetFlags(ctx context.Context, folder string, uids []uint32, flags []string, on bool) error
	Move(ctx context.Context, folder string, uids []uint32, dest string) error
	// Delete moves messages to Trash, or removes them for good when they are
	// already in Trash or Junk (or there is no Trash folder).
	Delete(ctx context.Context, folder string, uids []uint32) error
	// Expunge removes messages for good, wherever they are.
	Expunge(ctx context.Context, folder string, uids []uint32) error
	// Append stores a message (a sent copy or a draft) in the folder with the
	// given role, creating that folder if the account has none.
	Append(ctx context.Context, role Role, raw []byte, seen, draft bool) error

	CreateFolder(ctx context.Context, name string) error
	// EnsureFolders creates a folder for each role the account lacks, under
	// its conventional name (Drafts, Sent, Junk, Trash).
	EnsureFolders(ctx context.Context, roles []Role) error
	RenameFolder(ctx context.Context, from, to string) error
	DeleteFolder(ctx context.Context, name string) error
	// MarkAllRead marks every message in folder read.
	MarkAllRead(ctx context.Context, folder string) error
	// EmptyFolder removes every message in folder for good.
	EmptyFolder(ctx context.Context, folder string) error
	// Delimiter is the hierarchy separator of folder names ("/" or ".").
	Delimiter(ctx context.Context) (string, error)
	// Tags lists the user keywords in use in folder, for suggestions.
	Tags(ctx context.Context, folder string) ([]string, error)
	// Related finds the messages in folders that belong to the same
	// conversation as the given Message-IDs: those IDs themselves, and
	// anything whose References or In-Reply-To name one of them.
	Related(ctx context.Context, folders []string, ids []string) ([]Related, error)

	ObjectStore
	Close() error
}

// Errors a Mailstore returns that handlers map to user-facing pages.
var (
	ErrAuthFailed = errors.New("webmail: authentication failed")
	ErrNotFound   = errors.New("webmail: message or folder not found")
	ErrTooLarge   = errors.New("webmail: message too large to display")
	ErrExists     = errors.New("webmail: a folder with that name already exists")
	// ErrLoginRefused is a correct sign-in the server turned away, usually
	// because the account has too many connections open.
	ErrLoginRefused = errors.New("webmail: sign-in refused by the mail server")
)

// Dialer opens a Mailstore authenticated as one user.
type Dialer func(ctx context.Context, username, password string) (Mailstore, error)
