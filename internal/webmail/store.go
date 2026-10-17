package webmail

import (
	"context"
	"errors"
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
	UID      uint32
	From     []Address
	To       []Address
	Subject  string
	Date     time.Time
	Size     int64
	Seen     bool
	Flagged  bool
	Answered bool
	Draft    bool
}

// Page is a window of a folder's messages, newest first.
type Page struct {
	Folder   string
	Messages []Summary
	Total    int // messages matching, across all pages
	Page     int // 1-based
	PageSize int
}

// Pages is the number of pages Total spans.
func (p Page) Pages() int {
	if p.PageSize <= 0 || p.Total == 0 {
		return 1
	}
	return (p.Total + p.PageSize - 1) / p.PageSize
}

// Mailstore is the webmail's view of one user's mailboxes. The IMAP
// implementation is the real one; handlers depend on this interface so they
// can be tested without a server.
//
// A Mailstore is used by one request at a time: IMAP's selected-mailbox state
// is per connection, so callers serialise access (see Session.withStore).
type Mailstore interface {
	Folders(ctx context.Context) ([]Folder, error)
	// List returns page (1-based) of folder, newest first. A non-empty
	// query restricts it to messages whose text matches.
	List(ctx context.Context, folder, query string, page, pageSize int) (Page, error)
	// Raw returns the full RFC 5322 source of a message, without marking it
	// read. maxBytes caps the download; ErrTooLarge reports a bigger message.
	Raw(ctx context.Context, folder string, uid uint32, maxBytes int64) ([]byte, error)
	SetSeen(ctx context.Context, folder string, uid uint32, seen bool) error
	SetFlagged(ctx context.Context, folder string, uid uint32, flagged bool) error
	Move(ctx context.Context, folder string, uid uint32, dest string) error
	// Delete moves a message to Trash, or removes it for good when it is
	// already in Trash (or there is no Trash folder).
	Delete(ctx context.Context, folder string, uid uint32) error
	// Append stores a message (a sent copy or a draft) in the folder with the
	// given role, creating that folder if the account has none.
	Append(ctx context.Context, role Role, raw []byte, seen, draft bool) error
	Close() error
}

// Errors a Mailstore returns that handlers map to user-facing pages.
var (
	ErrAuthFailed = errors.New("webmail: authentication failed")
	ErrNotFound   = errors.New("webmail: message or folder not found")
	ErrTooLarge   = errors.New("webmail: message too large to display")
)

// Dialer opens a Mailstore authenticated as one user.
type Dialer func(ctx context.Context, username, password string) (Mailstore, error)
