package webmail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// startIMAP runs an in-memory IMAP server with one user and returns a config
// pointing at it.
func startIMAP(t *testing.T) Config {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("dana@example.com", "secret")
	for _, name := range []string{"INBOX", "Sent", "Trash", "Projects", "Projects/Northwind"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return Config{IMAPAddr: ln.Addr().String(), IMAPTLS: TLSModeNone, SubmissionAddr: "127.0.0.1:1"}.WithDefaults()
}

func testMessage(i int, subject string) []byte {
	return []byte(fmt.Sprintf("From: Priya Shah <priya@northwind.example>\r\nTo: dana@example.com\r\nSubject: %s\r\nDate: Mon, 19 Oct 2026 09:%02d:00 +0000\r\nMessage-Id: <m%d@northwind.example>\r\n\r\nBody number %d.\r\n", subject, i, i, i))
}

func dialTest(t *testing.T, cfg Config) *imapStore {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := dialIMAP(ctx, cfg, "dana@example.com", "secret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func appendTo(t *testing.T, st *imapStore, folder string, raw []byte) {
	t.Helper()
	cmd := st.c.Append(folder, int64(len(raw)), nil)
	if _, err := bytes.NewReader(raw).WriteTo(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestIMAPStoreLoginFailure(t *testing.T) {
	cfg := startIMAP(t)
	_, err := dialIMAP(context.Background(), cfg, "dana@example.com", "wrong")
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestIMAPStoreFoldersAndPaging(t *testing.T) {
	cfg := startIMAP(t)
	st := dialTest(t, cfg)
	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		appendTo(t, st, "INBOX", testMessage(i, fmt.Sprintf("Message %d", i)))
	}

	folders, err := st.Folders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if folders[0].Name != "INBOX" || folders[0].Role != RoleInbox || folders[0].Total != 7 || folders[0].Unread != 7 {
		t.Fatalf("first folder = %+v, want INBOX with 7 unread", folders[0])
	}
	var sub *Folder
	for i := range folders {
		if folders[i].Name == "Projects/Northwind" {
			sub = &folders[i]
		}
	}
	if sub == nil || sub.Display != "Northwind" || sub.Depth != 1 {
		t.Fatalf("nested folder = %+v", sub)
	}

	p, err := st.List(ctx, "INBOX", "", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 7 || p.Pages() != 3 || len(p.Messages) != 3 || p.Messages[0].Subject != "Message 7" {
		t.Fatalf("page 1 = total %d pages %d first %+v", p.Total, p.Pages(), p.Messages)
	}
	p, err = st.List(ctx, "INBOX", "", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Messages) != 1 || p.Messages[0].Subject != "Message 1" {
		t.Fatalf("last page = %+v", p.Messages)
	}
	if got := p.Messages[0].From; len(got) != 1 || got[0].Email != "priya@northwind.example" || got[0].Name != "Priya Shah" {
		t.Fatalf("from = %+v", got)
	}

	p, err = st.List(ctx, "INBOX", "number 4", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 1 || p.Messages[0].Subject != "Message 4" {
		t.Fatalf("search = %+v", p)
	}
}

func TestIMAPStoreReadFlagMoveDelete(t *testing.T) {
	cfg := startIMAP(t)
	st := dialTest(t, cfg)
	ctx := context.Background()
	appendTo(t, st, "INBOX", testMessage(1, "Hello"))
	p, err := st.List(ctx, "INBOX", "", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	uid := p.Messages[0].UID

	raw, err := st.Raw(ctx, "INBOX", uid, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Body number 1.") {
		t.Fatalf("raw = %q", raw)
	}
	if _, err := st.Raw(ctx, "INBOX", uid, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("small limit err = %v, want ErrTooLarge", err)
	}
	if _, err := st.Raw(ctx, "INBOX", uid+100, 1<<20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing uid err = %v, want ErrNotFound", err)
	}
	// Raw peeks; reading must not have marked it.
	p, _ = st.List(ctx, "INBOX", "", 1, 10)
	if p.Messages[0].Seen {
		t.Fatal("Raw marked the message seen")
	}
	if err := st.SetSeen(ctx, "INBOX", uid, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFlagged(ctx, "INBOX", uid, true); err != nil {
		t.Fatal(err)
	}
	p, _ = st.List(ctx, "INBOX", "", 1, 10)
	if !p.Messages[0].Seen || !p.Messages[0].Flagged {
		t.Fatalf("flags = %+v", p.Messages[0])
	}

	if err := st.Move(ctx, "INBOX", uid, "Projects"); err != nil {
		t.Fatal(err)
	}
	p, _ = st.List(ctx, "Projects", "", 1, 10)
	if len(p.Messages) != 1 {
		t.Fatalf("Projects after move = %+v", p.Messages)
	}

	// Delete outside Trash moves to Trash; inside Trash it's permanent.
	if err := st.Delete(ctx, "Projects", p.Messages[0].UID); err != nil {
		t.Fatal(err)
	}
	trash, _ := st.List(ctx, "Trash", "", 1, 10)
	if len(trash.Messages) != 1 {
		t.Fatalf("Trash = %+v", trash.Messages)
	}
	if err := st.Delete(ctx, "Trash", trash.Messages[0].UID); err != nil {
		t.Fatal(err)
	}
	trash, _ = st.List(ctx, "Trash", "", 1, 10)
	if len(trash.Messages) != 0 {
		t.Fatalf("Trash after permanent delete = %+v", trash.Messages)
	}
}

func TestIMAPStoreAppendCreatesRoleFolder(t *testing.T) {
	cfg := startIMAP(t)
	st := dialTest(t, cfg)
	ctx := context.Background()
	if err := st.Append(ctx, RoleSent, testMessage(1, "Sent copy"), true, false); err != nil {
		t.Fatal(err)
	}
	// There is no Drafts folder yet; Append must create it.
	if err := st.Append(ctx, RoleDrafts, testMessage(2, "Draft"), true, true); err != nil {
		t.Fatal(err)
	}
	p, err := st.List(ctx, "Drafts", "", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Messages) != 1 || !p.Messages[0].Draft || !p.Messages[0].Seen {
		t.Fatalf("Drafts = %+v", p.Messages)
	}
	p, _ = st.List(ctx, "Sent", "", 1, 10)
	if len(p.Messages) != 1 || p.Messages[0].Subject != "Sent copy" {
		t.Fatalf("Sent = %+v", p.Messages)
	}
}

func TestRoleOf(t *testing.T) {
	cases := []struct {
		name  string
		attrs []imap.MailboxAttr
		want  Role
	}{
		{"inbox", nil, RoleInbox},
		{"Gesendet", []imap.MailboxAttr{imap.MailboxAttrSent}, RoleSent},
		{"Deleted Items", nil, RoleTrash},
		{"Spam", nil, RoleJunk},
		{"Projects", nil, RoleNone},
	}
	for _, c := range cases {
		if got := roleOf(c.name, c.attrs); got != c.want {
			t.Errorf("roleOf(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
