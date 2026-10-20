package migrate

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// fakeImporter keeps imports in memory and, like the mailbox, stores a key
// once.
type fakeImporter struct {
	mu    sync.Mutex
	byKey map[string]mailpolicy.Import
	calls int
}

func (f *fakeImporter) Import(_ context.Context, m mailpolicy.Import) (mailpolicy.ImportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.byKey == nil {
		f.byKey = map[string]mailpolicy.Import{}
	}
	if _, ok := f.byKey[m.Key]; ok {
		return mailpolicy.ImportResult{UID: 1, Duplicate: true}, nil
	}
	f.byKey[m.Key] = m
	return mailpolicy.ImportResult{UID: uint32(len(f.byKey)), Folder: m.Folder}, nil
}

func (f *fakeImporter) folder(name string) []mailpolicy.Import {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []mailpolicy.Import
	for _, m := range f.byKey {
		if m.Folder == name {
			out = append(out, m)
		}
	}
	return out
}

// startSource runs an in-memory IMAP server with one user's mail.
func startSource(t *testing.T) (string, *imapclient.Client) {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("old@source.example", "secret")
	for _, name := range []string{"INBOX", "Sent Items", "Projects", "Projects/Alpha", "Deleted Items"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatal(err)
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
	c, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login("old@source.example", "secret").Wait(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return ln.Addr().String(), c
}

func put(t *testing.T, c *imapclient.Client, folder, subject string, flags []imap.Flag, date time.Time) {
	t.Helper()
	raw := []byte("From: someone@example.org\r\nSubject: " + subject + "\r\nMessage-ID: <" + strings.ReplaceAll(subject, " ", "-") + "@x>\r\n\r\nbody of " + subject + "\r\n")
	cmd := c.Append(folder, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: date})
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

func TestMailMigration(t *testing.T) {
	addr, c := startSource(t)
	when := time.Date(2024, 3, 1, 9, 30, 0, 0, time.UTC)
	put(t, c, "INBOX", "hello", []imap.Flag{imap.FlagSeen, "$Important"}, when)
	put(t, c, "INBOX", "unread", nil, when)
	put(t, c, "INBOX", "gone", []imap.Flag{imap.FlagDeleted}, when)
	put(t, c, "Sent Items", "my reply", []imap.Flag{imap.FlagSeen, imap.FlagAnswered}, when)
	put(t, c, "Projects/Alpha", "plan", nil, when)

	src := Source{Addr: addr, TLS: "none", User: "old@source.example", Password: "secret"}
	to := &fakeImporter{}
	opts := Options{StateDir: t.TempDir(), Batch: 2}
	rep, err := Mail(context.Background(), src, "dana@example.com", to, opts)
	if err != nil {
		t.Fatal(err)
	}
	tot := rep.Totals()
	if tot.Copied != 4 || tot.Deleted != 1 || tot.Failed != 0 {
		t.Fatalf("totals = %+v (folders %+v)", tot, rep.Folders)
	}
	inbox := to.folder("INBOX")
	if len(inbox) != 2 {
		t.Fatalf("INBOX got %d messages", len(inbox))
	}
	for _, m := range inbox {
		if strings.Contains(string(m.Raw), "hello") {
			if strings.Join(m.Flags, ",") != `\Seen,$Important` && strings.Join(m.Flags, ",") != `$Important,\Seen` {
				t.Errorf("flags = %v", m.Flags)
			}
			if !m.Date.Equal(when) {
				t.Errorf("date = %v, want %v", m.Date, when)
			}
		}
	}
	// "Sent Items" becomes the webmail's Sent; nested folders keep their path.
	if len(to.folder("Sent")) != 1 || len(to.folder("Projects/Alpha")) != 1 {
		t.Fatalf("folder mapping: sent %d, alpha %d", len(to.folder("Sent")), len(to.folder("Projects/Alpha")))
	}

	// Running again downloads nothing: the state remembers each folder.
	calls := to.calls
	if _, err := Mail(context.Background(), src, "dana@example.com", to, opts); err != nil {
		t.Fatal(err)
	}
	if to.calls != calls {
		t.Errorf("a rerun imported %d more messages", to.calls-calls)
	}

	// New mail at the source is picked up on the next run, and only it.
	put(t, c, "INBOX", "later", nil, when)
	rep, err = Mail(context.Background(), src, "dana@example.com", to, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Totals().Copied; got != 1 || len(to.folder("INBOX")) != 3 {
		t.Errorf("incremental run copied %d (INBOX now %d)", got, len(to.folder("INBOX")))
	}

	// Without the state file every message is offered again, and the
	// import keys make them all skips.
	rep, err = Mail(context.Background(), src, "dana@example.com", to, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if tot := rep.Totals(); tot.Copied != 0 || tot.Skipped != 5 {
		t.Errorf("stateless rerun = %+v", tot)
	}

	// Wrong source password fails clearly.
	if _, err := Mail(context.Background(), Source{Addr: addr, TLS: "none", User: "old@source.example", Password: "nope"}, "dana@example.com", to, Options{}); err == nil || !strings.Contains(err.Error(), "sign in") {
		t.Errorf("bad password: %v", err)
	}
}

const sampleICS = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Old//EN\r\n" +
	"BEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n" +
	"BEGIN:VEVENT\r\nUID:weekly@old\r\nDTSTAMP:20240101T000000Z\r\nDTSTART;TZID=Europe/Paris:20240105T100000\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Weekly sync\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:weekly@old\r\nDTSTAMP:20240101T000000Z\r\nRECURRENCE-ID;TZID=Europe/Paris:20240112T100000\r\nDTSTART;TZID=Europe/Paris:20240112T110000\r\nSUMMARY:Weekly sync (moved)\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nDTSTAMP:20240101T000000Z\r\nDTSTART:20240201T090000Z\r\nSUMMARY:No UID\r\nEND:VEVENT\r\n" +
	"BEGIN:VTODO\r\nUID:task@old\r\nDTSTAMP:20240101T000000Z\r\nSUMMARY:File taxes\r\nEND:VTODO\r\n" +
	"END:VCALENDAR\r\n"

const sampleVCF = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:priya@old\r\nFN:Priya Shah\r\nEMAIL:priya@northwind.example\r\nEND:VCARD\r\n" +
	"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:No Uid Person\r\nEMAIL:nouid@example.org\r\nEND:VCARD\r\n"

func TestCalendarAndContacts(t *testing.T) {
	objs, err := SplitCalendar(strings.NewReader(sampleICS))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 3 {
		t.Fatalf("got %d objects, want 3 (the series with its exception, the event without a UID, the task)", len(objs))
	}
	series := objs[0]
	if series.ID != "weekly@old" || series.Folder != "Calendar" || strings.Count(string(series.Data), "BEGIN:VEVENT") != 2 || !strings.Contains(string(series.Data), "BEGIN:VTIMEZONE") {
		t.Errorf("series object:\n%s", series.Data)
	}
	if !strings.HasPrefix(objs[1].ID, "import-") || objs[2].Folder != "Tasks" || objs[2].Title != "File taxes" {
		t.Errorf("objects = %+v / %+v", objs[1], objs[2])
	}
	again, _ := SplitCalendar(strings.NewReader(sampleICS))
	if again[1].ID != objs[1].ID {
		t.Error("an entry without a UID got a different ID on a second read")
	}
	cards, err := SplitContacts(strings.NewReader(sampleVCF))
	if err != nil || len(cards) != 2 || cards[0].ID != "priya@old" || cards[0].Title != "Priya Shah" || !strings.HasPrefix(cards[1].ID, "import-") {
		t.Fatalf("contacts = %+v, %v", cards, err)
	}

	to := &fakeImporter{}
	rep, err := ImportObjects(context.Background(), "dana@example.com", append(objs, cards...), to)
	if err != nil || rep.Imported != 5 {
		t.Fatalf("import = %+v, %v", rep, err)
	}
	if got := to.folder("Contacts"); len(got) != 2 || !strings.Contains(string(got[0].Raw), "X-Elemta-Object") && !strings.Contains(string(got[0].Raw), "Elemta Webmail") {
		t.Errorf("contacts weren't stored as webmail objects: %v", got)
	}
	rep, _ = ImportObjects(context.Background(), "dana@example.com", append(objs, cards...), to)
	if rep.Imported != 0 || rep.Skipped != 5 {
		t.Errorf("rerun = %+v", rep)
	}
}
