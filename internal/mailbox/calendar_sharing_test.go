package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/google/uuid"
)

const calendarMemberPassword = "member-password"

// calendarRig is an owner with mail and a calendar, a member, and a service
// listening as the webmail's internal listener does.
type calendarRig struct {
	e             *Engine
	s             *Service
	owner, member Account
	addr          string
}

func newCalendarRig(t *testing.T) *calendarRig {
	t.Helper()
	e, owner := testEngine(t)
	ctx := context.Background()
	domain := owner.Address[strings.LastIndexByte(owner.Address, '@'):]
	member := Account{ID: uuid.NewString(), Address: "member-" + uuid.NewString()[:8] + domain}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, member.ID) })
	if err := e.EnsureAccount(ctx, member); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(ctx, owner.ID, calendarFolder); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(ctx, owner.ID, "Private"); err != nil {
		t.Fatal(err)
	}
	for _, folder := range []string{"INBOX", calendarFolder, "Private"} {
		if _, err := e.Append(ctx, owner.ID, folder, []byte("Subject: in "+folder+"\r\n\r\nsecret\r\n"), nil, time.Time{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	s, err := newService(cfg, e, shareAuth{owner: owner, member: member}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.imap.Serve(ln) }()
	// The listener too: with no client connected, Close can arrive before Serve
	// has started, and Serve would then wait on it forever.
	t.Cleanup(func() { s.cancel(); _ = s.imap.Close(); _ = ln.Close(); <-done })
	return &calendarRig{e: e, s: s, owner: owner, member: member, addr: ln.Addr().String()}
}

func (r *calendarRig) grant(t *testing.T, level string) {
	t.Helper()
	if _, err := r.e.GrantCalendar(context.Background(), r.owner, r.member, level); err != nil {
		t.Fatal(err)
	}
}

func (r *calendarRig) scoped() string {
	return r.member.Address + "|" + r.owner.Address + calendarLoginSuffix
}

func (r *calendarRig) dial(t *testing.T) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(r.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Login(r.scoped(), calendarMemberPassword).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	return c
}

// refused runs a command that must fail with the session still usable.
func refused(t *testing.T, name string, run func() error) {
	t.Helper()
	if err := run(); err == nil {
		t.Errorf("%s was allowed", name)
	}
}

func folderNames(t *testing.T, c *imapclient.Client) []string {
	t.Helper()
	list, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range list {
		out = append(out, m.Mailbox)
	}
	return out
}

func appendTo(c *imapclient.Client, folder string) error {
	raw := []byte("Subject: planted\r\n\r\nbody\r\n")
	cmd := c.Append(folder, int64(len(raw)), nil)
	if _, err := cmd.Write(raw); err != nil {
		return err
	}
	if err := cmd.Close(); err != nil {
		return err
	}
	_, err := cmd.Wait()
	return err
}

// escapes tries every way out of the calendar folder. It runs at each level,
// because a grant to edit a calendar is no grant to touch anything else.
func escapes(t *testing.T, c *imapclient.Client) {
	t.Helper()
	if got := folderNames(t, c); len(got) != 1 || got[0] != calendarFolder {
		t.Errorf("LIST shows %v", got)
	}
	refused(t, "SELECT INBOX", func() error { _, err := c.Select("INBOX", nil).Wait(); return err })
	refused(t, "SELECT INBOX by another case", func() error { _, err := c.Select("inbox", nil).Wait(); return err })
	refused(t, "SELECT another folder", func() error { _, err := c.Select("Private", nil).Wait(); return err })
	refused(t, "EXAMINE INBOX", func() error {
		_, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
		return err
	})
	refused(t, "STATUS INBOX", func() error {
		_, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		return err
	})
	refused(t, "APPEND to INBOX", func() error { return appendTo(c, "INBOX") })
	refused(t, "CREATE a folder", func() error { return c.Create("Elsewhere", nil).Wait() })
	refused(t, "DELETE the calendar", func() error { return c.Delete(calendarFolder).Wait() })
	refused(t, "DELETE a folder", func() error { return c.Delete("Private").Wait() })
	refused(t, "RENAME the calendar", func() error { return c.Rename(calendarFolder, "Moved", nil).Wait() })
	refused(t, "RENAME a folder into view", func() error { return c.Rename("INBOX", calendarFolder, nil).Wait() })
	refused(t, "SUBSCRIBE", func() error { return c.Subscribe("INBOX").Wait() })
	refused(t, "UNSUBSCRIBE", func() error { return c.Unsubscribe("INBOX").Wait() })
	refused(t, "GETQUOTAROOT", func() error { _, err := c.GetQuotaRoot("INBOX").Wait(); return err })
	refused(t, "GETQUOTA", func() error { _, err := c.GetQuota("").Wait(); return err })

	if _, err := c.Select(calendarFolder, nil).Wait(); err != nil {
		t.Fatalf("SELECT Calendar: %v", err)
	}
	all := imap.UIDSetNum(1)
	refused(t, "COPY out", func() error { _, err := c.Copy(all, "INBOX").Wait(); return err })
	refused(t, "COPY to another folder", func() error { _, err := c.Copy(all, "Private").Wait(); return err })
	refused(t, "MOVE out", func() error { _, err := c.Move(all, "INBOX").Wait(); return err })
}

func TestCalendarGrantCantLeaveTheCalendar(t *testing.T) {
	for _, level := range []string{CalendarView, CalendarEdit, CalendarDelegate} {
		t.Run(level, func(t *testing.T) {
			r := newCalendarRig(t)
			r.grant(t, level)
			escapes(t, r.dial(t))
			// The owner's other folders are as they were.
			ctx := context.Background()
			for _, folder := range []string{"INBOX", "Private", calendarFolder} {
				if _, msgs, err := r.e.Snapshot(ctx, r.owner.ID, folder); err != nil || len(msgs) != 1 {
					t.Errorf("%s now holds %d, %v", folder, len(msgs), err)
				}
			}
		})
	}
}

func TestCalendarViewIsReadOnly(t *testing.T) {
	r := newCalendarRig(t)
	r.grant(t, CalendarView)
	c := r.dial(t)
	if _, err := c.Select(calendarFolder, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	msgs, err := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("can't read the calendar: %d, %v", len(msgs), err)
	}
	refused(t, "APPEND", func() error { return appendTo(c, calendarFolder) })
	refused(t, "CREATE the calendar", func() error { return c.Create(calendarFolder, nil).Wait() })
	refused(t, "STORE", func() error {
		return c.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close()
	})
	refused(t, "EXPUNGE", func() error { return c.Expunge().Close() })
	if _, got, err := r.e.Snapshot(context.Background(), r.owner.ID, calendarFolder); err != nil || len(got) != 1 {
		t.Fatalf("the calendar changed: %d, %v", len(got), err)
	}
}

func TestCalendarEditCanWrite(t *testing.T) {
	r := newCalendarRig(t)
	r.grant(t, CalendarEdit)
	c := r.dial(t)
	if err := appendTo(c, calendarFolder); err != nil {
		t.Fatalf("APPEND: %v", err)
	}
	if _, err := c.Select(calendarFolder, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatalf("STORE: %v", err)
	}
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}
	if _, got, err := r.e.Snapshot(context.Background(), r.owner.ID, calendarFolder); err != nil || len(got) != 1 {
		t.Fatalf("the calendar holds %d, %v", len(got), err)
	}
}

func TestCalendarLoginRefusals(t *testing.T) {
	r := newCalendarRig(t)
	ctx := context.Background()
	login := func(user, password string) error {
		_, _, err := (&imapSession{service: r.s, ctx: ctx}).signIn(user, password)
		return err
	}
	if err := login(r.scoped(), calendarMemberPassword); !errors.Is(err, ErrCredentials) {
		t.Fatalf("no grant: %v", err)
	}
	r.grant(t, CalendarView)
	if err := login(r.scoped(), calendarMemberPassword); err != nil {
		t.Fatalf("with a grant: %v", err)
	}
	for name, try := range map[string]func() error{
		"a wrong password":       func() error { return login(r.scoped(), "wrong") },
		"an administrator token": func() error { return login(r.scoped(), adminTokenPrefix+"anything") },
		"a third address": func() error {
			return login(r.member.Address+"|other@example.com"+calendarLoginSuffix, calendarMemberPassword)
		},
		"nesting": func() error {
			return login(r.member.Address+"|"+r.owner.Address+"|"+r.owner.Address+calendarLoginSuffix, calendarMemberPassword)
		},
		// The webmail is what hides private events, so a mail app can't use this.
		"a public listener": func() error {
			_, _, err := (&imapSession{service: r.s, ctx: ctx, public: true}).signIn(r.scoped(), calendarMemberPassword)
			return err
		},
		// A calendar grant isn't a mailbox grant, by any other path.
		"the mailbox login": func() error {
			_, err := r.s.login(ctx, r.member.Address+"|"+r.owner.Address, calendarMemberPassword, false, "", "")
			return err
		},
		"the scoped name on the mailbox login": func() error {
			_, err := r.s.login(ctx, r.scoped(), calendarMemberPassword, false, "", "")
			return err
		},
		"the security API": func() error {
			_, err := r.s.securityLogin(ctx, r.scoped(), calendarMemberPassword)
			return err
		},
	} {
		if err := try(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := r.e.RevokeCalendar(ctx, r.owner.ID, r.member.ID); err != nil {
		t.Fatal(err)
	}
	if err := login(r.scoped(), calendarMemberPassword); !errors.Is(err, ErrCredentials) {
		t.Fatalf("revoked: %v", err)
	}
}

// A level is read at sign-in, so an open connection has to notice a change.
func TestChangedGrantEndsTheSession(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *calendarRig){
		"cut back to view": func(t *testing.T, r *calendarRig) { r.grant(t, CalendarView) },
		"revoked": func(t *testing.T, r *calendarRig) {
			if err := r.e.RevokeCalendar(context.Background(), r.owner.ID, r.member.ID); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newCalendarRig(t)
			r.grant(t, CalendarEdit)
			server, client := net.Pipe()
			defer func() { _ = client.Close() }()
			ticks := make(chan time.Time)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &imapSession{service: r.s, ctx: ctx, cancel: cancel, conn: server, recheck: ticks,
				user: r.scoped(), password: calendarMemberPassword, account: r.owner, calendarLevel: CalendarEdit}
			go s.watchCredentials()
			ticks <- time.Now() // unchanged: the session stays
			change(t, r)
			// That check may still be running and catch the change itself,
			// in which case nothing is left to take this one.
			select {
			case ticks <- time.Now():
			case <-time.After(2 * time.Second):
			}
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
				t.Fatalf("the session outlived the change: %v", err)
			}
		})
	}
}

func TestGrantCalendarRules(t *testing.T) {
	r := newCalendarRig(t)
	ctx := context.Background()
	if _, err := r.e.GrantCalendar(ctx, r.owner, r.owner, CalendarView); err == nil {
		t.Error("shared a calendar with its owner")
	}
	if _, err := r.e.GrantCalendar(ctx, r.owner, r.member, "owner"); err == nil {
		t.Error("accepted an unknown level")
	}
	outside := Account{ID: uuid.NewString(), Address: "x@elsewhere.example"}
	if _, err := r.e.GrantCalendar(ctx, r.owner, outside, CalendarView); err == nil {
		t.Error("shared across domains")
	}
	r.grant(t, CalendarView)
	r.grant(t, CalendarEdit) // changes the level, not a second row
	shares, err := r.e.CalendarSharesFor(ctx, r.member.ID)
	if err != nil || len(shares) != 1 || shares[0].Level != CalendarEdit || shares[0].OwnerID != r.owner.ID {
		t.Fatalf("shares %+v, %v", shares, err)
	}
}

func TestCalendarShareAPI(t *testing.T) {
	r := newCalendarRig(t)
	r.grant(t, CalendarView)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:5000"
		req.SetBasicAuth(r.member.Address, calendarMemberPassword)
		w := httptest.NewRecorder()
		r.s.http.Handler.ServeHTTP(w, req)
		return w
	}
	w := call(http.MethodGet, "/v1/calendar-shares", "")
	var listed struct {
		Received []struct {
			Owner, Level string
			OwnerID      string `json:"owner_id"`
		} `json:"received"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed.Received) != 1 || listed.Received[0].Level != CalendarView || listed.Received[0].OwnerID != r.owner.ID {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	busy := `{"from":"2026-11-01T00:00:00Z","to":"2026-11-02T00:00:00Z","busy":[]}`
	path := "/v1/calendar-shares/" + r.owner.Address + "/freebusy"
	if w := call(http.MethodPut, path, busy); w.Code == http.StatusOK {
		t.Fatal("a viewer published the owner's free/busy")
	}
	r.grant(t, CalendarEdit)
	if w := call(http.MethodPut, path, busy); w.Code != http.StatusOK {
		t.Fatalf("an editor couldn't publish free/busy: %d %s", w.Code, w.Body.String())
	}
	// The member shares their own calendar, never someone else's.
	if w := call(http.MethodPut, "/v1/calendar-shares/"+r.owner.Address, `{"level":"edit"}`); w.Code != http.StatusOK {
		t.Fatalf("sharing my own calendar: %d %s", w.Code, w.Body.String())
	}
	if got, err := r.e.CalendarLevel(context.Background(), r.member.ID, r.owner.ID); err != nil || got != CalendarEdit {
		t.Fatalf("level %q, %v", got, err)
	}
	if got, _ := r.e.CalendarLevel(context.Background(), r.owner.ID, r.member.ID); got != CalendarEdit {
		t.Fatalf("that changed a grant on the owner's calendar: %q", got)
	}
}
