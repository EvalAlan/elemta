package mailbox

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

type scheduleRig struct {
	t      *testing.T
	e      *Engine
	svc    *Service
	a      Account
	submit *fakeSubmission
	ctx    context.Context
}

func newScheduleRig(t *testing.T) *scheduleRig {
	t.Helper()
	e, a := testEngine(t)
	submit, addr := startFakeSubmission(t)
	cfg := Config{}.WithDefaults()
	cfg.Server.AllowPlaintextAuth = true
	cfg.Server.LMTPAllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Sieve.SubmitAddr = addr
	svc, _, _ := startTestService(t, e, a, cfg)
	return &scheduleRig{t: t, e: e, svc: svc, a: a, submit: submit, ctx: context.Background()}
}

const scheduledMessage = "From: me@example.com\r\nTo: ana@example.net\r\nSubject: Quarterly numbers\r\n\r\nHere they are.\r\n"

// due makes every waiting row due now, instead of waiting for it.
func (r *scheduleRig) due() {
	r.t.Helper()
	if _, err := r.e.DB.Exec(`UPDATE mailbox_scheduled_sends SET send_at=now()-interval '1 second' WHERE account=$1`, r.a.ID); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.e.DB.Exec(`UPDATE mailbox_snoozes SET until=now()-interval '1 second' WHERE account=$1`, r.a.ID); err != nil {
		r.t.Fatal(err)
	}
}

func (r *scheduleRig) uids(folder string) []uint32 {
	r.t.Helper()
	_, msgs, err := r.e.Snapshot(r.ctx, r.a.ID, folder)
	if err != nil {
		return nil
	}
	out := []uint32{}
	for _, m := range msgs {
		out = append(out, m.UID)
	}
	return out
}

func (r *scheduleRig) flags(folder string, uid uint32) []string {
	r.t.Helper()
	_, msgs, err := r.e.Snapshot(r.ctx, r.a.ID, folder)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, m := range msgs {
		if m.UID == uid {
			return m.Flags
		}
	}
	r.t.Fatalf("no message %d in %s", uid, folder)
	return nil
}

func (r *scheduleRig) schedule(at time.Time) uint32 {
	r.t.Helper()
	// From is the account's own address, as the webmail writes it; a From the
	// account can't use is refused (TestScheduledSendChecksTheMessagesFrom).
	raw := strings.Replace(scheduledMessage, "From: me@example.com", "From: "+r.a.Address, 1)
	uid, err := r.e.ScheduleSend(r.ctx, r.a.ID, []byte(raw), r.a.Address, []string{"ana@example.net", "hidden@example.org"}, at)
	if err != nil {
		r.t.Fatal(err)
	}
	return uid
}

// pendingPush is what the pusher is about to announce for the account.
func (r *scheduleRig) pendingPush() []mailItem {
	r.t.Helper()
	if r.svc.push == nil {
		r.t.Fatal("the test service has no pusher")
	}
	r.svc.push.mu.Lock()
	defer r.svc.push.mu.Unlock()
	if b := r.svc.push.pending[r.a.ID]; b != nil {
		return append([]mailItem(nil), b.items...)
	}
	return nil
}

func (r *scheduleRig) pending() []ScheduledSend {
	r.t.Helper()
	list, err := r.e.ScheduledSends(r.ctx, r.a.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return list
}

func TestScheduledSendGoesAtItsTime(t *testing.T) {
	r := newScheduleRig(t)
	if err := r.e.Create(r.ctx, r.a.ID, "Sent"); err != nil {
		t.Fatal(err)
	}
	uid := r.schedule(time.Now().Add(time.Hour))
	if got := r.uids(scheduledFolder); len(got) != 1 || got[0] != uid {
		t.Fatalf("Scheduled holds %v, want [%d]", got, uid)
	}
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.submit.messages()); n != 0 {
		t.Fatalf("sent %d messages an hour early", n)
	}

	r.due()
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	sent := r.submit.messages()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}
	if sent[0].from != r.a.Address || strings.Join(sent[0].to, ",") != "ana@example.net,hidden@example.org" {
		t.Errorf("envelope %s -> %v", sent[0].from, sent[0].to)
	}
	if !strings.Contains(string(sent[0].data), "Here they are.") {
		t.Errorf("sent the wrong body: %q", sent[0].data)
	}
	if got := r.uids(scheduledFolder); len(got) != 0 {
		t.Errorf("Scheduled still holds %v after sending", got)
	}
	if got := r.uids("Sent"); len(got) != 1 {
		t.Errorf("Sent holds %v, want the message", got)
	}
	if p := r.pending(); len(p) != 0 {
		t.Errorf("rows left after sending: %+v", p)
	}
	// Nothing goes twice.
	r.due()
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.submit.messages()); n != 1 {
		t.Errorf("sent %d times", n)
	}
}

// Deleting or moving the message, from any client, cancels it.
func TestScheduledSendCancelledByDeletingTheMessage(t *testing.T) {
	r := newScheduleRig(t)
	uid := r.schedule(time.Now().Add(time.Hour))
	// As a mail app deletes: flag, then expunge.
	if err := r.e.MutateFlags(r.ctx, r.a.ID, scheduledFolder, []uint32{uid}, []string{`\Deleted`}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.Expunge(r.ctx, r.a.ID, scheduledFolder, []uint32{uid}); err != nil {
		t.Fatal(err)
	}
	if p := r.pending(); len(p) != 0 {
		t.Fatalf("the row outlived its message: %+v", p)
	}

	uid = r.schedule(time.Now().Add(time.Hour))
	if err := r.e.Create(r.ctx, r.a.ID, "Keep"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.e.CopyMove(r.ctx, r.a.ID, scheduledFolder, "Keep", []uint32{uid}, true); err != nil {
		t.Fatal(err)
	}
	if p := r.pending(); len(p) != 0 {
		t.Fatalf("moving the message out didn't cancel it: %+v", p)
	}
	r.due()
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.submit.messages()); n != 0 {
		t.Errorf("sent %d cancelled messages", n)
	}
}

func TestScheduledSendCancelToDrafts(t *testing.T) {
	r := newScheduleRig(t)
	uid := r.schedule(time.Now().Add(time.Hour))
	folder, draft, err := r.e.CancelSend(r.ctx, r.a.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	if folder != "Drafts" || draft == 0 {
		t.Fatalf("cancelled to %s %d", folder, draft)
	}
	if f := r.flags("Drafts", draft); !hasFlag(f, `\Draft`) {
		t.Errorf("the draft's flags are %v", f)
	}
	if _, _, err := r.e.CancelSend(r.ctx, r.a.ID, uid); err != ErrNotFound {
		t.Errorf("cancelling twice: %v, want ErrNotFound", err)
	}
}

func TestScheduledSendReschedule(t *testing.T) {
	r := newScheduleRig(t)
	uid := r.schedule(time.Now().Add(time.Hour))
	later := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if err := r.e.RescheduleSend(r.ctx, r.a.ID, uid, later); err != nil {
		t.Fatal(err)
	}
	if p := r.pending(); len(p) != 1 || !p[0].SendAt.Equal(later) {
		t.Fatalf("after rescheduling: %+v", p)
	}
	// A message being sent right now can't be moved.
	if _, err := r.e.DB.Exec(`UPDATE mailbox_scheduled_sends SET claimed_until=now()+interval '1 minute' WHERE account=$1`, r.a.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.e.RescheduleSend(r.ctx, r.a.ID, uid, later); err != ErrNotFound {
		t.Errorf("rescheduling a claimed message: %v, want ErrNotFound", err)
	}
	if _, _, err := r.e.CancelSend(r.ctx, r.a.ID, uid); err != ErrNotFound {
		t.Errorf("cancelling a claimed message: %v, want ErrNotFound", err)
	}
}

// Two mailbox servers looking at once: one of them sends.
func TestScheduledSendOneClaim(t *testing.T) {
	r := newScheduleRig(t)
	r.schedule(time.Now().Add(-time.Second))
	var wg sync.WaitGroup
	got := make([]int, 4)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := r.e.claimDueSends(r.ctx)
			if err != nil {
				t.Error(err)
			}
			got[i] = len(d)
		}(i)
	}
	wg.Wait()
	total := 0
	for _, n := range got {
		total += n
	}
	if total != 1 {
		t.Errorf("claimed %d times, want once: %v", total, got)
	}
}

// A refusal goes back to Drafts at once, with a note in the inbox.
func TestScheduledSendRefused(t *testing.T) {
	r := newScheduleRig(t)
	r.submit.mu.Lock()
	r.submit.refuse = &smtp.SMTPError{Code: 550, Message: "No such user"}
	r.submit.mu.Unlock()
	r.schedule(time.Now().Add(-time.Second))
	before := len(r.uids("INBOX"))
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if p := r.pending(); len(p) != 0 {
		t.Errorf("a refused message is still waiting: %+v", p)
	}
	if got := r.uids("Drafts"); len(got) != 1 {
		t.Errorf("Drafts holds %v, want the message", got)
	}
	inbox := r.uids("INBOX")
	if len(inbox) != before+1 {
		t.Fatalf("no failure note in the inbox (%d before, %d after)", before, len(inbox))
	}
	_, msgs, _ := r.e.Snapshot(r.ctx, r.a.ID, "INBOX")
	raw, err := r.e.Read(r.ctx, msgs[len(msgs)-1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Subject: Not sent: Quarterly numbers", "No such user", "It's in Drafts"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the note lacks %q:\n%s", want, raw)
		}
	}
}

// A server that isn't answering is tried again later, not given up on.
func TestScheduledSendRetriesTemporaryFailure(t *testing.T) {
	r := newScheduleRig(t)
	r.svc.cfg.Sieve.SubmitAddr = "127.0.0.1:1" // nothing listens there
	r.schedule(time.Now().Add(-time.Second))
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	p := r.pending()
	if len(p) != 1 {
		t.Fatalf("the message is gone after a temporary failure: %+v", p)
	}
	if p[0].Attempts != 1 || p[0].LastError == "" || !p[0].SendAt.After(time.Now()) {
		t.Errorf("after one failure: %+v", p[0])
	}
	if got := r.uids("Drafts"); len(got) != 0 {
		t.Errorf("moved to Drafts after one temporary failure")
	}
}

// Permission to send as an address can be taken away after scheduling.
func TestScheduledSendChecksSendAsAtSendTime(t *testing.T) {
	r := newScheduleRig(t)
	shared := "team@example.com"
	r.svc.auth = testAuth{account: Account{ID: r.a.ID, Address: r.a.Address, SendAs: []string{shared}}}
	if ok, err := r.svc.maySendAs(r.ctx, Account{ID: r.a.ID, Address: r.a.Address, SendAs: []string{shared}}, shared); err != nil || !ok {
		t.Fatalf("maySendAs(granted) = %v, %v", ok, err)
	}
	if _, err := r.e.ScheduleSend(r.ctx, r.a.ID, []byte(scheduledMessage), shared, []string{"ana@example.net"}, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	r.svc.auth = testAuth{account: r.a} // the grant is gone
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.submit.messages()); n != 0 {
		t.Fatalf("sent as %s after the grant went", shared)
	}
	if got := r.uids("Drafts"); len(got) != 1 {
		t.Errorf("Drafts holds %v, want the message", got)
	}
}

func TestSnoozeComesBackUnread(t *testing.T) {
	r := newScheduleRig(t)
	res, err := r.e.Append(r.ctx, r.a.ID, "INBOX", []byte(scheduledMessage), []string{`\Seen`}, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	snoozed, err := r.e.Snooze(r.ctx, r.a.ID, "INBOX", []uint32{res.UID}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(snoozed) != 1 || len(r.uids("INBOX")) != 0 || len(r.uids(snoozedFolder)) != 1 {
		t.Fatalf("after snoozing: snoozed %v, INBOX %v, Snoozed %v", snoozed, r.uids("INBOX"), r.uids(snoozedFolder))
	}
	if err := r.svc.returnDueSnoozes(r.ctx); err != nil {
		t.Fatal(err)
	}
	if len(r.uids("INBOX")) != 0 {
		t.Fatal("came back an hour early")
	}
	r.due()
	if err := r.svc.returnDueSnoozes(r.ctx); err != nil {
		t.Fatal(err)
	}
	inbox := r.uids("INBOX")
	if len(inbox) != 1 || len(r.uids(snoozedFolder)) != 0 {
		t.Fatalf("after its time: INBOX %v, Snoozed %v", inbox, r.uids(snoozedFolder))
	}
	if f := r.flags("INBOX", inbox[0]); hasFlag(f, `\Seen`) {
		t.Errorf("came back read: %v", f)
	}
	// Announced to the user's devices like new mail, and without a tab, so
	// a device that takes only Primary hears it too.
	if items := r.pendingPush(); len(items) != 1 || items[0].uid != inbox[0] || items[0].category != "" || items[0].subject != "Quarterly numbers" {
		t.Errorf("push for the returned message: %+v", items)
	}
	if list, _ := r.e.Snoozes(r.ctx, r.a.ID); len(list) != 0 {
		t.Errorf("snooze rows left: %+v", list)
	}
}

func TestSnoozeReturnsToItsFolderAndUnsnooze(t *testing.T) {
	r := newScheduleRig(t)
	if err := r.e.Create(r.ctx, r.a.ID, "Projects"); err != nil {
		t.Fatal(err)
	}
	res, err := r.e.Append(r.ctx, r.a.ID, "Projects", []byte(scheduledMessage), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	snoozed, err := r.e.Snooze(r.ctx, r.a.ID, "Projects", []uint32{res.UID}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Snoozing again from Snoozed changes the time, not the destination.
	later := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	if _, err := r.e.Snooze(r.ctx, r.a.ID, snoozedFolder, snoozed, later); err != nil {
		t.Fatal(err)
	}
	list, _ := r.e.Snoozes(r.ctx, r.a.ID)
	if len(list) != 1 || !list[0].Until.Equal(later) || list[0].ReturnTo != "Projects" {
		t.Fatalf("after re-snoozing: %+v", list)
	}
	back, err := r.e.Unsnooze(r.ctx, r.a.ID, snoozed)
	if err != nil {
		t.Fatal(err)
	}
	if items := r.pendingPush(); len(items) != 0 {
		t.Errorf("a snooze ended by hand was pushed: %+v", items)
	}
	if len(back["Projects"]) != 1 || len(r.uids("Projects")) != 1 {
		t.Errorf("unsnoozed to %v; Projects holds %v", back, r.uids("Projects"))
	}
}

// Its folder deleted meanwhile, a snoozed message comes back to the inbox.
func TestSnoozeFolderGone(t *testing.T) {
	r := newScheduleRig(t)
	if err := r.e.Create(r.ctx, r.a.ID, "Gone"); err != nil {
		t.Fatal(err)
	}
	res, err := r.e.Append(r.ctx, r.a.ID, "Gone", []byte(scheduledMessage), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.Snooze(r.ctx, r.a.ID, "Gone", []uint32{res.UID}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.e.DeleteFolder(r.ctx, r.a.ID, "Gone"); err != nil {
		t.Fatal(err)
	}
	r.due()
	if err := r.svc.returnDueSnoozes(r.ctx); err != nil {
		t.Fatal(err)
	}
	if got := r.uids("INBOX"); len(got) != 1 {
		t.Errorf("INBOX holds %v, want the message back", got)
	}
}

// A message snoozed from another folder goes back there without a push, as
// mail filed into a folder on delivery isn't announced either.
func TestSnoozeReturnToAFolderIsQuiet(t *testing.T) {
	r := newScheduleRig(t)
	if err := r.e.Create(r.ctx, r.a.ID, "Projects"); err != nil {
		t.Fatal(err)
	}
	res, err := r.e.Append(r.ctx, r.a.ID, "Projects", []byte(scheduledMessage), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.Snooze(r.ctx, r.a.ID, "Projects", []uint32{res.UID}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.due()
	if err := r.svc.returnDueSnoozes(r.ctx); err != nil {
		t.Fatal(err)
	}
	if got := r.uids("Projects"); len(got) != 1 {
		t.Fatalf("Projects holds %v", got)
	}
	if items := r.pendingPush(); len(items) != 0 {
		t.Errorf("a return to Projects was pushed: %+v", items)
	}
}

func TestScheduleValidation(t *testing.T) {
	now := time.Now()
	for _, at := range []time.Time{now.Add(-time.Hour), now.Add(400 * 24 * time.Hour)} {
		if checkScheduleTime(at, now) == nil {
			t.Errorf("accepted %v", at)
		}
	}
	if err := checkScheduleTime(now.Add(-time.Minute), now); err != nil {
		t.Errorf("refused a minute ago (a slow click on Send now): %v", err)
	}
	for _, bad := range [][]string{nil, {"no-at-sign"}, {"a@b@c"}, {"Ana <ana@example.net>"}, {"ana@example.net\r\nRCPT TO:<x@y>"}} {
		if _, err := checkScheduleRecipients(bad); err == nil {
			t.Errorf("accepted recipients %q", bad)
		}
	}
	if got, err := checkScheduleRecipients([]string{" ana@example.net "}); err != nil || got[0] != "ana@example.net" {
		t.Errorf("checkScheduleRecipients = %v, %v", got, err)
	}
}

// The From inside a scheduled message is checked as well as the envelope.
// The message goes out through the MTA's internal relay, where From isn't
// bound to a login, and is signed for the envelope's domain, so an unchecked
// From let a user send as a colleague with an aligned signature.
func TestScheduledSendChecksTheMessagesFrom(t *testing.T) {
	r := newScheduleRig(t)
	forged := strings.Replace(scheduledMessage, "From: me@example.com", "From: CEO <ceo@example.com>", 1)
	if _, ok, err := r.svc.mayAuthor(r.ctx, r.a, []byte(forged)); err != nil || ok {
		t.Fatalf("mayAuthor(colleague) = %v, %v", ok, err)
	}
	own := strings.Replace(scheduledMessage, "From: me@example.com", "From: "+r.a.Address, 1)
	if _, ok, err := r.svc.mayAuthor(r.ctx, r.a, []byte(own)); err != nil || !ok {
		t.Fatalf("mayAuthor(own) = %v, %v", ok, err)
	}

	// Scheduled anyway (straight into the engine), it's refused at send time.
	if _, err := r.e.ScheduleSend(r.ctx, r.a.ID, []byte(forged), r.a.Address, []string{"ana@example.net"}, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.sendDue(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.submit.messages()); n != 0 {
		t.Fatal("a message with someone else's From was sent")
	}
	if got := r.uids("Drafts"); len(got) != 1 {
		t.Errorf("Drafts holds %v, want the message", got)
	}
}
