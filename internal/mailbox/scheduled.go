package mailbox

// Scheduled send and snooze.
//
// Both have to happen when nobody is signed in, so they run here rather than
// in the webmail, which only ever holds a user's password for the length of a
// session. A scheduled message goes out through sieve.submit_addr, the same
// trusted submission path vacation replies, redirects and list expansion
// already use; the user's credentials are needed only to schedule it, through
// the account API.
//
// The messages themselves are ordinary messages in two folders, Scheduled and
// Snoozed, created on first use as Quarantine is. Storing them through Append
// keeps body encryption, compression and quota, and any mail app can see what
// is waiting. A row beside each message says when to act, and it is tied to
// the message by a foreign key (schema.sql): deleting the message, or moving
// it out of the folder, from the webmail or any IMAP client, cancels it.
//
// Sending is at least once. A server that dies between handing a message to
// the MTA and moving it to Sent leaves its claim to lapse, and another server
// sends it again five minutes later. The window is the length of one SMTP
// transaction; losing a scheduled message would be worse.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"net/mail"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/lib/pq"
)

const (
	scheduledFolder = "Scheduled"
	snoozedFolder   = "Snoozed"
	// maxScheduleAhead bounds both a send time and a snooze: far enough for
	// "remind me next year", near enough that a typo in the year is caught.
	maxScheduleAhead = 366 * 24 * time.Hour
	// maxScheduledRecipients matches what the webmail's compose accepts.
	maxScheduledRecipients = 500
	// scheduleClaim is how long a server has to act on a row it claimed
	// before another may.
	scheduleClaim = 5 * time.Minute
	// maxSendAttempts gives a temporary failure (the MTA restarting, a
	// full queue) about two hours before the message goes back to Drafts.
	maxSendAttempts = 6
)

// sendRetry is the wait before attempt n+1 after a temporary failure.
func sendRetry(attempt int) time.Duration {
	steps := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(steps) {
		return steps[len(steps)-1]
	}
	return steps[attempt-1]
}

// ScheduledSend is one message waiting in Scheduled.
type ScheduledSend struct {
	UID       uint32    `json:"uid"`
	SendAt    time.Time `json:"send_at"`
	From      string    `json:"from"`
	To        []string  `json:"to"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
}

// SnoozedMessage is one message waiting in Snoozed.
type SnoozedMessage struct {
	UID      uint32    `json:"uid"`
	Until    time.Time `json:"until"`
	ReturnTo string    `json:"return_to"`
}

// ensureFolder creates name unless it exists.
func (e *Engine) ensureFolder(ctx context.Context, account, name string) (Folder, error) {
	if err := e.Create(ctx, account, name); err != nil && !errors.Is(err, ErrExists) {
		return Folder{}, err
	}
	return e.Folder(ctx, account, name)
}

// existingFolder is the first of names the account has, or the first name.
func (e *Engine) existingFolder(ctx context.Context, account string, names ...string) string {
	for _, n := range names {
		if _, err := e.Folder(ctx, account, n); err == nil {
			return n
		}
	}
	return names[0]
}

// ScheduleSend stores raw in Scheduled and records when to send it, from whom
// and to whom. The caller has checked that the account may send as from.
func (e *Engine) ScheduleSend(ctx context.Context, account string, raw []byte, from string, rcpts []string, at time.Time) (uint32, error) {
	f, err := e.ensureFolder(ctx, account, scheduledFolder)
	if err != nil {
		return 0, err
	}
	res, err := e.Append(ctx, account, scheduledFolder, raw, []string{`\Seen`}, time.Now(), "")
	if err != nil {
		return 0, err
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_scheduled_sends(folder,uid,account,send_at,mail_from,rcpts) VALUES($1,$2,$3,$4,$5,$6)`,
		f.ID, int64(res.UID), account, at.UTC(), from, pq.Array(rcpts))
	if err != nil {
		// Without its row the message would sit in Scheduled and never go.
		// Removed outright: it was never the user's to see.
		_, _ = e.expunge(context.WithoutCancel(ctx), account, scheduledFolder, []uint32{res.UID}, false, "")
		return 0, err
	}
	return res.UID, nil
}

// ScheduledSends lists what the account has waiting, soonest first.
func (e *Engine) ScheduledSends(ctx context.Context, account string) ([]ScheduledSend, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT uid,send_at,mail_from,rcpts,attempts,last_error FROM mailbox_scheduled_sends WHERE account=$1 ORDER BY send_at, uid`, account)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ScheduledSend{}
	for rows.Next() {
		var s ScheduledSend
		var uid int64
		if err := rows.Scan(&uid, &s.SendAt, &s.From, pq.Array(&s.To), &s.Attempts, &s.LastError); err != nil {
			return nil, err
		}
		s.UID = uint32(uid) // #nosec G115 -- IMAP UIDs are 32-bit; the column is wider only because Postgres has no unsigned type
		out = append(out, s)
	}
	return out, rows.Err()
}

// RescheduleSend moves a waiting message's send time, and clears a previous
// failure, so "Send now" is a reschedule to now. A message being sent at
// this moment can't be moved: ErrNotFound, as for one already sent.
func (e *Engine) RescheduleSend(ctx context.Context, account string, uid uint32, at time.Time) error {
	res, err := e.DB.ExecContext(ctx, `UPDATE mailbox_scheduled_sends SET send_at=$3, attempts=0, last_error='', claimed_until=NULL
WHERE account=$1 AND uid=$2 AND folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name=$4)
  AND (claimed_until IS NULL OR claimed_until<now())`, account, int64(uid), at.UTC(), scheduledFolder)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CancelSend stops a waiting message and moves it to Drafts to be edited,
// returning its UID there. The row goes first, under the same claim rule as
// sending, so a message can't be both cancelled and sent.
func (e *Engine) CancelSend(ctx context.Context, account string, uid uint32) (string, uint32, error) {
	res, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_scheduled_sends
WHERE account=$1 AND uid=$2 AND folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name=$3)
  AND (claimed_until IS NULL OR claimed_until<now())`, account, int64(uid), scheduledFolder)
	if err != nil {
		return "", 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", 0, ErrNotFound
	}
	drafts := e.existingFolder(ctx, account, "Drafts")
	if _, err := e.ensureFolder(ctx, account, drafts); err != nil {
		return "", 0, err
	}
	_, _, to, err := e.CopyMove(ctx, account, scheduledFolder, drafts, []uint32{uid}, true)
	if err != nil || len(to) == 0 {
		return "", 0, errors.Join(errors.New("cancelled but not moved to Drafts"), err)
	}
	// A draft carries the flag webmail and mail apps look for.
	_ = e.MutateFlags(ctx, account, drafts, to, []string{`\Draft`}, 1)
	return drafts, to[0], nil
}

// Snooze moves messages to Snoozed until a time, to come back to the folder
// they came from, and returns their UIDs in Snoozed. Snoozing a message that
// is already snoozed changes when it comes back.
func (e *Engine) Snooze(ctx context.Context, account, folder string, uids []uint32, until time.Time) ([]uint32, error) {
	sf, err := e.ensureFolder(ctx, account, snoozedFolder)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(canonicalMailbox(folder), snoozedFolder) {
		_, err := e.DB.ExecContext(ctx, `UPDATE mailbox_snoozes SET until=$3, claimed_until=NULL WHERE folder=$1 AND uid=ANY($2)`, sf.ID, pq.Array(int64s(uids)), until.UTC())
		return uids, err
	}
	_, _, to, err := e.CopyMove(ctx, account, folder, snoozedFolder, uids, true)
	if err != nil {
		return nil, err
	}
	for _, uid := range to {
		if _, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_snoozes(folder,uid,account,until,return_to) VALUES($1,$2,$3,$4,$5)
ON CONFLICT (folder,uid) DO UPDATE SET until=EXCLUDED.until, return_to=EXCLUDED.return_to, claimed_until=NULL`,
			sf.ID, int64(uid), account, until.UTC(), canonicalMailbox(folder)); err != nil {
			// Put them back rather than leave them where nothing returns them.
			_, _, _, _ = e.CopyMove(context.WithoutCancel(ctx), account, snoozedFolder, folder, to, true)
			return nil, err
		}
	}
	return to, nil
}

// Snoozes lists the account's snoozed messages, soonest back first.
func (e *Engine) Snoozes(ctx context.Context, account string) ([]SnoozedMessage, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT uid,until,return_to FROM mailbox_snoozes WHERE account=$1 ORDER BY until, uid`, account)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []SnoozedMessage{}
	for rows.Next() {
		var s SnoozedMessage
		var uid int64
		if err := rows.Scan(&uid, &s.Until, &s.ReturnTo); err != nil {
			return nil, err
		}
		s.UID = uint32(uid) // #nosec G115 -- IMAP UIDs are 32-bit
		out = append(out, s)
	}
	return out, rows.Err()
}

// Unsnooze brings snoozed messages back now, unread, and returns where they
// went: each folder and the messages' UIDs there.
func (e *Engine) Unsnooze(ctx context.Context, account string, uids []uint32) (map[string][]uint32, error) {
	rows, err := e.DB.QueryContext(ctx, `DELETE FROM mailbox_snoozes
WHERE account=$1 AND uid=ANY($2) AND folder=(SELECT id FROM mailbox_folders WHERE account=$1 AND name=$3)
  AND (claimed_until IS NULL OR claimed_until<now())
RETURNING uid, return_to`, account, pq.Array(int64s(uids)), snoozedFolder)
	if err != nil {
		return nil, err
	}
	back := map[string][]uint32{}
	for rows.Next() {
		var uid int64
		var to string
		if err := rows.Scan(&uid, &to); err != nil {
			_ = rows.Close()
			return nil, err
		}
		back[to] = append(back[to], uint32(uid)) // #nosec G115 -- IMAP UIDs are 32-bit
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string][]uint32{}
	for to, list := range back {
		dest, moved, err := e.returnSnoozed(ctx, account, snoozedFolder, to, list)
		if err != nil {
			return out, err
		}
		out[dest] = append(out[dest], moved...)
	}
	return out, nil
}

// returnSnoozed moves messages from the snoozed folder (by its current name)
// back to where they were, or to INBOX if that folder is gone, and marks them
// unread so they read as new.
func (e *Engine) returnSnoozed(ctx context.Context, account, from, to string, uids []uint32) (string, []uint32, error) {
	if _, err := e.Folder(ctx, account, to); err != nil {
		to = "INBOX"
	}
	_, _, moved, err := e.CopyMove(ctx, account, from, to, uids, true)
	if err != nil {
		return to, nil, err
	}
	if len(moved) > 0 {
		if err := e.MutateFlags(ctx, account, to, moved, []string{`\Seen`}, 2); err != nil {
			return to, moved, err
		}
	}
	return to, moved, nil
}

func int64s(uids []uint32) []int64 {
	out := make([]int64, len(uids))
	for i, u := range uids {
		out[i] = int64(u)
	}
	return out
}

// dueSend is a claimed row.
type dueSend struct {
	folderID      int64
	folder        string
	uid           uint32
	account, from string
	rcpts         []string
	attempt       int
}

func (e *Engine) claimDueSends(ctx context.Context) ([]dueSend, error) {
	rows, err := e.DB.QueryContext(ctx, `UPDATE mailbox_scheduled_sends s SET claimed_until=now()+$1::interval, attempts=s.attempts+1
FROM (SELECT folder,uid FROM mailbox_scheduled_sends WHERE send_at<=now() AND (claimed_until IS NULL OR claimed_until<now())
        AND account IN (SELECT id FROM mailbox_accounts WHERE writable)
      ORDER BY send_at LIMIT 20 FOR UPDATE SKIP LOCKED) due, mailbox_folders f
WHERE s.folder=due.folder AND s.uid=due.uid AND f.id=s.folder
RETURNING s.folder, f.name, s.uid, s.account, s.mail_from, s.rcpts, s.attempts`, fmt.Sprintf("%d seconds", int(scheduleClaim.Seconds())))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []dueSend
	for rows.Next() {
		var d dueSend
		var uid int64
		if err := rows.Scan(&d.folderID, &d.folder, &uid, &d.account, &d.from, pq.Array(&d.rcpts), &d.attempt); err != nil {
			return nil, err
		}
		d.uid = uint32(uid) // #nosec G115 -- IMAP UIDs are 32-bit
		out = append(out, d)
	}
	return out, rows.Err()
}

// dueSnooze is a claimed snooze, grouped by where it goes back to.
type dueSnooze struct {
	account, folder, returnTo string
	uids                      []uint32
}

func (e *Engine) claimDueSnoozes(ctx context.Context) ([]dueSnooze, error) {
	rows, err := e.DB.QueryContext(ctx, `UPDATE mailbox_snoozes s SET claimed_until=now()+$1::interval
FROM (SELECT folder,uid FROM mailbox_snoozes WHERE until<=now() AND (claimed_until IS NULL OR claimed_until<now())
        AND account IN (SELECT id FROM mailbox_accounts WHERE writable)
      ORDER BY until LIMIT 500 FOR UPDATE SKIP LOCKED) due, mailbox_folders f
WHERE s.folder=due.folder AND s.uid=due.uid AND f.id=s.folder
RETURNING s.account, f.name, s.return_to, s.uid`, fmt.Sprintf("%d seconds", int(scheduleClaim.Seconds())))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	groups := map[[3]string]*dueSnooze{}
	var order [][3]string
	for rows.Next() {
		var account, folder, to string
		var uid int64
		if err := rows.Scan(&account, &folder, &to, &uid); err != nil {
			return nil, err
		}
		k := [3]string{account, folder, to}
		g := groups[k]
		if g == nil {
			g = &dueSnooze{account: account, folder: folder, returnTo: to}
			groups[k] = g
			order = append(order, k)
		}
		g.uids = append(g.uids, uint32(uid)) // #nosec G115 -- IMAP UIDs are 32-bit
	}
	out := make([]dueSnooze, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	return out, rows.Err()
}

// runScheduled sends scheduled messages and returns snoozed ones as they come
// due. Every mailbox server runs it; the claims keep them off each other's
// rows.
func (s *Service) runScheduled(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := s.sendDue(c); err != nil && c.Err() == nil {
				s.log.Warn("scheduled send", "error", err)
			}
			if err := s.returnDueSnoozes(c); err != nil && c.Err() == nil {
				s.log.Warn("snooze", "error", err)
			}
			cancel()
		}
	}
}

func (s *Service) returnDueSnoozes(ctx context.Context) error {
	due, err := s.engine.claimDueSnoozes(ctx)
	if err != nil {
		return err
	}
	for _, d := range due {
		// The move removes the rows (the foreign key); a failure leaves
		// them claimed, to be tried again when the claim lapses.
		dest, moved, err := s.engine.returnSnoozed(ctx, d.account, d.folder, d.returnTo, d.uids)
		if err != nil {
			s.log.Warn("snooze: return", "account", d.account, "error", err)
			continue
		}
		s.announceReturned(ctx, d.account, dest, moved)
	}
	return nil
}

// announceReturned pushes snoozed messages that came back to the inbox to
// the user's devices, as new mail is. A snooze is a reminder the user asked
// for, so it goes to every device that takes mail notifications, including
// those limited to the Primary tab: it is announced without a category.
// Messages returning to another folder aren't announced, as mail filed
// there on delivery isn't.
func (s *Service) announceReturned(ctx context.Context, account, folder string, uids []uint32) {
	if s.push == nil || canonicalMailbox(folder) != "INBOX" || len(uids) == 0 {
		return
	}
	a := Account{ID: account}
	if err := s.engine.DB.QueryRowContext(ctx, `SELECT address FROM mailbox_accounts WHERE id=$1`, account).Scan(&a.Address); err != nil {
		return
	}
	f, err := s.engine.Folder(ctx, account, folder)
	if err != nil {
		return
	}
	msgs, err := s.engine.MessagesByUID(ctx, f.ID, uids)
	if err != nil {
		return
	}
	for _, uid := range uids {
		m, ok := msgs[uid]
		if !ok {
			continue
		}
		raw, err := s.engine.Read(ctx, m)
		if err != nil {
			continue
		}
		s.push.mailArrived(a, uid, raw, "")
	}
}

func (s *Service) sendDue(ctx context.Context) error {
	due, err := s.engine.claimDueSends(ctx)
	if err != nil {
		return err
	}
	for _, d := range due {
		s.sendScheduled(ctx, d)
	}
	return nil
}

// errSendRefused is a failure that trying again won't fix.
var errSendRefused = errors.New("refused")

func (s *Service) sendScheduled(ctx context.Context, d dueSend) {
	err := s.sendOne(ctx, d)
	if err == nil {
		s.log.Info("scheduled send: sent", "account", d.account, "recipients", len(d.rcpts))
		return
	}
	if errors.Is(err, ErrNotFound) {
		return // the message went while we looked
	}
	if !errors.Is(err, errSendRefused) && d.attempt < maxSendAttempts {
		s.log.Warn("scheduled send: will retry", "account", d.account, "attempt", d.attempt, "error", err)
		_, uerr := s.engine.DB.ExecContext(ctx, `UPDATE mailbox_scheduled_sends SET send_at=now()+$3::interval, claimed_until=NULL, last_error=$4 WHERE folder=$1 AND uid=$2`,
			d.folderID, int64(d.uid), fmt.Sprintf("%d seconds", int(sendRetry(d.attempt).Seconds())), clip(err.Error(), 300))
		if uerr != nil {
			s.log.Warn("scheduled send: record retry", "error", uerr)
		}
		return
	}
	s.log.Warn("scheduled send: gave up", "account", d.account, "attempt", d.attempt, "error", err)
	s.failScheduled(ctx, d, err)
}

func (s *Service) sendOne(ctx context.Context, d dueSend) error {
	if s.cfg.Sieve.SubmitAddr == "" {
		return errors.New("sieve.submit_addr isn't set")
	}
	var address string
	if err := s.engine.DB.QueryRowContext(ctx, `SELECT address FROM mailbox_accounts WHERE id=$1`, d.account).Scan(&address); err != nil {
		return err
	}
	// The directory as it is now: an account deleted, suspended, or no
	// longer allowed to send as this address since it scheduled the
	// message mustn't send it.
	a, err := s.auth.Resolve(ctx, address)
	if errors.Is(err, ErrCredentials) || errors.Is(err, ErrNotFound) || (err == nil && (a.ID != d.account || a.Suspended)) {
		return fmt.Errorf("%w: the account can no longer send", errSendRefused)
	}
	if err != nil {
		return err
	}
	if ok, err := s.maySendAs(ctx, a, d.from); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: %s may no longer send as %s", errSendRefused, a.Address, d.from)
	}
	f, err := s.engine.Folder(ctx, d.account, d.folder)
	if err != nil {
		return err
	}
	msgs, err := s.engine.MessagesByUID(ctx, f.ID, []uint32{d.uid})
	if err != nil {
		return err
	}
	m, ok := msgs[d.uid]
	if !ok {
		return ErrNotFound
	}
	raw, err := s.engine.Read(ctx, m)
	if err != nil {
		return err
	}
	// As at scheduling: the From inside the message must be one the account
	// may still use, not only the envelope.
	if addr, ok, err := s.mayAuthor(ctx, a, raw); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: %s may not send as %q", errSendRefused, a.Address, addr)
	}
	if err := s.submit(ctx, d.from, d.rcpts, raw); err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) && se.Code >= 500 {
			return fmt.Errorf("%w: the mail server said %d %s", errSendRefused, se.Code, se.Message)
		}
		return err
	}
	// Sent. Moving it removes the row; if the move fails the message has
	// still gone, so the row goes anyway rather than send it twice.
	sent := s.engine.existingFolder(ctx, d.account, "Sent", "Sent Items", "Sent Messages")
	if _, err := s.engine.ensureFolder(ctx, d.account, sent); err == nil {
		if _, _, _, err = s.engine.CopyMove(ctx, d.account, d.folder, sent, []uint32{d.uid}, true); err == nil {
			return nil
		}
		s.log.Warn("scheduled send: sent but not moved to Sent", "account", d.account, "error", err)
	}
	_, err = s.engine.DB.ExecContext(context.WithoutCancel(ctx), `DELETE FROM mailbox_scheduled_sends WHERE folder=$1 AND uid=$2`, d.folderID, int64(d.uid))
	return err
}

// maySendAs follows the check SMTP makes and compose offers (sendAddresses).
// mayAuthor reports whether every From address in raw is one a may send as.
// The scheduled message goes out through the MTA's internal relay, where
// the MTA doesn't bind From to a login, and is signed for the envelope's
// domain: checking only the envelope let a user schedule mail that claimed
// to be from a colleague, signed and aligned. Mail with no From is allowed,
// since it claims nobody.
func (s *Service) mayAuthor(ctx context.Context, a Account, raw []byte) (string, bool, error) {
	addrs, ok := mailpolicy.FromAddresses(raw)
	if !ok {
		return "", false, nil
	}
	for _, addr := range addrs {
		allowed, err := s.maySendAs(ctx, a, addr)
		if err != nil || !allowed {
			return addr, false, err
		}
	}
	return "", true, nil
}

func (s *Service) maySendAs(ctx context.Context, a Account, from string) (bool, error) {
	from = strings.ToLower(strings.TrimSpace(from))
	if from == strings.ToLower(a.Address) {
		return true, nil
	}
	allowed, err := s.sendAddresses(ctx, a)
	if err != nil {
		return false, err
	}
	return slices.Contains(allowed, from), nil
}

// failScheduled moves a message that won't go to Drafts and leaves a note in
// the inbox saying so, since nobody is watching when it fails.
func (s *Service) failScheduled(ctx context.Context, d dueSend, cause error) {
	ctx = context.WithoutCancel(ctx)
	_, _ = s.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_scheduled_sends WHERE folder=$1 AND uid=$2`, d.folderID, int64(d.uid))
	subject := ""
	drafts := s.engine.existingFolder(ctx, d.account, "Drafts")
	if _, err := s.engine.ensureFolder(ctx, d.account, drafts); err == nil {
		if f, err := s.engine.Folder(ctx, d.account, d.folder); err == nil {
			if msgs, err := s.engine.MessagesByUID(ctx, f.ID, []uint32{d.uid}); err == nil {
				if m, ok := msgs[d.uid]; ok {
					if raw, err := s.engine.Read(ctx, m); err == nil {
						subject = headerSubject(raw)
					}
				}
			}
		}
		if _, _, to, err := s.engine.CopyMove(ctx, d.account, d.folder, drafts, []uint32{d.uid}, true); err == nil {
			_ = s.engine.MutateFlags(ctx, d.account, drafts, to, []string{`\Draft`}, 1)
		} else {
			s.log.Warn("scheduled send: move to Drafts", "account", d.account, "error", err)
		}
	}
	reason := strings.TrimPrefix(cause.Error(), errSendRefused.Error()+": ")
	note := failureNote(d.from, subject, d.rcpts, reason, drafts, time.Now())
	if _, err := s.engine.Append(ctx, d.account, "INBOX", note, nil, time.Now(), ""); err != nil {
		s.log.Warn("scheduled send: failure note", "account", d.account, "error", err)
	}
}

// headerSubject is the message's Subject as written, encoded words and all.
func headerSubject(raw []byte) string {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return ""
	}
	return squash(h.Get("Subject"))
}

// squash puts header-bound text on one line, so a subject or a reason can't
// start a header of its own.
func squash(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func failureNote(from, subject string, rcpts []string, reason, drafts string, now time.Time) []byte {
	if subject == "" {
		subject = "(no subject)"
	}
	var b bytes.Buffer
	domain := from[strings.LastIndex(from, "@")+1:]
	fmt.Fprintf(&b, "From: %s\r\n", (&mail.Address{Name: "Mail delivery", Address: "mailer-daemon@" + domain}).String())
	fmt.Fprintf(&b, "To: %s\r\n", from)
	fmt.Fprintf(&b, "Subject: Not sent: %s\r\n", squash(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "A message you scheduled couldn't be sent.\r\n\r\nTo: %s\r\nReason: %s\r\n\r\nIt's in %s, to edit and send again.\r\n",
		squash(strings.Join(rcpts, ", ")), squash(reason), drafts)
	return b.Bytes()
}

// errScheduleUnavailable means this server can't send scheduled mail.
var errScheduleUnavailable = &requestError{"scheduled send isn't available: the mailbox service has no submission server"}

// checkScheduleTime refuses a time in the past or more than a year ahead.
// A few minutes late is allowed: "now" from a slow connection.
func checkScheduleTime(at, now time.Time) error {
	if at.Before(now.Add(-5*time.Minute)) || at.After(now.Add(maxScheduleAhead)) {
		return &requestError{"pick a time within the next year"}
	}
	return nil
}

// checkScheduleRecipients takes bare addresses, as SMTP RCPT wants them.
func checkScheduleRecipients(rcpts []string) ([]string, error) {
	if len(rcpts) == 0 || len(rcpts) > maxScheduledRecipients {
		return nil, &requestError{fmt.Sprintf("a scheduled message needs 1 to %d recipients", maxScheduledRecipients)}
	}
	out := make([]string, 0, len(rcpts))
	for _, r := range rcpts {
		r = strings.TrimSpace(r)
		if len(r) > 320 || strings.Count(r, "@") != 1 || strings.HasPrefix(r, "@") || strings.HasSuffix(r, "@") || strings.ContainsAny(r, "<>\r\n\t ,;\"") {
			return nil, &requestError{"not an email address: " + clip(r, 80)}
		}
		out = append(out, r)
	}
	return out, nil
}
