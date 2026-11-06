package webmail

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Undo send.
//
// With undo send on (Settings, default 10 seconds), Send doesn't hand the
// message to the mail server at once. It saves it to Drafts, replacing the
// draft it was edited from, and sends it when the delay is up; the notice
// says "Sending" with an Undo button until then. Undo stops it and opens the
// draft. The draft is the point: whatever happens to this process in the
// meantime, the message is never lost. A shutdown (a deploy) sends what is
// waiting straight away (FlushPendingSends). Only a crash can leave one
// unsent, and then it is in Drafts.
//
// The waiting messages live in this process. With several webmail replicas
// an Undo that reaches another one finds nothing and says it's too late;
// sending still happens, from the replica that took it.

// pendingSend is a message waiting out its undo delay.
type pendingSend struct {
	id, sessID string
	sess       *Session
	password   string
	from       string
	draft      *Draft
	raw        []byte
	draftUID   uint32 // the safety copy in Drafts
	origFolder string
	origUID    uint32
	mode       string
	due        time.Time
	timer      *time.Timer
}

type sendQueue struct {
	mu      sync.Mutex
	pending map[string]*pendingSend
	// failed holds, per session, delayed sends that didn't go, said on
	// the next page that session loads.
	failed map[string][]string
}

func newSendQueue() *sendQueue {
	return &sendQueue{pending: map[string]*pendingSend{}, failed: map[string][]string{}}
}

// takeFailures returns and forgets the session's failed-send messages.
func (q *sendQueue) takeFailures(sessID string) []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	f := q.failed[sessID]
	delete(q.failed, sessID)
	return f
}

// undoSendChoices are the delays Settings offers, in seconds; 0 is off.
var undoSendChoices = []int{0, 5, 10, 20, 30}

// defaultUndoSend is the delay for someone who hasn't chosen. A variable
// only so the package's tests, most of which check what a send produced,
// can run with sending immediate (sendlater_test.go turns it back on).
var defaultUndoSend = 10

// UndoSendSeconds is the chosen delay; UndoSend "" means the default and
// "0" off, so existing accounts get it without a migration.
func (p Settings) UndoSendSeconds() int {
	if p.UndoSend == "" {
		return defaultUndoSend
	}
	n, err := strconv.Atoi(p.UndoSend)
	if err != nil {
		return defaultUndoSend
	}
	for _, c := range undoSendChoices {
		if c == n {
			return n
		}
	}
	return defaultUndoSend
}

// UndoSendOptions lists the delays for the settings form.
func (p Settings) UndoSendOptions() []int { return undoSendChoices }

func validUndoSend(v string) string {
	n, err := strconv.Atoi(v)
	if err != nil {
		return ""
	}
	for _, c := range undoSendChoices {
		if c == n {
			return v
		}
	}
	return ""
}

// queueSend saves the message to Drafts and schedules it. It returns the
// pending send's id, for the notice's Undo.
func (s *Server) queueSend(ctx context.Context, sess *Session, password, from string, d *Draft, raw []byte, cv *composeView, delay time.Duration) (*pendingSend, error) {
	var draftUID uint32
	err := s.sessions.withMailStore(ctx, sess, s.dial, func(st Mailstore) error {
		uid, err := st.Append(ctx, RoleDrafts, raw, true, true)
		if err != nil {
			return err
		}
		draftUID = uid
		// The copy just saved supersedes the draft it was edited from.
		return s.dropDraft(ctx, st, cv.DraftUID)
	})
	if err != nil {
		return nil, err
	}
	id, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	p := &pendingSend{
		id: id, sessID: sess.ID, sess: sess, password: password, from: from, draft: d, raw: raw,
		draftUID: draftUID, origFolder: cv.OrigFolder, origUID: cv.OrigUID, mode: cv.Mode,
		due: s.now().Add(delay),
	}
	s.sends.mu.Lock()
	s.sends.pending[id] = p
	p.timer = time.AfterFunc(delay, func() { s.fireSend(id) })
	s.sends.mu.Unlock()
	return p, nil
}

// fireSend sends a pending message whose delay is up, unless it was undone.
func (s *Server) fireSend(id string) {
	s.sends.mu.Lock()
	p, ok := s.sends.pending[id]
	delete(s.sends.pending, id)
	s.sends.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.deliverPending(ctx, p); err != nil {
		s.log.Warn("webmail: delayed send", "user", p.sess.User, "error", err)
		msg := "A message you sent couldn't be sent. It's saved in Drafts: open it and send it again."
		if errors.Is(err, ErrRejected) {
			msg = "The mail server refused a message you sent: " + strings.TrimPrefix(err.Error(), ErrRejected.Error()+": ") + " It's saved in Drafts."
		}
		s.sends.mu.Lock()
		s.sends.failed[p.sessID] = append(s.sends.failed[p.sessID], msg)
		s.sends.mu.Unlock()
	}
}

// deliverPending hands a waiting message to the mail server, then files the
// sent copy and removes the safety draft. Until the server has taken it the
// draft stays, so a failure loses nothing.
func (s *Server) deliverPending(ctx context.Context, p *pendingSend) error {
	if err := s.submit.Submit(ctx, p.sess.User, p.password, p.from, p.draft.Recipients(), p.raw); err != nil {
		return err
	}
	s.logSent(ctx, p.sess, p.draft, "message")
	if err := s.sessions.withMailStore(ctx, p.sess, s.dial, func(st Mailstore) error {
		if _, err := st.Append(ctx, RoleSent, p.raw, true, false); err != nil {
			return err
		}
		if err := s.dropDraft(ctx, st, p.draftUID); err != nil {
			s.log.Warn("webmail: remove sent draft", "user", p.sess.User, "error", err)
		}
		if p.origFolder != "" && p.origUID != 0 {
			flag := FlagAnswered
			if p.mode == "forward" {
				flag = FlagForwarded
			}
			if err := st.SetFlags(ctx, p.origFolder, []uint32{p.origUID}, []string{flag}, true); err != nil {
				s.log.Warn("webmail: mark original", "user", p.sess.User, "error", err)
			}
		}
		return nil
	}); err != nil {
		// Sent, which is what matters; only the copy and the tidying failed.
		s.log.Warn("webmail: save sent copy", "user", p.sess.User, "error", err)
	}
	s.rememberRecipients(ctx, p.sess, p.draft)
	return nil
}

// undoSend stops a pending send and opens its draft for editing.
func (s *Server) undoSend(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PostFormValue("id")
	s.sends.mu.Lock()
	p, ok := s.sends.pending[id]
	if ok && p.sessID == sess.ID && p.timer.Stop() {
		delete(s.sends.pending, id)
	} else {
		ok = false
	}
	s.sends.mu.Unlock()
	if !ok {
		http.Redirect(w, r, folderURL("INBOX", 1, "")+"&n=send-too-late", http.StatusSeeOther)
		return
	}
	folder := "Drafts"
	_ = s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		for _, f := range folders {
			if f.Role == RoleDrafts {
				folder = f.Name
			}
		}
		return err
	})
	if p.draftUID == 0 {
		// The server didn't say where the draft went; it's in Drafts.
		http.Redirect(w, r, folderURL(folder, 1, "")+"&n=send-undone", http.StatusSeeOther)
		return
	}
	q := url.Values{"mode": {"draft"}, "f": {folder}, "uid": {strconv.FormatUint(uint64(p.draftUID), 10)}, "n": {"send-undone"}}
	http.Redirect(w, r, "/compose?"+q.Encode(), http.StatusSeeOther)
}

// FlushPendingSends sends everything still waiting out its delay, at once.
// The webmail command calls it on shutdown, so a deploy doesn't strand
// messages people have already pressed Send on.
func (s *Server) FlushPendingSends(ctx context.Context) {
	s.sends.mu.Lock()
	var ids []string
	for id, p := range s.sends.pending {
		if p.timer.Stop() {
			ids = append(ids, id)
		}
	}
	s.sends.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) { defer wg.Done(); s.fireSend(id) }(id)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("webmail: shutdown before every pending message was sent; they're in Drafts")
	}
}

// pendingNotice is what the notice needs to show a pending send.
type pendingNotice struct {
	ID string
	// Left is the seconds still to wait when the page was made: relative,
	// so a browser with a wrong clock still counts down right.
	Left int
}

// pendingFor finds the session's pending send with that id, if still due.
func (s *Server) pendingFor(sess *Session, id string) *pendingNotice {
	s.sends.mu.Lock()
	defer s.sends.mu.Unlock()
	p, ok := s.sends.pending[id]
	if !ok || p.sessID != sess.ID {
		return nil
	}
	left := int(p.due.Sub(s.now()).Seconds() + 0.999)
	return &pendingNotice{ID: p.id, Left: max(left, 0)}
}
