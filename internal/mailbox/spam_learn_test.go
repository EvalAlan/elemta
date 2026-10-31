package mailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/antispam"
)

func TestLearnClass(t *testing.T) {
	tests := []struct{ src, dst, want string }{
		{"INBOX", "Junk", antispam.LearnSpam},
		{"INBOX", "Spam", antispam.LearnSpam},
		{"INBOX", "junk e-mail", antispam.LearnSpam},
		{"Archive/2026", "Junk", antispam.LearnSpam},
		{"Trash", "Junk", antispam.LearnSpam},
		{"Junk", "INBOX", antispam.LearnHam},
		{"Spam", "Archive", antispam.LearnHam},
		// Throwing spam away is not calling it good mail.
		{"Junk", "Trash", ""},
		{"Junk", "Deleted Items", ""},
		// Nothing about incoming mail either way.
		{"Sent", "Junk", ""},
		{"Drafts", "Junk", ""},
		{"Junk", "Spam", ""},
		{"INBOX", "Archive", ""},
		{"INBOX", "Trash", ""},
	}
	for _, tt := range tests {
		if got := learnClass(tt.src, tt.dst); got != tt.want {
			t.Errorf("learnClass(%q, %q) = %q, want %q", tt.src, tt.dst, got, tt.want)
		}
	}
}

// recordingLearner stands in for Rspamd.
type recordingLearner struct {
	mu      sync.Mutex
	classes []string
	bodies  [][]byte
	err     error
}

func (r *recordingLearner) Learn(_ context.Context, class string, msg []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.classes = append(r.classes, class)
	r.bodies = append(r.bodies, msg)
	return nil
}

func (r *recordingLearner) learned() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.classes...)
}

// learningMailbox is an account with Junk and Archive, and n messages in the
// INBOX.
func learningMailbox(t *testing.T, n int) (*Engine, Account, []uint32) {
	t.Helper()
	e, a := testEngine(t)
	e.spamLearnPerDay = DefaultSpamLearnPerDay
	ctx := context.Background()
	for _, name := range []string{"Junk", "Archive", "Trash"} {
		if err := e.Create(ctx, a.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	var uids []uint32
	for i := range n {
		msg := fmt.Appendf(nil, "From: a@example.org\r\nSubject: %d\r\n\r\nbody %d\r\n", i, i)
		r, err := e.Append(ctx, a.ID, "INBOX", msg, nil, time.Time{}, "")
		if err != nil {
			t.Fatal(err)
		}
		uids = append(uids, r.UID)
	}
	return e, a, uids
}

func queued(t *testing.T, e *Engine, account string) (pending, total int) {
	t.Helper()
	err := e.DB.QueryRow(`SELECT count(*) FILTER (WHERE learned IS NULL),count(*) FROM mailbox_spam_feedback WHERE account=$1`, account).Scan(&pending, &total)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// A row just learned or claimed must come due at once for the next step of a
// test, which would otherwise wait out the retry delay.
func makeDue(t *testing.T, e *Engine, account string) {
	t.Helper()
	if _, err := e.DB.Exec(`UPDATE mailbox_spam_feedback SET not_before=now() WHERE account=$1`, account); err != nil {
		t.Fatal(err)
	}
}

func TestMoveToJunkTeachesSpam(t *testing.T) {
	e, a, uids := learningMailbox(t, 2)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	l := &recordingLearner{}
	if n, err := e.LearnSpamFeedback(ctx, l); err != nil || n != 2 {
		t.Fatalf("learned %d, err %v", n, err)
	}
	got := l.learned()
	if len(got) != 2 || got[0] != antispam.LearnSpam {
		t.Fatalf("classes %v", got)
	}
	if !bytes.Contains(l.bodies[0], []byte("Subject:")) {
		t.Fatalf("Rspamd needs the whole message, got %q", l.bodies[0])
	}
	// Nothing goes round twice.
	if n, err := e.LearnSpamFeedback(ctx, l); err != nil || n != 0 {
		t.Fatalf("second pass learned %d, err %v", n, err)
	}
}

func TestCorrectionRelearns(t *testing.T) {
	e, a, uids := learningMailbox(t, 1)
	ctx := context.Background()
	_, _, to, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true)
	if err != nil {
		t.Fatal(err)
	}
	l := &recordingLearner{}
	if _, err := e.LearnSpamFeedback(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.CopyMove(ctx, a.ID, "Junk", "INBOX", to, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.LearnSpamFeedback(ctx, l); err != nil {
		t.Fatal(err)
	}
	got := l.learned()
	if len(got) != 2 || got[1] != antispam.LearnHam {
		t.Fatalf("classes %v", got)
	}
}

func TestDisabledLearningQueuesNothing(t *testing.T) {
	e, a, uids := learningMailbox(t, 1)
	e.spamLearnPerDay = 0
	if _, _, _, err := e.CopyMove(context.Background(), a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	if _, total := queued(t, e, a.ID); total != 0 {
		t.Fatalf("%d rows queued with learning off", total)
	}
}

func TestDailyLimitCapsOneAccount(t *testing.T) {
	e, a, uids := learningMailbox(t, 5)
	e.spamLearnPerDay = 3
	ctx := context.Background()
	_, _, to, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true)
	if err != nil {
		t.Fatal(err)
	}
	if pending, _ := queued(t, e, a.ID); pending != 3 {
		t.Fatalf("%d queued, want the limit of 3", pending)
	}
	// The limit must not fail the user's move.
	if len(to) != 5 {
		t.Fatalf("moved %d of 5", len(to))
	}
	// A correction is heard even at the limit.
	l := &recordingLearner{}
	if _, err := e.LearnSpamFeedback(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.CopyMove(ctx, a.ID, "Junk", "INBOX", to, true); err != nil {
		t.Fatal(err)
	}
	if pending, _ := queued(t, e, a.ID); pending != 3 {
		t.Fatalf("%d corrections queued, want 3", pending)
	}
}

func TestOutageKeepsFeedback(t *testing.T) {
	e, a, uids := learningMailbox(t, 2)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	down := &recordingLearner{err: errors.New("connection refused")}
	if _, err := e.LearnSpamFeedback(ctx, down); err == nil {
		t.Fatal("want the failure reported")
	}
	if pending, _ := queued(t, e, a.ID); pending != 2 {
		t.Fatalf("%d left, want both kept", pending)
	}
	// Claimed rows wait out the delay rather than hammering a sick Rspamd.
	if n, err := e.LearnSpamFeedback(ctx, down); err != nil || n != 0 {
		t.Fatalf("retried at once: %d, %v", n, err)
	}
	makeDue(t, e, a.ID)
	up := &recordingLearner{}
	if n, err := e.LearnSpamFeedback(ctx, up); err != nil || n != 2 {
		t.Fatalf("after recovery %d, %v", n, err)
	}
}

func TestRefusedMessageIsNotRetried(t *testing.T) {
	e, a, uids := learningMailbox(t, 1)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	l := &recordingLearner{err: fmt.Errorf("%w: 400", antispam.ErrLearnRefused)}
	if n, err := e.LearnSpamFeedback(ctx, l); err != nil || n != 1 {
		t.Fatalf("%d, %v", n, err)
	}
	if pending, _ := queued(t, e, a.ID); pending != 0 {
		t.Fatalf("%d still pending", pending)
	}
}

func TestDeletedBodyIsSkipped(t *testing.T) {
	e, a, uids := learningMailbox(t, 1)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(`UPDATE mailbox_spam_feedback SET body=$1 WHERE account=$2`, "0123456789abcdef0123456789abcdef", a.ID); err != nil {
		t.Fatal(err)
	}
	l := &recordingLearner{}
	if n, err := e.LearnSpamFeedback(ctx, l); err != nil || n != 1 {
		t.Fatalf("%d, %v", n, err)
	}
	if got := l.learned(); len(got) != 0 {
		t.Fatalf("learned a missing message: %v", got)
	}
}

func TestPruneKeepsWhatTheLimitNeeds(t *testing.T) {
	e, a, uids := learningMailbox(t, 3)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.LearnSpamFeedback(ctx, &recordingLearner{}); err != nil {
		t.Fatal(err)
	}
	if err := e.pruneSpamFeedback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, total := queued(t, e, a.ID); total != 3 {
		t.Fatalf("pruned rows still inside the limit's window: %d left", total)
	}
	if _, err := e.DB.Exec(`UPDATE mailbox_spam_feedback SET learned=now()-interval '2 days' WHERE account=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.pruneSpamFeedback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, total := queued(t, e, a.ID); total != 0 {
		t.Fatalf("%d left after a day", total)
	}
}

func TestReplicasShareTheQueue(t *testing.T) {
	e, a, uids := learningMailbox(t, 20)
	ctx := context.Background()
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", uids, true); err != nil {
		t.Fatal(err)
	}
	l := &recordingLearner{}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.LearnSpamFeedback(ctx, l); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := len(l.learned()); got != 20 {
		t.Fatalf("learned %d times, want each of the 20 once", got)
	}
}

// TestLearnAgainstRspamd checks the queue against a real Rspamd, whose answers
// the stand-in above only imitates. Rspamd reports a message it has seen as
// already learned, which proves this one arrived.
func TestLearnAgainstRspamd(t *testing.T) {
	url, password := os.Getenv("ELEMTA_TEST_RSPAMD_CONTROLLER"), os.Getenv("ELEMTA_TEST_RSPAMD_PASSWORD")
	if url == "" {
		t.Skip("set ELEMTA_TEST_RSPAMD_CONTROLLER and ELEMTA_TEST_RSPAMD_PASSWORD")
	}
	e, a, _ := learningMailbox(t, 0)
	ctx := context.Background()
	msg := fmt.Sprintf("From: a@example.org\r\nSubject: offer\r\nMessage-ID: <%d@example.org>\r\n\r\n%s\r\n",
		time.Now().UnixNano(), strings.Repeat("unique words about a cheap offer today ", 40))
	res, err := e.Append(ctx, a.ID, "INBOX", []byte(msg), nil, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.CopyMove(ctx, a.ID, "INBOX", "Junk", []uint32{res.UID}, true); err != nil {
		t.Fatal(err)
	}
	if n, err := e.LearnSpamFeedback(ctx, antispam.NewLearner(url, password)); err != nil || n != 1 {
		t.Fatalf("learned %d, err %v", n, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/learnspam", strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Password", password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAlreadyReported {
		t.Fatalf("Rspamd answered %s; it did not learn the message", resp.Status)
	}
}
