package mailbox

// Spam learning: when someone moves mail in or out of Junk, Rspamd's
// classifier learns from it.
//
// The hook is CopyMove because the webmail and every mail app reach it, so
// there is one place to get this right. Delivery does not go through it, which
// matters: mail filed in Junk automatically is the filter agreeing with
// itself, and learning from that would only entrench its mistakes. Only a
// person's decision counts.
//
// Feedback is queued in the same transaction as the move. The user's move must
// not wait on Rspamd or fail because of it, and an outage must not lose what
// they told us. Rows stay for a day after they are learned to count against
// the daily limit, and to tell a correction from a repeat.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/antispam"
	"github.com/lib/pq"
)

const (
	// DefaultSpamLearnPerDay limits what one account can teach in a day.
	// Bayes tokens are shared by every account on the server, so without a
	// limit one compromised mailbox could retrain the filter for all of
	// them. Enough for someone clearing out a folder by hand.
	DefaultSpamLearnPerDay = 500

	spamLearnBatch = 50
	// spamLearnInterval is how often a replica looks for work. Feedback is
	// not urgent, and at this rate a batch comes to 200 messages a minute.
	spamLearnInterval = 15 * time.Second
	// spamLearnRetry is how long a claimed row is left alone. A replica
	// that dies mid-batch needs no cleanup: its rows simply come due again.
	spamLearnRetry = 5 * time.Minute
	// spamLearnMaxBytes matches the size Rspamd scans at delivery. Bigger
	// messages are attachments, which add nothing to the classifier.
	spamLearnMaxBytes = 25 << 20
)

// spamLearner is what the queue needs from Rspamd; antispam.Learner in
// production.
type spamLearner interface {
	Learn(ctx context.Context, class string, msg []byte) error
}

func junkFolderName(name string) bool {
	return retentionFolderName(name, "Junk", "Spam", "Junk E-mail")
}

// learnClass says what moving mail from src to dst tells us, if anything.
//
// Leaving Junk for Trash is not "this is good mail": it is how people get rid
// of spam. Nothing leaves Sent or Drafts as spam either, since those are the
// user's own words, and filing them in Junk says nothing about incoming mail.
func learnClass(src, dst string) string {
	srcJunk, dstJunk := junkFolderName(src), junkFolderName(dst)
	switch {
	case dstJunk && !srcJunk:
		if retentionFolderName(src, "Sent", "Sent Items", "Sent Messages", "Drafts") {
			return ""
		}
		return antispam.LearnSpam
	case srcJunk && !dstJunk:
		if retentionFolderName(dst, "Trash", "Deleted Items", "Deleted Messages", "Sent", "Sent Items", "Sent Messages", "Drafts") {
			return ""
		}
		return antispam.LearnHam
	}
	return ""
}

// queueSpamFeedback runs inside CopyMove's transaction.
//
// Corrections skip the daily limit: someone undoing a mistake should always be
// heard, and a message can only be flipped by a person moving it back.
func queueSpamFeedback(ctx context.Context, tx *sql.Tx, account, class string, bodies []string, perDay int) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mailbox_spam_feedback SET class=$2,not_before=now(),learned=NULL
WHERE account=$1 AND body=ANY($3) AND class<>$2`, account, class, pq.Array(bodies)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_spam_feedback(account,body,class)
SELECT $1::text,b,$2::text FROM unnest($3::text[]) AS b
LIMIT GREATEST($4::bigint-(SELECT count(*) FROM mailbox_spam_feedback WHERE account=$1 AND created>now()-interval '1 day'),0)
ON CONFLICT (account,body) DO NOTHING`, account, class, pq.Array(bodies), perDay)
	return err
}

type spamFeedback struct{ account, body, class string }

// claimSpamFeedback takes rows by pushing their not_before forward instead of
// holding locks while it talks to Rspamd. A move touching one of these rows
// would otherwise wait on that network call, inside the user's transaction.
func (e *Engine) claimSpamFeedback(ctx context.Context, n int) ([]spamFeedback, error) {
	rows, err := e.DB.QueryContext(ctx, `WITH due AS (
  SELECT account,body FROM mailbox_spam_feedback
  WHERE learned IS NULL AND not_before<=now() ORDER BY not_before LIMIT $1 FOR UPDATE SKIP LOCKED)
UPDATE mailbox_spam_feedback f SET not_before=now()+make_interval(secs=>$2)
FROM due WHERE f.account=due.account AND f.body=due.body
RETURNING f.account,f.body,f.class`, n, spamLearnRetry.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []spamFeedback
	for rows.Next() {
		var f spamFeedback
		if err := rows.Scan(&f.account, &f.body, &f.class); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// finishSpamFeedback checks the class so a correction that arrived while this
// row was in flight stays queued.
func (e *Engine) finishSpamFeedback(ctx context.Context, f spamFeedback) error {
	_, err := e.DB.ExecContext(ctx, `UPDATE mailbox_spam_feedback SET learned=now()
WHERE account=$1 AND body=$2 AND class=$3`, f.account, f.body, f.class)
	return err
}

// learnableBody reads the message, or returns nil when it is gone or too big
// to bother with. Someone can empty Junk before the queue gets here.
func (e *Engine) learnableBody(ctx context.Context, key string) ([]byte, error) {
	var size int64
	var state string
	err := e.DB.QueryRowContext(ctx, `SELECT size,state FROM mailbox_bodies WHERE key=$1`, key).Scan(&size, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if state != "ready" || size == 0 || size > spamLearnMaxBytes {
		return nil, nil
	}
	return e.Bodies.Get(ctx, key, size)
}

// LearnSpamFeedback sends one batch to Rspamd and returns how many messages
// were dealt with. It stops at the first failure, because that nearly always
// means Rspamd is down or the password is wrong, and the rest would fail too.
func (e *Engine) LearnSpamFeedback(ctx context.Context, l spamLearner) (int, error) {
	items, err := e.claimSpamFeedback(ctx, spamLearnBatch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, f := range items {
		raw, err := e.learnableBody(ctx, f.body)
		if err != nil {
			return done, fmt.Errorf("read body: %w", err)
		}
		if raw != nil {
			// A refusal is about this message and will not change, so it
			// stops here rather than coming back for a week.
			if err := l.Learn(ctx, f.class, raw); err != nil && !errors.Is(err, antispam.ErrLearnRefused) {
				return done, err
			}
		}
		if err := e.finishSpamFeedback(ctx, f); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

// pruneSpamFeedback drops rows the daily limit no longer needs, and any that
// could not be learned in a week: by then the outage is the news, and the
// messages may well be gone.
func (e *Engine) pruneSpamFeedback(ctx context.Context) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_spam_feedback
WHERE (learned IS NOT NULL AND learned<now()-interval '1 day') OR created<now()-interval '7 days'`)
	return err
}

// runSpamLearning feeds the queue to Rspamd until the service stops. Every
// replica runs it; claims keep them off each other's rows.
func (s *Service) runSpamLearning() {
	ticker := time.NewTicker(spamLearnInterval)
	defer ticker.Stop()
	var lastPrune time.Time
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
		done, err := s.engine.LearnSpamFeedback(ctx, s.spamLearner)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("spam learning failed; will retry", "error", err)
		}
		if done > 0 {
			s.log.Info("spam feedback learned", "count", done)
		}
		if time.Since(lastPrune) >= time.Hour {
			lastPrune = time.Now()
			if err := s.engine.pruneSpamFeedback(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("spam feedback cleanup failed", "error", err)
			}
		}
		cancel()
	}
}

// validateSpamLearningURL catches a config that would fail quietly, in the
// background, only once someone reports spam.
func validateSpamLearningURL(u string) error {
	if u == "" || strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return nil
	}
	return fmt.Errorf("spam_learning.rspamd_url must be an http or https URL, got %q", u)
}
