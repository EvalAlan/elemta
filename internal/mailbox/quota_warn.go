package mailbox

// Quota warnings: a note in the user's INBOX as their mailbox passes each
// threshold of its quota ([quota] warn_percent, 80% and 95% by default),
// so they can clear space before mail to them starts being refused.
//
// Each threshold is announced once. The level last announced is kept with
// the account and claimed in the same statement that checks it, so two
// replicas delivering at once don't both send it. When usage falls well
// back (5 points under the threshold) the level drops, so filling up again
// warns again, without a message every time usage wobbles around a line.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// quotaHysteresis is how far under a threshold usage must fall before it
// can be announced again.
const quotaHysteresis = 5

// quotaLevel is the highest threshold usage has reached, or 0.
func quotaLevel(thresholds []int, used, limit int64) int {
	if limit <= 0 {
		return 0
	}
	pct := used * 100 / limit
	level := 0
	for _, t := range thresholds {
		if t > 0 && t <= 100 && pct >= int64(t) && t > level {
			level = t
		}
	}
	return level
}

// quotaWarning checks the account's usage after a delivery and tells the
// user when it has passed a new threshold. Failures only cost the
// warning; the delivery has already succeeded.
func (s *Service) quotaWarning(ctx context.Context, a Account) {
	thresholds := s.cfg.Quota.WarnPercent
	if len(thresholds) == 0 || a.ID == "" {
		return
	}
	used, limit, err := s.engine.Quota(ctx, a.ID)
	if err != nil || limit <= 0 {
		return
	}
	level := quotaLevel(thresholds, used, limit)
	var warned int
	if err := s.engine.DB.QueryRowContext(ctx, `SELECT quota_warned FROM mailbox_accounts WHERE id=$1`, a.ID).Scan(&warned); err != nil {
		return
	}
	if level < warned {
		// Below what was announced: re-arm once clearly under it.
		if used*100/limit <= int64(warned-quotaHysteresis) {
			_, _ = s.engine.DB.ExecContext(ctx, `UPDATE mailbox_accounts SET quota_warned=$2 WHERE id=$1 AND quota_warned>$2`, a.ID, level)
		}
		return
	}
	if level == 0 || level == warned {
		return
	}
	res, err := s.engine.DB.ExecContext(ctx, `UPDATE mailbox_accounts SET quota_warned=$2 WHERE id=$1 AND quota_warned<$2`, a.ID, level)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return // another replica has told them
	}
	msg := quotaMessage(a.Address, level, used, limit, slices.Max(thresholds), time.Now())
	if _, err := s.engine.Append(ctx, a.ID, "INBOX", msg, nil, time.Now(), ""); err != nil {
		s.log.Warn("quota warning not delivered", "account", a.ID, "error", err)
		return
	}
	s.log.Info("quota warning sent", "account", a.ID, "percent", level)
}

// quotaMessage is the warning itself.
func quotaMessage(address string, level int, used, limit int64, highest int, now time.Time) []byte {
	domain := domainOf(address)
	subject := fmt.Sprintf("Your mailbox is %d%% full", level)
	next := "Mail to you will be refused once it is completely full."
	if level < highest {
		next = "You'll get another note if it keeps filling up; mail to you is refused once it is completely full."
	}
	body := fmt.Sprintf("Your mailbox (%s) is using %s of its %s.\r\n\r\n%s\r\n\r\n"+
		"To make room, empty Trash and Junk, and delete or move large messages\r\n"+
		"you no longer need. Your administrator can also raise the limit.\r\n",
		address, humanBytes(used), humanBytes(limit), next)
	var b strings.Builder
	fmt.Fprintf(&b, "From: Mail system <postmaster@%s>\r\n", domain)
	fmt.Fprintf(&b, "To: <%s>\r\n", address)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <quota-%s@%s>\r\n", uuid.NewString(), domain)
	b.WriteString("Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", n>>10)
	}
}
