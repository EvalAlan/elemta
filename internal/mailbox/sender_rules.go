package mailbox

// Each user's allowed and blocked senders, and filing spam in Junk.
//
// The MTA marks mail its spam check flags but lets through
// ("X-Spam-Status: Yes"); delivery now files that in Junk rather than the
// INBOX. A user's blocked senders go to Junk too, whatever the check said;
// their allowed senders stay in the INBOX even when flagged. Each rule is
// an address or @domain, matched against the envelope sender and the
// message's From. Mail the MTA refused outright never gets here, so an
// allowed sender can't bring that back.
//
// Users manage the lists in the webmail (Settings, Account) through the
// security API, up to their class of service's max_sender_rules.

import (
	"context"
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/lib/pq"
)

// SenderRules are a user's allowed and blocked senders.
type SenderRules struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
	// Max is how many the account's class allows, together.
	Max int `json:"max"`
}

// SenderRules returns the account's rules, sorted.
func (e *Engine) SenderRules(ctx context.Context, account string) (SenderRules, error) {
	out := SenderRules{Allow: []string{}, Block: []string{}}
	rows, err := e.DB.QueryContext(ctx, `SELECT entry, kind FROM mailbox_sender_rules WHERE account=$1 ORDER BY entry`, account)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry, kind string
		if err := rows.Scan(&entry, &kind); err != nil {
			return out, err
		}
		if kind == "allow" {
			out.Allow = append(out.Allow, entry)
		} else {
			out.Block = append(out.Block, entry)
		}
	}
	return out, rows.Err()
}

// senderRule normalises one rule: an address or @domain.
func senderRule(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if domain, ok := strings.CutPrefix(v, "@"); ok {
		if d, err := normalDomain(domain); err == nil {
			return "@" + d, nil
		}
		return "", fmt.Errorf("%w: %q isn't a domain", mailpolicy.ErrInvalid, raw)
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v {
		return "", fmt.Errorf("%w: %q isn't an email address or @domain", mailpolicy.ErrInvalid, raw)
	}
	return v, nil
}

// SetSenderRules replaces the account's rules. A rule can't be both
// allowed and blocked, and together they may not exceed max.
func (e *Engine) SetSenderRules(ctx context.Context, account string, allow, block []string, max int) (SenderRules, error) {
	clean := func(in []string) ([]string, error) {
		out := []string{}
		for _, r := range in {
			if strings.TrimSpace(r) == "" {
				continue
			}
			n, err := senderRule(r)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out, nil
	}
	a, err := clean(allow)
	if err != nil {
		return SenderRules{}, err
	}
	b, err := clean(block)
	if err != nil {
		return SenderRules{}, err
	}
	for _, r := range a {
		if slices.Contains(b, r) {
			return SenderRules{}, fmt.Errorf("%w: %s is both allowed and blocked", mailpolicy.ErrInvalid, r)
		}
	}
	if len(a)+len(b) > max {
		return SenderRules{}, fmt.Errorf("%w: at most %d allowed and blocked senders", mailpolicy.ErrInvalid, max)
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return SenderRules{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_sender_rules WHERE account=$1`, account); err != nil {
		return SenderRules{}, err
	}
	for kind, entries := range map[string][]string{"allow": a, "block": b} {
		for _, entry := range entries {
			if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_sender_rules(account, entry, kind) VALUES($1,$2,$3)`, account, entry, kind); err != nil {
				return SenderRules{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return SenderRules{}, err
	}
	out, err := e.SenderRules(ctx, account)
	out.Max = max
	return out, err
}

// senderVerdict is "allow", "block" or "" for a message's senders. A block
// wins over an allow, so a forged From can't lift a blocked envelope.
func (e *Engine) senderVerdict(ctx context.Context, account string, senders []string) (string, error) {
	var keys []string
	for _, s := range senders {
		if s = strings.ToLower(strings.TrimSpace(s)); strings.Contains(s, "@") {
			keys = append(keys, s, "@"+domainOf(s))
		}
	}
	if len(keys) == 0 {
		return "", nil
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT kind FROM mailbox_sender_rules WHERE account=$1 AND entry=ANY($2)`, account, pq.Array(keys))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	verdict := ""
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return "", err
		}
		if kind == "block" {
			verdict = "block"
		} else if verdict == "" {
			verdict = "allow"
		}
	}
	return verdict, rows.Err()
}

// messageSenders are the envelope sender and the From addresses.
func messageSenders(from string, raw []byte) []string {
	out := []string{strings.Trim(from, "<>")}
	for _, line := range headerLines(headerBlock(raw), "From") {
		if list, err := mail.ParseAddressList(line); err == nil {
			for _, a := range list {
				out = append(out, a.Address)
			}
		}
	}
	return out
}

// spamFlagged reports whether the MTA's spam check flagged the message. The
// MTA adds its header above the message's own, so the first one counts: a
// sender can't clear the flag with an X-Spam-Status of their own below it.
func spamFlagged(raw []byte) bool {
	lines := headerLines(headerBlock(raw), "X-Spam-Status")
	return len(lines) > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(lines[0])), "yes")
}

// spamHeld reports whether the MTA marked the message for quarantine. As with
// spamFlagged, only the first header counts.
func spamHeld(raw []byte) bool {
	lines := headerLines(headerBlock(raw), "X-Spam-Status")
	if len(lines) == 0 {
		return false
	}
	fields := strings.Split(lines[0], ",")
	return len(fields) > 1 && strings.EqualFold(strings.TrimSpace(fields[0]), "yes") &&
		strings.EqualFold(strings.TrimSpace(fields[1]), quarantineFolder)
}

// headerLines returns the unfolded values of a header, in order.
func headerLines(head []byte, name string) []string {
	var out []string
	prefix := strings.ToLower(name) + ":"
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(strings.ToLower(lines[i]), prefix) {
			continue
		}
		v := lines[i][len(prefix):]
		for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "\t")) {
			i++
			v += " " + strings.TrimSpace(lines[i])
		}
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// junkFolder is the account's Junk folder, by the names mail apps use, or
// "Junk" to be created.
func (s *Service) junkFolder(ctx context.Context, account string) string {
	for _, name := range []string{"Junk", "Spam", "Junk E-mail"} {
		if _, err := s.engine.Folder(ctx, account, name); err == nil {
			return name
		}
	}
	return "Junk"
}

// quarantineFolder holds mail the spam check would have refused, for the user
// to release or leave to expire (retention.go).
const quarantineFolder = "Quarantine"

// spamFolder is where delivery should file the message before forwarding and
// the user's filters, or "" for normal delivery: Junk for a blocked sender or a
// message the spam check flagged, Quarantine for one it would have refused.
//
// An allowed sender skips Junk but not Quarantine. An allow entry can match the
// From header, which anyone can forge, and a forged message scoring that high
// is the thing being held. The user can still see it and release it.
func (s *Service) spamFolder(ctx context.Context, d delivery) (string, error) {
	verdict, err := s.engine.senderVerdict(ctx, d.account.ID, messageSenders(d.from, d.raw))
	if err != nil {
		return "", err
	}
	switch {
	case verdict == "block":
		return s.junkFolder(ctx, d.account.ID), nil
	case spamHeld(d.raw):
		return quarantineFolder, nil
	case verdict == "allow":
		return "", nil
	case spamFlagged(d.raw):
		return s.junkFolder(ctx, d.account.ID), nil
	}
	return "", nil
}
