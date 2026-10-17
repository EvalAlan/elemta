package webmail

import (
	"strings"
	"time"
	"unicode"
)

// parseSearch turns the search box's text into a ListQuery. Besides free
// text it understands the operators people know from other mail clients:
//
//	from:priya  to:legal  subject:"signed msa"  tag:invoices
//	is:unread  is:read  is:flagged  is:starred  is:answered
//	has:attachment  after:2026-01-31  before:2026-03-01  on:2026-02-14
//
// Unknown operators are searched for as text, so nothing typed is silently
// dropped. Dates are calendar days in loc.
func parseSearch(input string, loc *time.Location) ListQuery {
	var q ListQuery
	var text []string
	for _, tok := range splitSearch(input) {
		key, val, ok := strings.Cut(tok, ":")
		if !ok || val == "" {
			text = append(text, tok)
			continue
		}
		switch strings.ToLower(key) {
		case "from":
			q.From = val
		case "to":
			q.To = val
		case "subject":
			q.Subject = val
		case "tag", "label":
			q.Tag = val
		case "is":
			switch strings.ToLower(val) {
			case "unread":
				q.Unread = true
			case "flagged", "starred":
				q.Flagged = true
			case "answered", "replied":
				q.Answered = true
			case "read":
				// Read is the default state; there's nothing to narrow.
			default:
				text = append(text, tok)
			}
		case "has":
			if strings.HasPrefix(strings.ToLower(val), "attachment") {
				q.HasAttachment = true
			} else {
				text = append(text, tok)
			}
		case "after", "since":
			if d, ok := parseDay(val, loc); ok {
				q.Since = d
			} else {
				text = append(text, tok)
			}
		case "before":
			if d, ok := parseDay(val, loc); ok {
				q.Before = d
			} else {
				text = append(text, tok)
			}
		case "on":
			if d, ok := parseDay(val, loc); ok {
				q.Since, q.Before = d, d.AddDate(0, 0, 1)
			} else {
				text = append(text, tok)
			}
		default:
			text = append(text, tok)
		}
	}
	q.Text = strings.Join(text, " ")
	return q
}

func parseDay(s string, loc *time.Location) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", "2006/01/02", "2006-1-2"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// splitSearch splits on spaces, keeping "quoted phrases" (also as an
// operator value, subject:"two words") together without their quotes.
func splitSearch(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case unicode.IsSpace(r) && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
