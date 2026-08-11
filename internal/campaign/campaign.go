// Package campaign implements bulk sending: a message, a recipient list, and a
// runner that hands them to the queue at a controlled rate.
//
// The rate limit is the reason this is not a loop over the recipients. Handing
// fifty thousand messages to the queue at once buries ordinary mail behind the
// bulk run, and gives the operator no way to stop it once they notice something
// is wrong. A campaign is therefore a durable object with a state machine, and
// sending is something that happens to it over time.
package campaign

import (
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"
)

// State is where a campaign is in its lifecycle.
type State string

const (
	// StateDraft: editable, nothing sent.
	StateDraft State = "draft"
	// StateRunning: the runner is enqueuing.
	StateRunning State = "running"
	// StatePaused: stopped by the operator, resumable from where it stopped.
	StatePaused State = "paused"
	// StateCompleted: every recipient has been attempted.
	StateCompleted State = "completed"
	// StateCancelled: stopped by the operator and not resumable.
	StateCancelled State = "cancelled"
	// StateFailed: the runner could not continue.
	StateFailed State = "failed"
)

// Recipient is one addressee and the values merged into their copy.
type Recipient struct {
	Email string            `json:"email"`
	Vars  map[string]string `json:"vars,omitempty"`
}

// Campaign is a bulk send: what to send, to whom, and how fast.
type Campaign struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	From    string `json:"from"`
	ReplyTo string `json:"reply_to,omitempty"`
	Subject string `json:"subject"`

	// HTMLBody and TextBody are the two alternatives. Sending both is what
	// makes a message render for people whose client will not show HTML, and
	// is expected of bulk mail.
	HTMLBody string `json:"html_body"`
	TextBody string `json:"text_body"`

	Recipients []Recipient `json:"recipients"`

	// RatePerMinute caps how fast messages are handed to the queue. Zero means
	// the configured default rather than "unlimited": an unbounded default is
	// the setting nobody notices until a campaign has swamped the queue.
	RatePerMinute int `json:"rate_per_minute"`

	State State `json:"state"`

	// Progress. Sent and Failed only move forward, so a resumed campaign
	// continues rather than restarting.
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
	// Skipped counts recipients passed over because they are on the
	// suppression list. Counted separately because they are neither a success
	// nor a failure, and folding them into either would misreport the campaign:
	// "sent" would overstate reach, "failed" would look like a delivery problem
	// to investigate.
	Skipped   int    `json:"skipped"`
	LastError string `json:"last_error,omitempty"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	mu sync.Mutex
}

// Total is how many recipients the campaign has.
func (c *Campaign) Total() int { return len(c.Recipients) }

// Remaining is how many are still to be attempted.
func (c *Campaign) Remaining() int {
	done := c.Sent + c.Failed + c.Skipped
	if done > len(c.Recipients) {
		return 0
	}
	return len(c.Recipients) - done
}

// Validate reports why a campaign cannot be sent.
//
// Checked before the campaign starts rather than per message: discovering a bad
// From address on recipient forty thousand means forty thousand refusals.
func (c *Campaign) Validate() error {
	var problems []string

	if strings.TrimSpace(c.Name) == "" {
		problems = append(problems, "name is required")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		problems = append(problems, fmt.Sprintf("from %q is not a valid address", c.From))
	}
	if c.ReplyTo != "" {
		if _, err := mail.ParseAddress(c.ReplyTo); err != nil {
			problems = append(problems, fmt.Sprintf("reply_to %q is not a valid address", c.ReplyTo))
		}
	}
	if strings.TrimSpace(c.Subject) == "" {
		problems = append(problems, "subject is required")
	}
	// The subject is concatenated into a header, so it must not be able to
	// write one of its own.
	if strings.ContainsAny(c.Subject, "\r\n") {
		problems = append(problems, "subject must not contain line breaks")
	}
	if strings.TrimSpace(c.HTMLBody) == "" && strings.TrimSpace(c.TextBody) == "" {
		problems = append(problems, "a message body is required")
	}
	if len(c.Recipients) == 0 {
		problems = append(problems, "at least one recipient is required")
	}
	if c.RatePerMinute < 0 {
		problems = append(problems, "rate_per_minute must not be negative")
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// CanStart reports whether Start is a legal transition.
func (c *Campaign) CanStart() bool {
	return c.State == StateDraft || c.State == StatePaused
}

// Clone returns a copy safe to hand out, without the lock.
func (c *Campaign) Clone() *Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cloneLocked()
}

func (c *Campaign) cloneLocked() *Campaign {
	out := &Campaign{
		ID:            c.ID,
		Name:          c.Name,
		From:          c.From,
		ReplyTo:       c.ReplyTo,
		Subject:       c.Subject,
		HTMLBody:      c.HTMLBody,
		TextBody:      c.TextBody,
		RatePerMinute: c.RatePerMinute,
		State:         c.State,
		Sent:          c.Sent,
		Failed:        c.Failed,
		Skipped:       c.Skipped,
		LastError:     c.LastError,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
	if c.StartedAt != nil {
		t := *c.StartedAt
		out.StartedAt = &t
	}
	if c.CompletedAt != nil {
		t := *c.CompletedAt
		out.CompletedAt = &t
	}
	out.Recipients = make([]Recipient, len(c.Recipients))
	copy(out.Recipients, c.Recipients)
	return out
}

// ParseRecipients reads a pasted or uploaded recipient list.
//
// Accepts a bare address per line, or CSV with a header row where one column is
// the address and the rest become merge variables. Bad rows are reported rather
// than dropped: silently skipping a malformed line means an operator believes
// they mailed a list they did not.
func ParseRecipients(input string) ([]Recipient, []string, error) {
	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	var header []string
	emailCol := -1
	out := make([]Recipient, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	var problems []string

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitCSVLine(line)

		// A first row that has several columns and no address in it is a header.
		if header == nil && len(fields) > 1 && !looksLikeEmail(fields[0]) {
			header = make([]string, len(fields))
			for j, f := range fields {
				header[j] = strings.ToLower(strings.TrimSpace(f))
				if emailCol < 0 && (header[j] == "email" || header[j] == "address" || header[j] == "e-mail") {
					emailCol = j
				}
			}
			if emailCol < 0 {
				emailCol = 0
			}
			continue
		}

		col := emailCol
		if col < 0 {
			col = 0
		}
		if col >= len(fields) {
			problems = append(problems, fmt.Sprintf("line %d: no address column", i+1))
			continue
		}

		addr := strings.TrimSpace(fields[col])
		parsed, err := mail.ParseAddress(addr)
		if err != nil {
			problems = append(problems, fmt.Sprintf("line %d: %q is not a valid address", i+1, addr))
			continue
		}
		email := parsed.Address

		// Duplicates are dropped rather than mailed twice. Sending the same
		// person two copies of a campaign is the most visible way to look
		// broken.
		key := strings.ToLower(email)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := Recipient{Email: email}
		if header != nil {
			r.Vars = make(map[string]string, len(fields))
			for j, f := range fields {
				if j == col || j >= len(header) || header[j] == "" {
					continue
				}
				r.Vars[header[j]] = strings.TrimSpace(f)
			}
		}
		out = append(out, r)
	}

	if len(out) == 0 && len(problems) == 0 {
		return nil, nil, errors.New("no recipients found")
	}
	return out, problems, nil
}

// splitCSVLine splits on commas or tabs, honouring double quotes.
func splitCSVLine(line string) []string {
	if !strings.ContainsAny(line, ",\t") {
		return []string{line}
	}
	var (
		fields  []string
		current strings.Builder
		inQuote bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			// A doubled quote inside a quoted field is a literal quote.
			if inQuote && i+1 < len(line) && line[i+1] == '"' {
				current.WriteByte('"')
				i++
				continue
			}
			inQuote = !inQuote
		case (c == ',' || c == '\t') && !inQuote:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	fields = append(fields, current.String())
	return fields
}

func looksLikeEmail(s string) bool {
	return strings.Contains(s, "@")
}

// SortRecipients orders recipients by address so a campaign sends in a stable,
// reproducible order — which is what makes "resume from where it stopped"
// meaningful.
func SortRecipients(rs []Recipient) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Email < rs[j].Email })
}
