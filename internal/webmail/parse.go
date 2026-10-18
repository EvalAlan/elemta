package webmail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/emersion/go-message"
	// Registers decoders for the non-UTF-8 charsets real mail still uses.
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

// maxTextPart caps how much of a single text part is decoded for display,
// so one enormous body can't balloon the response.
const maxTextPart = 4 << 20

// Message is a parsed message ready to display.
type Message struct {
	UID        uint32
	Folder     string
	MessageID  string
	InReplyTo  string
	References string
	Subject    string
	Date       time.Time
	From       []Address
	ReplyTo    []Address
	To         []Address
	Cc         []Address
	Text       string // first text/plain body part
	HTML       string // first text/html body part, unsanitised
	Parts      []Part // every part that isn't the displayed body
	Seen       bool
	Flagged    bool
	Tags       []string
	// HighPriority is set for messages marked important (Importance: high
	// or X-Priority 1 or 2).
	HighPriority bool
	// ReceiptTo is where the sender asked for a read receipt, if anywhere.
	ReceiptTo string
	// Newer and Older are the neighbouring messages in the list, for
	// next/previous navigation; 0 when there is none on this page.
	Newer, Older uint32
	// SenderContact is the contact ID of the sender, if they are one.
	SenderContact string
	// Calendar holds the iCalendar part of an invitation or a reply to one.
	Calendar []byte
	// Invite is the parsed invitation, set by the calendar decorator.
	Invite *inviteView
	// AuthResults is the topmost Authentication-Results header, which on a
	// mailbox fed by Elemta is the one Elemta itself added.
	AuthResults string
}

// Part is an attachment or an inline resource (such as a cid: image).
type Part struct {
	Index       int // position in walk order, the part's identifier in URLs
	Filename    string
	ContentType string
	ContentID   string // without angle brackets
	Inline      bool
	Size        int64
}

// parseMessage walks raw and returns the displayable message.
func parseMessage(raw []byte) (*Message, error) {
	r, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return nil, fmt.Errorf("webmail: parse message: %w", err)
	}
	defer func() { _ = r.Close() }()

	msg := &Message{}
	h := r.Header
	msg.Subject, _ = h.Subject()
	msg.Date, _ = h.Date()
	msg.MessageID = h.Get("Message-Id")
	msg.InReplyTo = h.Get("In-Reply-To")
	msg.References = h.Get("References")
	msg.AuthResults = h.Get("Authentication-Results")
	msg.From = headerAddresses(h, "From")
	msg.ReplyTo = headerAddresses(h, "Reply-To")
	msg.To = headerAddresses(h, "To")
	msg.Cc = headerAddresses(h, "Cc")
	imp := strings.ToLower(h.Get("Importance"))
	prio := strings.TrimSpace(h.Get("X-Priority"))
	msg.HighPriority = imp == "high" || strings.HasPrefix(prio, "1") || strings.HasPrefix(prio, "2")
	if dnt := headerAddresses(h, "Disposition-Notification-To"); len(dnt) > 0 {
		msg.ReceiptTo = dnt[0].Email
	}

	index := 0
	for {
		p, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !message.IsUnknownCharset(err) {
			// A malformed part late in the message shouldn't hide the body
			// we already have. Show what parsed.
			if msg.Text != "" || msg.HTML != "" {
				break
			}
			return nil, fmt.Errorf("webmail: parse part: %w", err)
		}
		index++
		switch ph := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			cid := strings.Trim(ph.Get("Content-Id"), "<>")
			if ct == "text/plain" && msg.Text == "" && cid == "" {
				msg.Text = readLimited(p.Body)
				continue
			}
			if ct == "text/html" && msg.HTML == "" && cid == "" {
				msg.HTML = readLimited(p.Body)
				continue
			}
			if ct == "text/calendar" && msg.Calendar == nil {
				// Invitations carry the event as an inline calendar part.
				// It is kept for the calendar to read, and also listed as
				// an attachment so it can be saved as an .ics file.
				msg.Calendar = []byte(readLimited(p.Body))
				msg.Parts = append(msg.Parts, Part{Index: index, ContentType: ct, Size: int64(len(msg.Calendar)), Filename: "invite.ics"})
				continue
			}
			n, _ := io.Copy(io.Discard, p.Body)
			msg.Parts = append(msg.Parts, Part{Index: index, ContentType: ct, ContentID: cid, Inline: true, Size: n, Filename: inlineName(ph)})
		case *mail.AttachmentHeader:
			ct, _, _ := ph.ContentType()
			name, _ := ph.Filename()
			if (ct == "text/calendar" || ct == "application/ics") && msg.Calendar == nil {
				body := readLimited(p.Body)
				msg.Calendar = []byte(body)
				msg.Parts = append(msg.Parts, Part{Index: index, Filename: name, ContentType: ct, Size: int64(len(body))})
				continue
			}
			n, _ := io.Copy(io.Discard, p.Body)
			cid := strings.Trim(ph.Get("Content-Id"), "<>")
			// go-message files every non-text part under attachments. A part
			// with a Content-ID and no explicit attachment disposition is a
			// resource the HTML body references (a cid: image), not a file.
			disp := strings.ToLower(strings.TrimSpace(ph.Get("Content-Disposition")))
			inline := cid != "" && !strings.HasPrefix(disp, "attachment")
			msg.Parts = append(msg.Parts, Part{
				Index: index, Filename: name, ContentType: ct,
				ContentID: cid, Inline: inline, Size: n,
			})
		}
	}
	return msg, nil
}

// Attachments returns the parts a user downloads, leaving out inline images
// the HTML body already shows.
func (m *Message) Attachments() []Part {
	var out []Part
	for _, p := range m.Parts {
		if p.Inline && p.ContentID != "" && m.HTML != "" {
			continue
		}
		if p.Filename == "" {
			p.Filename = fmt.Sprintf("part-%d", p.Index)
		}
		out = append(out, p)
	}
	return out
}

// findPart returns the body and metadata of the part at index, or the part
// with the given Content-ID when cid is set.
func findPart(raw []byte, index int, cid string) (Part, []byte, error) {
	r, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return Part{}, nil, fmt.Errorf("webmail: parse message: %w", err)
	}
	defer func() { _ = r.Close() }()
	i := 0
	for {
		p, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			return Part{}, nil, ErrNotFound
		}
		if err != nil && !message.IsUnknownCharset(err) {
			return Part{}, nil, fmt.Errorf("webmail: parse part: %w", err)
		}
		i++
		var ct, name, id string
		switch ph := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ = ph.ContentType()
			id = strings.Trim(ph.Get("Content-Id"), "<>")
			name = inlineName(ph)
		case *mail.AttachmentHeader:
			ct, _, _ = ph.ContentType()
			id = strings.Trim(ph.Get("Content-Id"), "<>")
			name, _ = ph.Filename()
		}
		if (cid != "" && id == cid) || (cid == "" && i == index) {
			body, err := io.ReadAll(p.Body)
			if err != nil {
				return Part{}, nil, fmt.Errorf("webmail: read part: %w", err)
			}
			return Part{Index: i, Filename: name, ContentType: ct, ContentID: id, Size: int64(len(body))}, body, nil
		}
	}
}

func readLimited(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, maxTextPart))
	return string(b)
}

// inlineName recovers a filename from an inline part's Content-Type name
// parameter, which is where inline images usually carry it.
func inlineName(h *mail.InlineHeader) string {
	_, params, err := h.ContentType()
	if err != nil {
		return ""
	}
	if name := params["name"]; name != "" {
		if dec, err := new(mime.WordDecoder).DecodeHeader(name); err == nil {
			return dec
		}
		return name
	}
	return ""
}

func headerAddresses(h mail.Header, key string) []Address {
	list, err := h.AddressList(key)
	if err != nil {
		// An unparsable header is shown raw rather than dropped, so a
		// malformed From still tells the user something.
		if v := h.Get(key); v != "" {
			return []Address{{Name: v}}
		}
		return nil
	}
	out := make([]Address, 0, len(list))
	for _, a := range list {
		out = append(out, Address{Name: a.Name, Email: a.Address})
	}
	return out
}
