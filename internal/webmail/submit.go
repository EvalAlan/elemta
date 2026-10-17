package webmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-message/mail"
)

// Draft is a message being composed.
type Draft struct {
	From        Address
	ReplyTo     []Address
	To          []Address
	Cc          []Address
	Bcc         []Address
	Subject     string
	Text        string
	HTML        string // optional HTML alternative, already sanitised
	InReplyTo   string
	References  string
	Attachments []Attachment
	// HighPriority marks the message important for clients that show it.
	HighPriority bool
	// ReceiptTo asks the recipient's client for a read receipt (RFC 8098).
	ReceiptTo string
	// Calendar is an iCalendar part sent alongside the text, which is how
	// invitations and replies to them travel (iMIP, RFC 6047).
	Calendar *CalendarPart
}

// CalendarPart is an iMIP payload.
type CalendarPart struct {
	Method string // REQUEST, REPLY or CANCEL
	Data   []byte
}

// Attachment is a file added to a draft.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Recipients returns every envelope recipient, Bcc included.
func (d *Draft) Recipients() []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]Address{d.To, d.Cc, d.Bcc} {
		for _, a := range list {
			key := strings.ToLower(a.Email)
			if a.Email == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, a.Email)
		}
	}
	return out
}

func mailAddresses(in []Address) []*mail.Address {
	out := make([]*mail.Address, 0, len(in))
	for _, a := range in {
		out = append(out, &mail.Address{Name: a.Name, Address: a.Email})
	}
	return out
}

// newMessageID returns an RFC 5322 Message-ID in the sender's domain.
func newMessageID(from string) (string, error) {
	tok, err := randomToken(18)
	if err != nil {
		return "", err
	}
	domain := "localhost"
	if at := strings.LastIndexByte(from, '@'); at >= 0 && at < len(from)-1 {
		domain = from[at+1:]
	}
	return tok + "@" + domain, nil
}

// Build renders the draft as an RFC 5322 message. Bcc is left out of the
// headers on purpose: it belongs only in the envelope.
//
// The body is text/plain alone when that is all there is, otherwise a
// multipart/alternative of the text, the HTML and the calendar part, wrapped
// in multipart/mixed when there are attachments.
func (d *Draft) Build(now time.Time) ([]byte, error) {
	var h mail.Header
	h.SetDate(now)
	h.SetAddressList("From", mailAddresses([]Address{d.From}))
	if len(d.ReplyTo) > 0 {
		h.SetAddressList("Reply-To", mailAddresses(d.ReplyTo))
	}
	if len(d.To) > 0 {
		h.SetAddressList("To", mailAddresses(d.To))
	}
	if len(d.Cc) > 0 {
		h.SetAddressList("Cc", mailAddresses(d.Cc))
	}
	h.SetSubject(d.Subject)
	id, err := newMessageID(d.From.Email)
	if err != nil {
		return nil, fmt.Errorf("webmail: message id: %w", err)
	}
	h.SetMessageID(id)
	if d.InReplyTo != "" {
		h.Set("In-Reply-To", d.InReplyTo)
		refs := strings.TrimSpace(d.References + " " + d.InReplyTo)
		h.Set("References", refs)
	}
	if d.HighPriority {
		h.Set("Importance", "high")
		h.Set("X-Priority", "1 (Highest)")
	}
	if d.ReceiptTo != "" {
		h.SetAddressList("Disposition-Notification-To", []*mail.Address{{Address: d.ReceiptTo}})
	}
	h.Set("User-Agent", "Elemta Webmail")

	text := normaliseNewlines(d.Text)
	var buf bytes.Buffer
	if len(d.Attachments) == 0 && d.HTML == "" && d.Calendar == nil {
		h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
		w, err := mail.CreateSingleInlineWriter(&buf, h)
		if err != nil {
			return nil, fmt.Errorf("webmail: build message: %w", err)
		}
		if _, err := io.WriteString(w, text); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	var bodyParts []struct {
		ct     string
		params map[string]string
		data   string
	}
	add := func(ct string, params map[string]string, data string) {
		bodyParts = append(bodyParts, struct {
			ct     string
			params map[string]string
			data   string
		}{ct, params, data})
	}
	add("text/plain", map[string]string{"charset": "utf-8"}, text)
	if d.HTML != "" {
		add("text/html", map[string]string{"charset": "utf-8"}, normaliseNewlines(d.HTML))
	}
	if d.Calendar != nil {
		add("text/calendar", map[string]string{"charset": "utf-8", "method": d.Calendar.Method}, normaliseNewlines(string(d.Calendar.Data)))
	}

	writeBody := func(create func(mail.InlineHeader) (io.WriteCloser, error)) error {
		for _, p := range bodyParts {
			var ih mail.InlineHeader
			ih.SetContentType(p.ct, p.params)
			pw, err := create(ih)
			if err != nil {
				return err
			}
			if _, err := io.WriteString(pw, p.data); err != nil {
				return err
			}
			if err := pw.Close(); err != nil {
				return err
			}
		}
		return nil
	}

	if len(d.Attachments) == 0 {
		// multipart/alternative at the top level.
		w, err := mail.CreateInlineWriter(&buf, h)
		if err != nil {
			return nil, fmt.Errorf("webmail: build message: %w", err)
		}
		if err := writeBody(w.CreatePart); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	w, err := mail.CreateWriter(&buf, h)
	if err != nil {
		return nil, fmt.Errorf("webmail: build message: %w", err)
	}
	if len(bodyParts) == 1 {
		var ih mail.InlineHeader
		ih.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
		tw, err := w.CreateSingleInline(ih)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(tw, text); err != nil {
			return nil, err
		}
		if err := tw.Close(); err != nil {
			return nil, err
		}
	} else {
		iw, err := w.CreateInline()
		if err != nil {
			return nil, err
		}
		if err := writeBody(iw.CreatePart); err != nil {
			return nil, err
		}
		if err := iw.Close(); err != nil {
			return nil, err
		}
	}
	for _, a := range d.Attachments {
		var ah mail.AttachmentHeader
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		ah.SetContentType(ct, nil)
		ah.SetFilename(a.Filename)
		aw, err := w.CreateAttachment(ah)
		if err != nil {
			return nil, err
		}
		if _, err := aw.Write(a.Data); err != nil {
			return nil, err
		}
		if err := aw.Close(); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normaliseNewlines turns browser line endings into CRLF, which SMTP
// requires and Elemta enforces (bare LF is rejected as a smuggling vector).
func normaliseNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// Submitter hands a finished message to the MTA.
type Submitter interface {
	Submit(ctx context.Context, user, password, from string, rcpts []string, raw []byte) error
}

// SMTPSubmitter submits over SMTP AUTH to Elemta's submission listener.
type SMTPSubmitter struct {
	Addr               string
	TLSMode            string
	InsecureSkipVerify bool
	// LocalName is sent in EHLO.
	LocalName string
}

// ErrRejected wraps a permanent SMTP refusal, whose text is safe to show.
var ErrRejected = errors.New("webmail: message rejected")

// Submit sends raw from from to rcpts, authenticating as user.
func (s SMTPSubmitter) Submit(ctx context.Context, user, password, from string, rcpts []string, raw []byte) error {
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return fmt.Errorf("webmail: submission_addr: %w", err)
	}
	tlsConf := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- opt-in for the dev stack's self-signed certificate; documented as dev-only
		InsecureSkipVerify: s.InsecureSkipVerify,
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if s.TLSMode == TLSModeImplicit {
		conn, err = tls.DialWithDialer(d, "tcp", s.Addr, tlsConf)
	} else {
		conn, err = d.DialContext(ctx, "tcp", s.Addr)
	}
	if err != nil {
		return fmt.Errorf("webmail: connect to submission %s: %w", s.Addr, err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("webmail: submission greeting: %w", err)
	}
	defer func() { _ = c.Close() }()
	local := s.LocalName
	if local == "" {
		local = "webmail.localhost"
	}
	if err := c.Hello(local); err != nil {
		return fmt.Errorf("webmail: EHLO: %w", err)
	}
	if s.TLSMode == TLSModeStartTLS {
		if err := c.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("webmail: STARTTLS: %w", err)
		}
	}
	// net/smtp's PlainAuth refuses to send credentials over an unencrypted
	// connection to anything but localhost. With tls = "none" that is the
	// guard we want, so it is not worked around.
	if err := c.Auth(smtp.PlainAuth("", user, password, host)); err != nil {
		return fmt.Errorf("webmail: AUTH: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return rejected("MAIL FROM", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return rejected("RCPT TO "+r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return rejected("DATA", err)
	}
	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		return fmt.Errorf("webmail: DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return rejected("message", err)
	}
	return c.Quit()
}

func rejected(stage string, err error) error {
	if strings.HasPrefix(err.Error(), "5") {
		return fmt.Errorf("%w: %s: %v", ErrRejected, stage, err)
	}
	return fmt.Errorf("webmail: %s: %w", stage, err)
}
