package webmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
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
	// Inline are images shown in the HTML body (pasted or inserted in the
	// editor), sent in a multipart/related with the HTML.
	Inline []Attachment
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
	// ContentID names an inline image the HTML refers to as cid:<id>.
	ContentID string
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

	root := d.bodyTree()
	root.header.Header = mergeHeaders(h.Header.Header, root.header.Header)
	var buf bytes.Buffer
	if err := root.write(&buf); err != nil {
		return nil, fmt.Errorf("webmail: build message: %w", err)
	}
	return buf.Bytes(), nil
}

// mimePart is one node of the message being built: a leaf with a body, or
// a multipart container with children.
type mimePart struct {
	header   message.Header
	body     []byte
	children []*mimePart
}

func leaf(ct string, params map[string]string, cte string, body []byte) *mimePart {
	p := &mimePart{body: body}
	p.header.SetContentType(ct, params)
	p.header.Set("Content-Transfer-Encoding", cte)
	return p
}

func container(kind string, children ...*mimePart) *mimePart {
	p := &mimePart{children: children}
	p.header.SetContentType("multipart/"+kind, map[string]string{})
	return p
}

// bodyTree lays out the body. Only what is present gets a part:
//
//	multipart/mixed                 when there are attachments
//	  multipart/alternative         when there is more than plain text
//	    text/plain
//	    multipart/related           when the HTML has inline images
//	      text/html
//	      image/* (Content-ID)
//	    text/calendar               for invitations
//	  attachments
func (d *Draft) bodyTree() *mimePart {
	utf8 := func() map[string]string { return map[string]string{"charset": "utf-8"} }
	alts := []*mimePart{leaf("text/plain", utf8(), "quoted-printable", []byte(normaliseNewlines(d.Text)))}
	if d.HTML != "" {
		html := leaf("text/html", utf8(), "quoted-printable", []byte(normaliseNewlines(d.HTML)))
		if len(d.Inline) > 0 {
			rel := container("related", html)
			for _, img := range d.Inline {
				p := leaf(orDefault(img.ContentType, "application/octet-stream"), nil, "base64", img.Data)
				p.header.Set("Content-ID", "<"+img.ContentID+">")
				p.header.Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": img.Filename}))
				rel.children = append(rel.children, p)
			}
			html = rel
		}
		alts = append(alts, html)
	}
	if d.Calendar != nil {
		params := utf8()
		params["method"] = d.Calendar.Method
		alts = append(alts, leaf("text/calendar", params, "quoted-printable", []byte(normaliseNewlines(string(d.Calendar.Data)))))
	}
	body := alts[0]
	if len(alts) > 1 {
		body = container("alternative", alts...)
	}
	if len(d.Attachments) == 0 {
		return body
	}
	mixed := container("mixed", body)
	for _, a := range d.Attachments {
		p := leaf(orDefault(a.ContentType, "application/octet-stream"), nil, "base64", a.Data)
		p.header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
		mixed.children = append(mixed.children, p)
	}
	return mixed
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// mergeHeaders puts the message headers above the root part's own
// (Content-Type and friends).
func mergeHeaders(top, part textproto.Header) textproto.Header {
	fields := part.Fields()
	for fields.Next() {
		top.Add(fields.Key(), fields.Value())
	}
	return top
}

// write renders p as a whole message (p being the root part).
func (p *mimePart) write(w io.Writer) error {
	mw, err := message.CreateWriter(w, p.header)
	if err != nil {
		return err
	}
	if err := p.fill(mw); err != nil {
		return err
	}
	return mw.Close()
}

func (p *mimePart) fill(mw *message.Writer) error {
	if len(p.children) == 0 {
		_, err := mw.Write(p.body)
		return err
	}
	for _, c := range p.children {
		cw, err := mw.CreatePart(c.header)
		if err != nil {
			return err
		}
		if err := c.fill(cw); err != nil {
			return err
		}
		if err := cw.Close(); err != nil {
			return err
		}
	}
	return nil
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
	// #nosec G707 -- net/smtp.Client.Mail validates and rejects CR/LF before writing the envelope address
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
