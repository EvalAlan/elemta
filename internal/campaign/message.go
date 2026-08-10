package campaign

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// mergeField matches {{ name }} with any surrounding spaces.
var mergeField = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}`)

// Merge substitutes {{field}} placeholders from a recipient's variables.
//
// An unknown field becomes empty rather than being left as "{{name}}". Mail
// that goes out reading "Hello {{first_name}}" is the classic bulk-send
// embarrassment, and it is better to send "Hello " than to advertise the
// template. UnresolvedFields reports them so the UI can warn before sending.
func Merge(template string, vars map[string]string) string {
	if template == "" || !strings.Contains(template, "{{") {
		return template
	}
	return mergeField.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.ToLower(strings.Trim(match, "{} \t"))
		if v, ok := vars[name]; ok {
			return v
		}
		return ""
	})
}

// MergeHTML is Merge for HTML bodies, escaping substituted values.
//
// Recipient variables come from an uploaded file. Injecting them raw lets a
// crafted "name" column put markup — or a script tag — into everyone's copy of
// the message, which is a stored cross-site scripting bug delivered by mail.
func MergeHTML(template string, vars map[string]string) string {
	if template == "" || !strings.Contains(template, "{{") {
		return template
	}
	return mergeField.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.ToLower(strings.Trim(match, "{} \t"))
		if v, ok := vars[name]; ok {
			return html.EscapeString(v)
		}
		return ""
	})
}

// UnresolvedFields lists placeholders in the template that no recipient
// supplies, so the operator can be told before the campaign goes out rather
// than after.
func UnresolvedFields(template string, recipients []Recipient) []string {
	matches := mergeField.FindAllStringSubmatch(template, -1)
	if len(matches) == 0 {
		return nil
	}

	// A field is unresolved if no recipient has a value for it.
	needed := map[string]bool{}
	for _, m := range matches {
		needed[strings.ToLower(m[1])] = true
	}
	for _, r := range recipients {
		for k := range r.Vars {
			delete(needed, strings.ToLower(k))
		}
		if len(needed) == 0 {
			break
		}
	}

	out := make([]string, 0, len(needed))
	for name := range needed {
		out = append(out, name)
	}
	return out
}

// EnvelopeSender is the address a campaign's mail is sent from on the wire.
//
// It is the bare address, not the From header. The two are different things: a
// From of `News <news@example.com>` is a correct header and an invalid MAIL
// FROM, and a delivery agent handed the display-name form either refuses it or
// strips it into something else — which is where bounces then go.
func EnvelopeSender(from string) (string, error) {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", fmt.Errorf("from address: %w", err)
	}
	return addr.Address, nil
}

// BuildMessage renders one recipient's copy as RFC 5322 bytes.
//
// Every header value that comes from the campaign is validated or encoded
// before it is written. A subject holding CR/LF, or a From that is really two
// addresses, would otherwise let the campaign author write arbitrary headers
// into every message — including a Bcc.
func BuildMessage(c *Campaign, r Recipient, hostname string) ([]byte, error) {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return nil, fmt.Errorf("from address: %w", err)
	}
	to, err := mail.ParseAddress(r.Email)
	if err != nil {
		return nil, fmt.Errorf("recipient %q: %w", r.Email, err)
	}
	subject := Merge(c.Subject, r.Vars)
	if strings.ContainsAny(subject, "\r\n") {
		return nil, fmt.Errorf("subject contains a line break after merging; a merge value must not be able to write headers")
	}

	textBody := Merge(c.TextBody, r.Vars)
	htmlBody := MergeHTML(c.HTMLBody, r.Vars)

	var b strings.Builder
	writeHeader := func(name, value string) {
		fmt.Fprintf(&b, "%s: %s\r\n", name, value)
	}

	writeHeader("From", from.String())
	writeHeader("To", to.String())
	if c.ReplyTo != "" {
		if replyTo, err := mail.ParseAddress(c.ReplyTo); err == nil {
			writeHeader("Reply-To", replyTo.String())
		}
	}
	// Encode the subject so non-ASCII survives, and so any structure in it is
	// carried as data rather than as header syntax.
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", subject))
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("Message-ID", messageID(hostname))
	writeHeader("MIME-Version", "1.0")
	// Bulk mail identifies itself. Without these a campaign looks like
	// individual correspondence to filters, which is both rude and a fast route
	// to being classified as spam.
	writeHeader("Precedence", "bulk")
	writeHeader("Auto-Submitted", "auto-generated")
	writeHeader("X-Campaign-ID", c.ID)

	switch {
	case htmlBody != "" && textBody != "":
		boundary := mimeBoundary()
		writeHeader("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", boundary))
		b.WriteString("\r\n")
		// Least-preferred part first, per RFC 2046: clients pick the last one
		// they can render.
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(normalizeBody(textBody))
		fmt.Fprintf(&b, "\r\n--%s\r\n", boundary)
		b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(normalizeBody(htmlBody))
		fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)

	case htmlBody != "":
		writeHeader("Content-Type", "text/html; charset=utf-8")
		writeHeader("Content-Transfer-Encoding", "8bit")
		b.WriteString("\r\n")
		b.WriteString(normalizeBody(htmlBody))

	default:
		writeHeader("Content-Type", "text/plain; charset=utf-8")
		writeHeader("Content-Transfer-Encoding", "8bit")
		b.WriteString("\r\n")
		b.WriteString(normalizeBody(textBody))
	}

	return []byte(b.String()), nil
}

// normalizeBody gives the body CRLF line endings and makes sure it ends with
// one. The server enforces RFC 5321 CRLF in DATA, so a body assembled with bare
// LF — which is what a browser textarea produces — would be refused by the very
// server sending it.
func normalizeBody(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	if !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return body
}

func messageID(hostname string) string {
	if hostname == "" {
		hostname = "localhost"
	}
	return fmt.Sprintf("<%s.%s@%s>", time.Now().UTC().Format("20060102150405"), randomToken(12), hostname)
}

func mimeBoundary() string {
	return "elemta-" + randomToken(16)
}

// randomToken produces a short unguessable string. MIME boundaries must not
// appear in the body, and a predictable boundary is one a crafted merge value
// could reproduce to break the message apart.
func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// Only reached if the system entropy source fails; a time-based value
		// still separates parts within a single message.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "=")
}
