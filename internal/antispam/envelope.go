package antispam

// What the SMTP server knows about a message beyond its content: who
// connected, what they said at HELO, the envelope sender and recipients, and
// whether they logged in. Rspamd scores far better with it. Without it, every
// message is judged as if it arrived from an unknown host, so its IP and
// HELO checks have nothing to work on, and a user's own mail is scored like
// inbound spam because Rspamd can't tell it was submitted after a login.
//
// It travels in the context rather than through the Scanner interface so the
// scanners that don't use it (SpamAssassin, ClamAV) are unchanged.

import (
	"context"
	"net/http"
	"strings"
)

// Envelope describes a message's SMTP transaction.
type Envelope struct {
	ClientIP string
	Helo     string
	From     string   // envelope sender; empty for bounces
	Rcpt     []string // envelope recipients
	User     string   // the authenticated user, or empty
	QueueID  string
}

type envelopeKey struct{}

// WithEnvelope attaches a message's envelope to ctx for the scanners.
func WithEnvelope(ctx context.Context, e Envelope) context.Context {
	return context.WithValue(ctx, envelopeKey{}, e)
}

func envelopeFrom(ctx context.Context) (Envelope, bool) {
	e, ok := ctx.Value(envelopeKey{}).(Envelope)
	return e, ok
}

// headerValue keeps client-supplied text (HELO, addresses) from breaking
// out of an HTTP header: control characters are dropped and length capped.
func headerValue(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.TrimSpace(s)
}

// setRspamdHeaders adds the envelope as the request headers Rspamd's
// /checkv2 reads: IP, Helo, From, Rcpt (one per recipient), User and
// Queue-Id. An empty field is left out, so Rspamd treats it as unknown
// rather than as an empty value. From is always sent, as "<>" for the null
// sender of a bounce, which Rspamd parses as the empty address.
func (e Envelope) setRspamdHeaders(h http.Header) {
	set := func(name, v string) {
		if v = headerValue(v); v != "" {
			h.Set(name, v)
		}
	}
	set("IP", e.ClientIP)
	set("Helo", e.Helo)
	if from := headerValue(e.From); from != "" {
		h.Set("From", from)
	} else {
		h.Set("From", "<>")
	}
	for i, r := range e.Rcpt {
		if i == 100 {
			break
		}
		if r = headerValue(r); r != "" {
			h.Add("Rcpt", r)
		}
	}
	set("User", e.User)
	set("Queue-Id", e.QueueID)
}
