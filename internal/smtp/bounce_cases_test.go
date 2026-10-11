package smtp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsedDSN is a bounce taken apart the way a receiving MUA or bounce
// processor would, so the cases below assert on structure rather than on
// substrings that a malformed message could still contain.
type parsedDSN struct {
	header     mail.Header
	reportType string
	parts      []dsnPart
	perMessage textproto.MIMEHeader
	recipients []textproto.MIMEHeader
	raw        string
}

type dsnPart struct {
	contentType string
	body        []byte
}

func parseDSN(t *testing.T, content []byte) parsedDSN {
	t.Helper()
	out := parsedDSN{raw: string(content)}
	msg, err := mail.ReadMessage(bytes.NewReader(content))
	require.NoError(t, err, "bounce must parse as an RFC 5322 message")
	out.header = msg.Header

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	require.NoError(t, err)
	require.Equal(t, "multipart/report", mediaType)
	out.reportType = params["report-type"]

	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(p)
		require.NoError(t, err)
		ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		out.parts = append(out.parts, dsnPart{contentType: ct, body: body})
		if ct != "message/delivery-status" {
			continue
		}
		// RFC 3464 §2.1: groups of fields separated by blank lines, the
		// first per-message, the rest one per recipient.
		groups := strings.Split(strings.TrimRight(string(body), "\r\n"), "\r\n\r\n")
		for i, g := range groups {
			h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(g + "\r\n\r\n"))).ReadMIMEHeader()
			require.NoError(t, err, "delivery-status group %d must parse", i)
			if i == 0 {
				out.perMessage = h
			} else {
				out.recipients = append(out.recipients, h)
			}
		}
	}
	return out
}

func (d parsedDSN) partTypes() []string {
	var types []string
	for _, p := range d.parts {
		types = append(types, p.contentType)
	}
	return types
}

func (d parsedDSN) finalRecipients() []string {
	var out []string
	for _, r := range d.recipients {
		out = append(out, r.Get("Final-Recipient"))
	}
	return out
}

func TestBounceCases(t *testing.T) {
	const (
		sender   = "alice@sender.example"
		original = "Received: from x\r\nFrom: Alice <alice@sender.example>\r\nTo: bob@rcpt.example\r\nSubject: quarterly numbers\r\nMessage-ID: <orig-1@sender.example>\r\n\r\nthe confidential body\r\n"
	)
	arrived := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	type tc struct {
		name        string
		from        string
		to          []string
		annotations map[string]string
		reason      string
		content     string // original message; empty means the default above

		wantBounce bool
		check      func(t *testing.T, d parsedDSN)
	}
	cases := []tc{
		{
			name:       "RFC 3464 structure for a plain 550",
			from:       sender,
			to:         []string{"bob@rcpt.example"},
			reason:     "550 5.1.1 <bob@rcpt.example>: Recipient address rejected: User unknown",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				assert.Equal(t, "delivery-status", d.reportType)
				assert.Equal(t, []string{"text/plain", "message/delivery-status", "text/rfc822-headers"}, d.partTypes())
				assert.Equal(t, "dns; test.example.com", d.perMessage.Get("Reporting-MTA"))
				assert.Equal(t, arrived.Format(time.RFC1123Z), d.perMessage.Get("Arrival-Date"))
				assert.Empty(t, d.perMessage.Get("Final-Recipient"), "per-message group carries no recipient fields")
				require.Len(t, d.recipients, 1)
				r := d.recipients[0]
				assert.Equal(t, "rfc822; bob@rcpt.example", r.Get("Final-Recipient"))
				assert.Equal(t, "failed", r.Get("Action"))
				assert.Equal(t, "5.1.1", r.Get("Status"))
				assert.Equal(t, "smtp; 550 5.1.1 <bob@rcpt.example>: Recipient address rejected: User unknown",
					r.Get("Diagnostic-Code"))
				assert.NotEmpty(t, r.Get("Last-Attempt-Date"))
				assert.Equal(t, "<"+sender+">", d.header.Get("To"))
				assert.Equal(t, "auto-replied", d.header.Get("Auto-Submitted"), "RFC 3834 marker keeps autoresponders quiet")
			},
		},
		{
			name:       "local failure is not labelled as an SMTP reply",
			from:       sender,
			to:         []string{"bob@rcpt.example"},
			reason:     "dial tcp 192.0.2.1:25: connection refused",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.recipients, 1)
				assert.Equal(t, "5.4.2", d.recipients[0].Get("Status"))
				assert.True(t, strings.HasPrefix(d.recipients[0].Get("Diagnostic-Code"), "X-Elemta; "),
					"got %q", d.recipients[0].Get("Diagnostic-Code"))
			},
		},
		{
			name:       "IPv4 address starting with 5 is not read as an enhanced status",
			from:       sender,
			to:         []string{"bob@rcpt.example"},
			reason:     "dial tcp 5.6.7.8:25: connection refused",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.recipients, 1)
				assert.Equal(t, "5.4.2", d.recipients[0].Get("Status"))
			},
		},
		{
			name: "NOTIFY=NEVER suppresses the bounce",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_notify:bob@rcpt.example": "NEVER"},
			reason:      "550 5.1.1 User unknown",
		},
		{
			name: "NOTIFY=SUCCESS alone does not ask for failures",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_notify:bob@rcpt.example": "SUCCESS"},
			reason:      "550 5.1.1 User unknown",
		},
		{
			name: "NOTIFY=DELAY alone does not ask for failures",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_notify:bob@rcpt.example": "DELAY"},
			reason:      "550 5.1.1 User unknown",
		},
		{
			name: "NOTIFY=FAILURE,DELAY bounces and echoes the request",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_notify:bob@rcpt.example": "FAILURE,DELAY"},
			reason:      "550 5.1.1 User unknown",
			wantBounce:  true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.recipients, 1)
				assert.Equal(t, "FAILURE,DELAY", d.recipients[0].Get("Original-Notify"))
			},
		},
		{
			name: "mixed recipients: one DSN listing only those that asked for it",
			from: sender,
			// The processor passes only the permanently failed recipients;
			// of those, the one with NOTIFY=NEVER and the one with
			// NOTIFY=SUCCESS must not appear.
			to: []string{"a@rcpt.example", "never@rcpt.example", "success@rcpt.example", "c@rcpt.example"},
			annotations: map[string]string{
				"dsn_notify:never@rcpt.example":   "NEVER",
				"dsn_notify:success@rcpt.example": "SUCCESS",
				"dsn_notify:c@rcpt.example":       "FAILURE",
			},
			reason:     "550 5.1.1 User unknown",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				assert.Equal(t, []string{"rfc822; a@rcpt.example", "rfc822; c@rcpt.example"}, d.finalRecipients())
				assert.NotContains(t, d.raw, "never@rcpt.example")
				assert.NotContains(t, d.raw, "success@rcpt.example")
				assert.Equal(t, 1, strings.Count(d.raw, "Reporting-MTA:"))
			},
		},
		{
			name: "RET=HDRS returns headers, not the body",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_return": "HDRS"},
			reason:      "550 5.1.1 User unknown",
			wantBounce:  true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.parts, 3)
				assert.Equal(t, "text/rfc822-headers", d.parts[2].contentType)
				assert.Contains(t, string(d.parts[2].body), "Subject: quarterly numbers")
				assert.NotContains(t, d.raw, "the confidential body")
			},
		},
		{
			name: "RET=FULL returns the whole message as message/rfc822",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_return": "full"},
			reason:      "550 5.1.1 User unknown",
			wantBounce:  true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.parts, 3)
				assert.Equal(t, "message/rfc822", d.parts[2].contentType)
				inner, err := mail.ReadMessage(bytes.NewReader(d.parts[2].body))
				require.NoError(t, err)
				assert.Equal(t, "<orig-1@sender.example>", inner.Header.Get("Message-ID"))
				body, _ := io.ReadAll(inner.Body)
				assert.Contains(t, string(body), "the confidential body")
			},
		},
		{
			name: "RET=FULL with a huge message falls back to headers",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_return": "FULL"},
			content:     "Subject: big\r\n\r\n" + strings.Repeat("A", maxReturnedMessage+1),
			reason:      "552 5.3.4 Message too big",
			wantBounce:  true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.parts, 3)
				assert.Equal(t, "text/rfc822-headers", d.parts[2].contentType)
				assert.Less(t, len(d.raw), 64<<10)
			},
		},
		{
			name: "huge message with no header/body separator is still capped",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{"dsn_return": "FULL"},
			content:     strings.Repeat("X-Filler: "+strings.Repeat("y", 60)+"\r\n", (maxReturnedMessage/72)+100),
			reason:      "552 5.3.4 Message too big",
			wantBounce:  true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.parts, 3)
				assert.Equal(t, "text/rfc822-headers", d.parts[2].contentType)
				assert.LessOrEqual(t, len(d.parts[2].body), maxReturnedHeaders)
			},
		},
		{
			name: "ENVID and ORCPT carried through, xtext-decoded",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{
				"dsn_envid":                   "QQ314159+2Bx",
				"dsn_orcpt:bob@rcpt.example":  "rfc822;Bob+2Bsales@alias.example",
				"dsn_notify:bob@rcpt.example": "FAILURE",
			},
			reason:     "550 5.1.1 User unknown",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				assert.Equal(t, "QQ314159+x", d.perMessage.Get("Original-Envelope-Id"))
				require.Len(t, d.recipients, 1)
				assert.Equal(t, "rfc822;Bob+sales@alias.example", d.recipients[0].Get("Original-Recipient"))
				assert.Equal(t, "rfc822; bob@rcpt.example", d.recipients[0].Get("Final-Recipient"),
					"Final-Recipient is the address actually tried, not ORCPT")
			},
		},
		{
			name: "xtext-encoded CRLF in ENVID cannot inject fields",
			from: sender, to: []string{"bob@rcpt.example"},
			annotations: map[string]string{
				"dsn_envid":                  "id+0D+0AAction: delivered",
				"dsn_orcpt:bob@rcpt.example": "rfc822;x+0D+0AStatus: 2.0.0",
			},
			reason:     "550 5.1.1 User unknown",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				assert.Empty(t, d.perMessage.Get("Action"))
				require.Len(t, d.recipients, 1)
				assert.Equal(t, []string{"failed"}, d.recipients[0].Values("Action"))
				assert.Equal(t, []string{"5.1.1"}, d.recipients[0].Values("Status"))
			},
		},
		{
			name: "CR/LF in remote server text cannot inject DSN fields or MIME parts",
			from: sender, to: []string{"bob@rcpt.example"},
			reason: "550-5.7.1 rejected\r\nAction: delivered\r\nStatus: 2.0.0\r\n\r\n" +
				"Final-Recipient: rfc822; evil@x\n--elemta-boundary-1\nContent-Type: text/html\n\n550 5.7.1 bye",
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				require.Len(t, d.recipients, 1, "injected blank lines must not create recipient groups")
				r := d.recipients[0]
				assert.Equal(t, []string{"failed"}, r.Values("Action"))
				assert.Equal(t, []string{"5.7.1"}, r.Values("Status"))
				assert.Len(t, d.parts, 3)
				for _, line := range strings.Split(d.raw, "\r\n") {
					assert.NotContains(t, line, "\n", "no bare LF anywhere in the bounce")
					assert.LessOrEqual(t, len(line), 998, "RFC 5322 line limit")
				}
			},
		},
		{
			name: "long 8-bit diagnostic is folded and kept 7-bit",
			from: sender, to: []string{"bob@rcpt.example"},
			reason:     "550 5.2.2 Postfach voll — " + strings.Repeat("überfüllt ", 150) + strings.Repeat("z", 1200),
			wantBounce: true,
			check: func(t *testing.T, d parsedDSN) {
				for _, line := range strings.Split(d.raw, "\r\n") {
					assert.LessOrEqual(t, len(line), 998)
				}
				for _, p := range d.parts[:2] {
					for _, b := range p.body {
						require.Less(t, b, byte(0x80), "%s part must be 7-bit", p.contentType)
					}
				}
				require.Len(t, d.recipients, 1)
				assert.Equal(t, "5.2.2", d.recipients[0].Get("Status"))
				assert.True(t, strings.HasPrefix(d.recipients[0].Get("Diagnostic-Code"), "smtp; 550 5.2.2"))
			},
		},
		{
			name: "null sender never bounces", from: "", to: []string{"bob@rcpt.example"},
			reason: "550 5.1.1 User unknown",
		},
		{
			name: "null sender in angle brackets never bounces", from: "<>", to: []string{"bob@rcpt.example"},
			reason: "550 5.1.1 User unknown",
		},
		{
			name: "MAILER-DAEMON sender does not get a bounce", from: "MAILER-DAEMON@other.example",
			to: []string{"bob@rcpt.example"}, reason: "550 5.1.1 User unknown",
		},
		{
			name: "bare mailer-daemon sender does not get a bounce", from: "mailer-daemon",
			to: []string{"bob@rcpt.example"}, reason: "550 5.1.1 User unknown",
		},
		{
			name: "our own postmaster does not bounce to itself", from: "Postmaster@test.example.com",
			to: []string{"bob@rcpt.example"}, reason: "550 5.1.1 User unknown",
		},
		{
			name: "a remote postmaster still gets told", from: "postmaster@sender.example",
			to: []string{"bob@rcpt.example"}, reason: "550 5.1.1 User unknown",
			wantBounce: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			engine, mgr := newTestBounceEngine(t)
			content := c.content
			if content == "" {
				content = original
			}
			id, err := mgr.EnqueueMessage(sender, c.to, "quarterly numbers", []byte(content), queue.PriorityNormal, arrived)
			require.NoError(t, err)

			result := engine.GenerateBounceIfNeeded(context.Background(), queue.Message{
				ID: id, From: c.from, To: c.to, Subject: "quarterly numbers",
				ReceivedAt: arrived, Annotations: c.annotations,
			}, c.reason)
			require.NotNil(t, result)
			require.NoError(t, result.Error)
			require.Equal(t, c.wantBounce, result.BounceGenerated)
			if !c.wantBounce {
				return
			}

			bounce, err := mgr.GetMessage(result.BounceID)
			require.NoError(t, err)
			assert.Empty(t, bounce.From, "bounces carry a null reverse-path so they cannot bounce")
			assert.Equal(t, []string{c.from}, bounce.To)

			raw, err := mgr.GetMessageContent(result.BounceID)
			require.NoError(t, err)
			d := parseDSN(t, raw)
			if c.check != nil {
				c.check(t, d)
			}
		})
	}
}

// Two bounces for one message (a partial failure, then the rest after
// retries) must not share a Message-ID, or receivers that de-duplicate on it
// drop the second.
func TestBounceMessageIDsDifferPerBounce(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	msg := queue.Message{ID: "m1", From: "a@x.example", To: []string{"b@y.example"}}
	first, err := engine.buildDSNBounceAt(msg, "550 5.1.1 no", time.Unix(100, 0))
	require.NoError(t, err)
	second, err := engine.buildDSNBounceAt(msg, "550 5.1.1 no", time.Unix(200, 0))
	require.NoError(t, err)
	again, err := engine.buildDSNBounceAt(msg, "550 5.1.1 no", time.Unix(100, 0))
	require.NoError(t, err)

	id := func(b []byte) string {
		m, err := mail.ReadMessage(bytes.NewReader(b))
		require.NoError(t, err)
		return m.Header.Get("Message-ID")
	}
	assert.NotEqual(t, id(first), id(second))
	assert.Equal(t, id(first), id(again), "the idempotent path depends on a stable ID for a stable time")
}

// A bounce with no stored arrival time omits Arrival-Date rather than
// claiming the message arrived in year 1.
func TestBounceOmitsZeroArrivalDate(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	raw, err := engine.buildDSNBounceAt(queue.Message{ID: "m2", From: "a@x.example", To: []string{"b@y.example"}},
		"550 5.1.1 no", time.Unix(100, 0))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "Arrival-Date:")
	assert.NotContains(t, string(raw), "0001")
}

func TestDecodeXText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":           "plain",
		"a+2Bb":           "a+b",
		"a+2bb":           "a+b",
		"+3D":             "=",
		"bad+ZZ":          "bad+ZZ",
		"trailing+2":      "trailing+2",
		"rfc822;x+40y.ex": "rfc822;x@y.ex",
	} {
		assert.Equal(t, want, decodeXText(in), in)
	}
}
