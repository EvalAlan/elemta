package mailbox

// Message summaries let the common IMAP requests run from Postgres alone.
//
// A message list (FETCH ENVELOPE, BODYSTRUCTURE, BODY.PEEK[HEADER.FIELDS
// (...)]) is what every client and the webmail send most, and answering it
// from the message body means one body-store read per row: a 50-message
// page is 50 S3 GETs. The summary holds what those requests need (the
// header block, the envelope and the MIME structure) plus the fields SORT
// and THREAD order by. It is computed once, when the body is stored, and
// keyed by the body, so copies of a message share it and body cleanup
// removes it. Mail stored before summaries existed gets one the first time
// it is fetched, or from `elemta mailbox backfill`.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/lib/pq"
)

// summaryVersion changes when the summary format or its derivation does, so
// stale rows are recomputed rather than served.
const summaryVersion = 1

// maxSummaryHeader bounds the stored header block. Larger headers (rare,
// usually abuse) are answered from the body instead.
const maxSummaryHeader = 256 << 10

func init() {
	gob.Register(&imap.BodyStructureSinglePart{})
	gob.Register(&imap.BodyStructureMultiPart{})
}

// Summary is what the server needs to answer header-level requests.
type Summary struct {
	Header    []byte // the raw header block, nil when it was too large
	Envelope  *imap.Envelope
	Structure imap.BodyStructure

	// Sort and thread keys (RFC 5256).
	BaseSubject string
	Sent        time.Time // the Date header, zero when missing or bad
	From        string    // first From mailbox, lower case
	To          string
	Cc          string
	DisplayFrom string // RFC 5957: display name, or the address
	DisplayTo   string
	MessageID   string
	References  []string // References, or In-Reply-To when absent
}

// summarize computes the summary of a raw message. It never fails: damaged
// mail gets the summary of whatever could be parsed.
func summarize(raw []byte) *Summary {
	s := &Summary{Structure: bodyStructure(raw)}
	br := bufio.NewReader(bytes.NewReader(raw))
	header, err := textproto.ReadHeader(br)
	if err != nil {
		s.Envelope = &imap.Envelope{}
		return s
	}
	if end := headerEnd(raw); end >= 0 && end <= maxSummaryHeader {
		s.Header = append([]byte(nil), raw[:end]...)
	}
	s.Envelope = imapserver.ExtractEnvelope(header)
	mh := mail.Header{Header: message.Header{Header: header}}
	subject, _ := mh.Subject()
	s.BaseSubject = baseSubject(subject)
	if d, err := mh.Date(); err == nil {
		s.Sent = d.UTC()
	}
	s.From, s.DisplayFrom = firstAddress(s.Envelope.From)
	s.To, s.DisplayTo = firstAddress(s.Envelope.To)
	s.Cc, _ = firstAddress(s.Envelope.Cc)
	s.MessageID = msgID(header.Get("Message-Id"))
	s.References = msgIDs(header.Get("References"))
	if len(s.References) == 0 {
		// RFC 5256: In-Reply-To stands in when there is no References.
		if ids := msgIDs(header.Get("In-Reply-To")); len(ids) > 0 {
			s.References = ids[:1]
		}
	}
	return s
}

// headerEnd is the length of the header block including the blank line, or
// -1 when the message has no body separator.
func headerEnd(raw []byte) int {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		if j := bytes.Index(raw, []byte("\n\n")); j >= 0 && j < i {
			return j + 2
		}
		return i + 4
	}
	if j := bytes.Index(raw, []byte("\n\n")); j >= 0 {
		return j + 2
	}
	return -1
}

func firstAddress(list []imap.Address) (addr, display string) {
	for _, a := range list {
		if a.IsGroupStart() || a.IsGroupEnd() {
			continue
		}
		addr = strings.ToLower(a.Addr())
		display = a.Name
		if display == "" {
			display = addr
		}
		return addr, strings.ToLower(display)
	}
	return "", ""
}

func msgID(v string) string {
	ids := msgIDs(v)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// msgIDs extracts <...> message IDs, in order, without duplicates.
func msgIDs(v string) []string {
	var out []string
	seen := map[string]bool{}
	for {
		i := strings.IndexByte(v, '<')
		if i < 0 {
			return out
		}
		j := strings.IndexByte(v[i:], '>')
		if j < 0 {
			return out
		}
		id := strings.TrimSpace(v[i+1 : i+j])
		v = v[i+j+1:]
		if id != "" && !seen[id] && len(out) < 100 {
			seen[id] = true
			out = append(out, id)
		}
	}
}

// baseSubject is the RFC 5256 base subject: reply and forward markers,
// leading "[list]" tags and "(fwd)" trailers removed, whitespace collapsed,
// lower case for comparison.
func baseSubject(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for {
		prev := s
		for strings.HasSuffix(strings.ToLower(s), "(fwd)") {
			s = strings.TrimSpace(s[:len(s)-5])
		}
		for {
			t, ok := stripLeader(s)
			if !ok {
				break
			}
			s = t
		}
		if l := strings.ToLower(s); strings.HasPrefix(l, "[fwd:") && strings.HasSuffix(s, "]") {
			s = strings.TrimSpace(s[5 : len(s)-1])
		}
		if s == prev {
			return strings.ToLower(s)
		}
	}
}

// stripLeader removes one "re:", "fw:" or "fwd:" (optionally with [blob]s
// before the colon), or one leading [blob] when text remains after it.
func stripLeader(s string) (string, bool) {
	l := strings.ToLower(s)
	for _, p := range []string{"re", "fwd", "fw"} {
		if !strings.HasPrefix(l, p) {
			continue
		}
		r := strings.TrimLeft(s[len(p):], " ")
		for strings.HasPrefix(r, "[") {
			k := strings.IndexByte(r, ']')
			if k < 0 {
				break
			}
			r = strings.TrimLeft(r[k+1:], " ")
		}
		if strings.HasPrefix(r, ":") {
			return strings.TrimLeft(r[1:], " "), true
		}
	}
	if strings.HasPrefix(s, "[") {
		if k := strings.IndexByte(s, ']'); k > 0 {
			if rest := strings.TrimLeft(s[k+1:], " "); rest != "" {
				return rest, true
			}
		}
	}
	return s, false
}

func encodeSummary(s *Summary) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSummary(data []byte) (*Summary, error) {
	var s Summary
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&s); err != nil {
		return nil, err
	}
	if s.Envelope == nil {
		s.Envelope = &imap.Envelope{}
	}
	return &s, nil
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func storeSummary(ctx context.Context, db execer, body string, s *Summary) error {
	data, err := encodeSummary(s)
	if err != nil {
		return err
	}
	refs := s.References
	if refs == nil {
		refs = []string{} // pq sends a nil slice as NULL
	}
	var sent any
	if !s.Sent.IsZero() {
		sent = s.Sent
	}
	_, err = db.ExecContext(ctx, `INSERT INTO mailbox_summaries(body,version,data,base_subject,sent,sender,recipient,cc,display_from,display_to,message_id,refs)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT(body) DO UPDATE SET version=EXCLUDED.version,data=EXCLUDED.data,base_subject=EXCLUDED.base_subject,sent=EXCLUDED.sent,
sender=EXCLUDED.sender,recipient=EXCLUDED.recipient,cc=EXCLUDED.cc,display_from=EXCLUDED.display_from,display_to=EXCLUDED.display_to,
message_id=EXCLUDED.message_id,refs=EXCLUDED.refs`,
		body, summaryVersion, data, s.BaseSubject, sent, s.From, s.To, s.Cc, s.DisplayFrom, s.DisplayTo, s.MessageID, pq.Array(refs))
	return err
}

func (e *Engine) missingSummaries(ctx context.Context, where string, limit int, start string) ([]Message, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT b.key,b.size,b.checksum FROM mailbox_bodies b
LEFT JOIN mailbox_summaries s ON s.body=b.key AND s.version=$1
WHERE b.state='ready' AND s.body IS NULL AND `+where+` LIMIT $2`, summaryVersion, limit, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.Body, &m.Size, &m.Checksum); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Summaries returns the stored, current summaries of the messages' bodies.
// Messages without one are missing from the map.
func (e *Engine) Summaries(ctx context.Context, msgs []Message) (map[string]*Summary, error) {
	out := make(map[string]*Summary, len(msgs))
	if len(msgs) == 0 {
		return out, nil
	}
	keys := make([]string, 0, len(msgs))
	for _, m := range msgs {
		keys = append(keys, m.Body)
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT body,data FROM mailbox_summaries WHERE body=ANY($1) AND version=$2`, pq.Array(keys), summaryVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var data []byte
		if err := rows.Scan(&key, &data); err != nil {
			return nil, err
		}
		s, err := decodeSummary(data)
		if err != nil {
			continue // recomputed by the caller
		}
		out[key] = s
	}
	return out, rows.Err()
}

// Summary returns the message's summary, computing and storing it from the
// body when there is none yet.
func (e *Engine) Summary(ctx context.Context, m Message) (*Summary, error) {
	got, err := e.Summaries(ctx, []Message{m})
	if err != nil {
		return nil, err
	}
	if s := got[m.Body]; s != nil {
		return s, nil
	}
	raw, err := e.Read(ctx, m)
	if err != nil {
		return nil, err
	}
	s := summarize(raw)
	if err := storeSummary(ctx, e.DB, m.Body, s); err != nil {
		return nil, fmt.Errorf("store summary: %w", err)
	}
	return s, nil
}

// Backfill computes missing or outdated summaries, at most limit of them,
// and reports how many it stored.
func (e *Engine) Backfill(ctx context.Context, limit int) (int, error) {
	// Body keys are random hex, so starting at a random key spreads
	// replicas running this at the same time over different bodies, and
	// the key index makes each run cheap.
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 0, err
	}
	start := hex.EncodeToString(seed[:])
	todo, err := e.missingSummaries(ctx, `b.key>=$3 ORDER BY b.key`, limit, start)
	if err != nil {
		return 0, err
	}
	if len(todo) < limit {
		more, err := e.missingSummaries(ctx, `b.key<$3 ORDER BY b.key`, limit-len(todo), start)
		if err != nil {
			return 0, err
		}
		todo = append(todo, more...)
	}
	// One unreadable body must not stop the rest; it is retried next time
	// and reported.
	n := 0
	var errs []error
	for _, m := range todo {
		raw, err := e.Read(ctx, m)
		if errors.Is(err, ErrTooLarge) {
			raw = nil
		} else if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", m.Body, err))
			continue
		}
		if err := storeSummary(ctx, e.DB, m.Body, summarize(raw)); err != nil {
			return n, err
		}
		n++
	}
	return n, errors.Join(errs...)
}
