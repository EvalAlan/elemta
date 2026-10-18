package mailbox

// The search index answers SEARCH without reading message bodies.
//
// Each message summary also stores the decoded From, To, Cc, Bcc and
// Subject header values, matched as case-insensitive substrings as IMAP
// specifies, and a text search vector of the readable body text (text/plain
// parts, and text/html with markup removed). BODY and TEXT match words by
// prefix against that vector, which is what users expect from a search box
// and what other indexed IMAP servers do; a literal substring scan of every
// body cannot scale. A pattern with no searchable words (punctuation only)
// still falls back to scanning bodies, and so does mail indexed before
// this existed until the backfill reaches it.

import (
	"bytes"
	"context"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
)

// maxIndexedText bounds the body text indexed per message. Postgres caps a
// tsvector at 1 MiB, and the start of a message is what people search for.
const maxIndexedText = 256 << 10

// indexedHeaders are the header fields with their own index column.
var indexedHeaders = map[string]string{
	"from": "hdr_from", "to": "hdr_to", "cc": "hdr_cc", "bcc": "hdr_bcc", "subject": "hdr_subject",
	// The webmail's has:attachment searches Content-Type for multipart/mixed.
	"content-type": "hdr_content_type",
}

// searchText is what a message contributes to the index. It isn't part of
// the stored summary data (gob skips unexported fields).
type searchText struct {
	headers map[string]string // lower-case field name to decoded values
	body    string
}

func indexHeaders(h textproto.Header) map[string]string {
	mh := mail.Header{Header: message.Header{Header: h}}
	out := map[string]string{}
	for field := range indexedHeaders {
		var vals []string
		fields := mh.FieldsByKey(field)
		for fields.Next() {
			v, err := fields.Text()
			if err != nil {
				v = fields.Value()
			}
			vals = append(vals, v)
		}
		out[field] = strings.ToLower(strings.Join(vals, "\n"))
	}
	return out
}

// bodyText extracts the readable text of a message, up to maxIndexedText.
func bodyText(raw []byte) string {
	e, err := message.Read(bytes.NewReader(raw))
	if e == nil || (err != nil && !message.IsUnknownCharset(err)) {
		return ""
	}
	var b strings.Builder
	collectText(e, &b, 0)
	return b.String()
}

var tagRE = regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>|<[^>]*>`)

func collectText(e *message.Entity, b *strings.Builder, depth int) {
	if depth > 32 || b.Len() >= maxIndexedText {
		return
	}
	if mr := e.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			collectText(part, b, depth+1)
		}
	}
	ct, _, _ := e.Header.ContentType()
	if disp, _, _ := e.Header.ContentDisposition(); disp == "attachment" {
		return
	}
	if ct != "text/plain" && ct != "text/html" && ct != "" {
		return
	}
	data, err := io.ReadAll(io.LimitReader(e.Body, int64(maxIndexedText-b.Len())*4))
	if err != nil && len(data) == 0 {
		return
	}
	text := string(data)
	if ct == "text/html" {
		text = html.UnescapeString(tagRE.ReplaceAllString(text, " "))
	}
	text = strings.ToValidUTF8(text, " ")
	if room := maxIndexedText - b.Len(); len(text) > room {
		text = text[:room]
	}
	b.WriteString(text)
	b.WriteByte('\n')
}

// tsPrefixQuery turns a search pattern into a tsquery matching every word
// as a prefix, or "" when the pattern has no letters or digits. Only
// letters and digits reach the query, so no input can change its syntax.
func tsPrefixQuery(pattern string) string {
	words := strings.FieldsFunc(strings.ToLower(pattern), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	if len(words) == 0 || len(words) > 32 {
		return ""
	}
	for i, w := range words {
		words[i] = w + ":*"
	}
	return strings.Join(words, " & ")
}

// likePattern escapes a substring for ILIKE.
func likePattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(s)) + "%"
}

// leafQuery is one condition on the summary row; a leaf's matches are the
// union of its queries.
type leafQuery struct {
	cond string
	args []any
}

// indexHits are the index's answers for the leaves of one SEARCH.
type indexHits struct {
	// leaves maps a leaf key to the UIDs it matched.
	leaves map[string]map[uint32]bool
	// unindexed holds UIDs whose summary predates the index; leaves are
	// evaluated by scanning for those.
	unindexed map[uint32]bool
}

func headerLeafKey(field, value string) string {
	return "h\x00" + strings.ToLower(field) + "\x00" + value
}
func bodyLeafKey(pattern string, text bool) string {
	if text {
		return "t\x00" + pattern
	}
	return "b\x00" + pattern
}

// collectLeaves lists the leaves of a criteria tree that the index can
// answer.
func collectLeaves(c *imap.SearchCriteria, out map[string]func() []leafQuery) {
	for _, f := range c.Header {
		col, ok := indexedHeaders[strings.ToLower(f.Key)]
		if !ok {
			continue
		}
		value := f.Value
		out[headerLeafKey(f.Key, value)] = func() []leafQuery {
			return []leafQuery{{"s." + col + ` ILIKE $3`, []any{likePattern(value)}}}
		}
	}
	for _, p := range c.Body {
		if q := tsPrefixQuery(p); q != "" {
			out[bodyLeafKey(p, false)] = func() []leafQuery {
				return []leafQuery{{`s.body_tsv @@ to_tsquery('simple',$3)`, []any{q}}}
			}
		}
	}
	for _, p := range c.Text {
		q := tsPrefixQuery(p)
		if q == "" {
			continue
		}
		like := likePattern(p)
		out[bodyLeafKey(p, true)] = func() []leafQuery {
			// TEXT covers the header too; the indexed fields stand in for it.
			// Two queries rather than one OR, so the body one can use its
			// GIN index.
			return []leafQuery{
				{`s.body_tsv @@ to_tsquery('simple',$3)`, []any{q}},
				{`(s.hdr_from ILIKE $3 OR s.hdr_to ILIKE $3 OR s.hdr_cc ILIKE $3 OR s.hdr_subject ILIKE $3)`, []any{like}},
			}
		}
	}
	for i := range c.Not {
		collectLeaves(&c.Not[i], out)
	}
	for i := range c.Or {
		collectLeaves(&c.Or[i][0], out)
		collectLeaves(&c.Or[i][1], out)
	}
}

// searchIndex runs the index queries for a criteria tree over one folder.
// It returns nil when no leaf can use the index.
func (e *Engine) searchIndex(ctx context.Context, folder int64, c *imap.SearchCriteria) (*indexHits, error) {
	leaves := map[string]func() []leafQuery{}
	collectLeaves(c, leaves)
	if len(leaves) == 0 {
		return nil, nil
	}
	hits := &indexHits{leaves: map[string]map[uint32]bool{}, unindexed: map[uint32]bool{}}
	rows, err := e.DB.QueryContext(ctx, `SELECT m.uid FROM mailbox_messages m LEFT JOIN mailbox_summaries s ON s.body=m.body AND s.version=$2
WHERE m.folder=$1 AND s.body IS NULL`, folder, summaryVersion)
	if err != nil {
		return nil, err
	}
	if err := collectUIDs(rows, hits.unindexed); err != nil {
		return nil, err
	}
	for key, build := range leaves {
		set := map[uint32]bool{}
		for _, q := range build() {
			// #nosec G202 -- cond is one of the fixed fragments above; values are parameters
			rows, err := e.DB.QueryContext(ctx, `SELECT m.uid FROM mailbox_messages m JOIN mailbox_summaries s ON s.body=m.body AND s.version=$1
WHERE m.folder=$2 AND `+q.cond, append([]any{summaryVersion, folder}, q.args...)...)
			if err != nil {
				return nil, err
			}
			if err := collectUIDs(rows, set); err != nil {
				return nil, err
			}
		}
		hits.leaves[key] = set
	}
	return hits, nil
}

func collectUIDs(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
	Err() error
}, into map[uint32]bool) error {
	defer rows.Close()
	for rows.Next() {
		var u uint32
		if err := rows.Scan(&u); err != nil {
			return err
		}
		into[u] = true
	}
	return rows.Err()
}
