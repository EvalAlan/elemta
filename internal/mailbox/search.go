package mailbox

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
)

// searchNeeds reports what a criteria tree needs beyond the message list
// and the index: the header block (from the summary) and the body text.
// Leaves the index answered (hits) need neither.
func searchNeeds(c *imap.SearchCriteria, hits *indexHits) (header, text bool) {
	header = !c.SentSince.IsZero() || !c.SentBefore.IsZero()
	for _, f := range c.Header {
		if !hits.has(headerLeafKey(f.Key, f.Value)) {
			header = true
		}
	}
	for _, p := range c.Body {
		if !hits.has(bodyLeafKey(p, false)) {
			text = true
		}
	}
	for _, p := range c.Text {
		if !hits.has(bodyLeafKey(p, true)) {
			text = true
		}
	}
	for i := range c.Not {
		h, t := searchNeeds(&c.Not[i], hits)
		header, text = header || h, text || t
	}
	for i := range c.Or {
		for j := range c.Or[i] {
			h, t := searchNeeds(&c.Or[i][j], hits)
			header, text = header || h, text || t
		}
	}
	return header, text
}

// searchNeedsRows reports whether a criteria tree reads a message's flags,
// internal date or size.
func searchNeedsRows(c *imap.SearchCriteria) bool {
	if len(c.Flag) > 0 || len(c.NotFlag) > 0 || !c.Since.IsZero() || !c.Before.IsZero() || c.Larger > 0 || c.Smaller > 0 {
		return true
	}
	for i := range c.Not {
		if searchNeedsRows(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if searchNeedsRows(&c.Or[i][0]) || searchNeedsRows(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

func (h *indexHits) has(key string) bool {
	if h == nil {
		return false
	}
	_, ok := h.leaves[key]
	return ok
}

// lookup answers a leaf from the index for one message, or reports false
// when the message or the leaf isn't indexed.
func (h *indexHits) lookup(key string, uid uint32) (matched, ok bool) {
	if h == nil || h.unindexed[uid] {
		return false, false
	}
	set, ok := h.leaves[key]
	if !ok {
		return false, false
	}
	return set[uid], true
}

func dateMatches(t, since, before time.Time) bool {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return (since.IsZero() || !d.Before(since)) && (before.IsZero() || d.Before(before))
}

// searchSource is what a message is matched against. Header criteria use
// the summary's header block; the body is read only for BODY and TEXT.
type searchSource struct {
	summary     *Summary
	loadSummary func() (*Summary, error)
	header      *mail.Header
	raw         []byte
	load        func() ([]byte, error)
	err         error
	hits        *indexHits
}

func (src *searchSource) sum() *Summary {
	if src.summary == nil && src.err == nil && src.loadSummary != nil {
		src.summary, src.err = src.loadSummary()
	}
	return src.summary
}

func (src *searchSource) body() []byte {
	if src.raw == nil && src.err == nil && src.load != nil {
		src.raw, src.err = src.load()
	}
	return src.raw
}

func (src *searchSource) headers() *mail.Header {
	if src.header != nil {
		return src.header
	}
	block := []byte(nil)
	if sum := src.sum(); sum != nil {
		block = sum.Header
	}
	if block == nil {
		block = src.body()
	}
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(block)))
	if err != nil {
		h = textproto.Header{}
	}
	src.header = &mail.Header{Header: message.Header{Header: h}}
	return src.header
}

func matchMessage(m Message, seq, total, maxUID uint32, src *searchSource, c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if !sequenceContains(set, seq, total) {
			return false
		}
	}
	for _, set := range c.UID {
		seqSet := imap.SeqSet{}
		for _, r := range set {
			seqSet = append(seqSet, imap.SeqRange{Start: uint32(r.Start), Stop: uint32(r.Stop)})
		}
		if !sequenceContains(seqSet, m.UID, maxUID) {
			return false
		}
	}
	if !dateMatches(m.Date, c.Since, c.Before) || (c.Larger > 0 && m.Size <= c.Larger) || (c.Smaller > 0 && m.Size >= c.Smaller) {
		return false
	}
	for _, f := range c.Flag {
		if !hasFlag(m.Flags, string(f)) {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if hasFlag(m.Flags, string(f)) {
			return false
		}
	}
	for _, field := range c.Header {
		if matched, ok := src.hits.lookup(headerLeafKey(field.Key, field.Value), m.UID); ok {
			if !matched {
				return false
			}
			continue
		}
		found := false
		fields := src.headers().FieldsByKey(field.Key)
		for fields.Next() {
			value, _ := fields.Text()
			if strings.Contains(strings.ToLower(value), strings.ToLower(field.Value)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
		var sent time.Time
		if sum := src.sum(); sum != nil {
			sent = sum.Sent
		} else if d, err := src.headers().Date(); err == nil {
			sent = d
		}
		if sent.IsZero() || !dateMatches(sent, c.SentSince, c.SentBefore) {
			return false
		}
	}
	for _, pattern := range c.Body {
		if matched, ok := src.hits.lookup(bodyLeafKey(pattern, false), m.UID); ok {
			if !matched {
				return false
			}
			continue
		}
		if !matchesMIME(src.body(), pattern, false) {
			return false
		}
	}
	for _, pattern := range c.Text {
		if matched, ok := src.hits.lookup(bodyLeafKey(pattern, true), m.UID); ok {
			if !matched {
				return false
			}
			continue
		}
		if !matchesMIME(src.body(), pattern, true) {
			return false
		}
	}
	for i := range c.Not {
		if matchMessage(m, seq, total, maxUID, src, &c.Not[i]) {
			return false
		}
	}
	for i := range c.Or {
		if !matchMessage(m, seq, total, maxUID, src, &c.Or[i][0]) && !matchMessage(m, seq, total, maxUID, src, &c.Or[i][1]) {
			return false
		}
	}
	return true
}
func sequenceContains(set imap.SeqSet, n, max uint32) bool {
	for _, r := range set {
		a, b := r.Start, r.Stop
		if a == 0 {
			a = max
		}
		if b == 0 {
			b = max
		}
		if a > b {
			a, b = b, a
		}
		if n >= a && n <= b {
			return true
		}
	}
	return false
}
func matchesMIME(raw []byte, pattern string, headers bool) bool {
	e, _ := message.Read(bytes.NewReader(raw))
	if e == nil {
		return false
	}
	return matchPart(e, strings.ToLower(pattern), headers, 0)
}
func matchPart(e *message.Entity, pattern string, headers bool, depth int) bool {
	if depth > 32 {
		return false
	}
	if headers {
		fields := e.Header.Fields()
		for fields.Next() {
			v, _ := fields.Text()
			if strings.Contains(strings.ToLower(v), pattern) {
				return true
			}
		}
	}
	if multi := e.MultipartReader(); multi != nil {
		for {
			part, err := multi.NextPart()
			if err != nil {
				return false
			}
			if matchPart(part, pattern, headers, depth+1) {
				return true
			}
		}
	}
	ct, _, _ := e.Header.ContentType()
	if !strings.HasPrefix(ct, "text/") && !strings.HasPrefix(ct, "message/") {
		return false
	}
	data, err := io.ReadAll(e.Body)
	return err == nil && strings.Contains(strings.ToLower(string(data)), pattern)
}
