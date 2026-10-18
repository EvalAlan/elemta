package mailbox

import (
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

func searchNeedsBody(c *imap.SearchCriteria) bool {
	if len(c.Header) > 0 || len(c.Body) > 0 || len(c.Text) > 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
		return true
	}
	for i := range c.Not {
		if searchNeedsBody(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if searchNeedsBody(&c.Or[i][0]) || searchNeedsBody(&c.Or[i][1]) {
			return true
		}
	}
	return false
}
func dateMatches(t, since, before time.Time) bool {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return (since.IsZero() || !d.Before(since)) && (before.IsZero() || d.Before(before))
}
func matchMessage(m Message, seq, total, maxUID uint32, raw []byte, c *imap.SearchCriteria) bool {
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
	if searchNeedsBody(c) {
		entity, err := message.Read(bytes.NewReader(raw))
		if entity == nil || (err != nil && !message.IsUnknownCharset(err)) {
			return false
		}
		h := mail.Header{Header: entity.Header}
		for _, field := range c.Header {
			found := false
			fields := h.FieldsByKey(field.Key)
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
			d, err := h.Date()
			if err != nil || !dateMatches(d, c.SentSince, c.SentBefore) {
				return false
			}
		}
		for _, pattern := range c.Body {
			if !matchesMIME(raw, pattern, false) {
				return false
			}
		}
		for _, pattern := range c.Text {
			if !matchesMIME(raw, pattern, true) {
				return false
			}
		}
	}
	for i := range c.Not {
		if matchMessage(m, seq, total, maxUID, raw, &c.Not[i]) {
			return false
		}
	}
	for i := range c.Or {
		if !matchMessage(m, seq, total, maxUID, raw, &c.Or[i][0]) && !matchMessage(m, seq, total, maxUID, raw, &c.Or[i][1]) {
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
