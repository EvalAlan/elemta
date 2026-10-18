package mailbox

// SORT and THREAD (RFC 5256) over the messages a search matched, using the
// sort and thread keys stored in message summaries.

import (
	"sort"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
)

// threadItem is one matched message as the algorithms see it.
type threadItem struct {
	num     uint32 // the number to report: sequence number or UID
	seq     int    // view position, the final tie breaker
	id      string // Message-ID, empty when missing
	refs    []string
	subject string // base subject
	reply   bool   // the subject had a reply or forward marker
	sent    time.Time
}

// sentOr is a message's thread date: its Date header, or its arrival when
// that is missing or unreadable.
func sentOr(sent, arrival time.Time) time.Time {
	if !sent.IsZero() {
		return sent
	}
	return arrival
}

// container is a node of the REFERENCES algorithm (RFC 5256 section 5).
type container struct {
	item     *threadItem // nil for a referenced but missing message
	parent   *container
	children []*container
}

func (c *container) isAncestorOf(other *container) bool {
	for p := other; p != nil; p = p.parent {
		if p == c {
			return true
		}
	}
	return false
}

func (c *container) setParent(p *container) {
	if c.parent != nil {
		siblings := c.parent.children
		for i, s := range siblings {
			if s == c {
				c.parent.children = append(siblings[:i], siblings[i+1:]...)
				break
			}
		}
	}
	c.parent = p
	if p != nil {
		p.children = append(p.children, c)
	}
}

// date is the container's sort date: its message's, or for a missing
// message its first child's.
func (c *container) date() time.Time {
	if c.item != nil {
		return c.item.sent
	}
	if len(c.children) > 0 {
		return c.children[0].date()
	}
	return time.Time{}
}

func (c *container) seq() int {
	if c.item != nil {
		return c.item.seq
	}
	if len(c.children) > 0 {
		return c.children[0].seq()
	}
	return 0
}

func sortContainers(list []*container) {
	sort.SliceStable(list, func(i, j int) bool {
		di, dj := list[i].date(), list[j].date()
		if !di.Equal(dj) {
			return di.Before(dj)
		}
		return list[i].seq() < list[j].seq()
	})
}

// threadReferences implements THREAD=REFERENCES.
func threadReferences(items []*threadItem) []imapserver.Thread {
	byID := map[string]*container{}
	var all []*container
	get := func(id string) *container {
		if c := byID[id]; c != nil {
			return c
		}
		c := &container{}
		byID[id] = c
		all = append(all, c)
		return c
	}
	// Step 1: link messages through their references.
	for _, it := range items {
		var c *container
		if it.id != "" && byID[it.id] != nil && byID[it.id].item == nil {
			c = byID[it.id]
		} else {
			// A missing or duplicate Message-ID gets a container of its own.
			c = &container{}
			if it.id != "" && byID[it.id] == nil {
				byID[it.id] = c
			}
			all = append(all, c)
		}
		c.item = it
		var prev *container
		for _, ref := range it.refs {
			r := get(ref)
			if prev != nil && r.parent == nil && !r.isAncestorOf(prev) && r != prev {
				r.setParent(prev)
			}
			prev = r
		}
		// The message's parent is the last reference, when that makes no loop.
		if prev != nil && (prev == c || c.isAncestorOf(prev)) {
			prev = nil
		}
		if c.parent != prev {
			c.setParent(prev)
		}
	}
	// Step 2: the root set.
	var roots []*container
	for _, c := range all {
		if c.parent == nil {
			roots = append(roots, c)
		}
	}
	// Step 3: discard missing-message containers without children, and
	// promote the children of others.
	var prune func(list []*container, atRoot bool) []*container
	prune = func(list []*container, atRoot bool) []*container {
		var out []*container
		for _, c := range list {
			c.children = prune(c.children, false)
			for _, k := range c.children {
				k.parent = c
			}
			if c.item == nil {
				switch {
				case len(c.children) == 0:
					continue
				case !atRoot || len(c.children) == 1:
					for _, k := range c.children {
						k.parent = c.parent
					}
					out = append(out, c.children...)
					continue
				}
			}
			out = append(out, c)
		}
		return out
	}
	roots = prune(roots, true)
	for _, r := range roots {
		r.parent = nil
	}
	// Step 4: order the roots by date.
	sortContainers(roots)
	// Step 5: gather roots with the same base subject.
	subjectOf := func(c *container) (string, bool) {
		if c.item != nil {
			return c.item.subject, c.item.reply
		}
		if len(c.children) > 0 && c.children[0].item != nil {
			return c.children[0].item.subject, c.children[0].item.reply
		}
		return "", false
	}
	table := map[string]*container{}
	for _, r := range roots {
		subj, reply := subjectOf(r)
		if subj == "" {
			continue
		}
		old := table[subj]
		if old == nil || (r.item == nil && old.item != nil) || (old.item != nil && old.item.reply && r.item != nil && !reply) {
			table[subj] = r
		}
	}
	var merged []*container
	for _, r := range roots {
		subj, reply := subjectOf(r)
		target := table[subj]
		if subj == "" || target == nil || target == r {
			merged = append(merged, r)
			continue
		}
		targetReply := target.item != nil && target.item.reply
		switch {
		case target.item == nil && r.item == nil:
			for _, k := range append([]*container(nil), r.children...) {
				k.setParent(target)
			}
		case target.item == nil:
			r.setParent(target)
		case targetReply && !reply:
			// Shouldn't happen given the table rules, but keep both.
			merged = append(merged, r)
		case !targetReply && reply:
			r.setParent(target)
		default:
			// Both or neither are replies: make a new missing-message parent.
			parent := &container{}
			idx := -1
			for i, m := range merged {
				if m == target {
					idx = i
				}
			}
			target.setParent(parent)
			r.setParent(parent)
			table[subj] = parent
			if idx >= 0 {
				merged[idx] = parent
			} else {
				merged = append(merged, parent)
			}
		}
	}
	// Step 6: order every level by date.
	var order func(list []*container)
	order = func(list []*container) {
		sortContainers(list)
		for _, c := range list {
			order(c.children)
		}
	}
	order(merged)
	return toThreads(merged)
}

func toThreads(list []*container) []imapserver.Thread {
	out := make([]imapserver.Thread, 0, len(list))
	for _, c := range list {
		t := imapserver.Thread{Children: toThreads(c.children)}
		if c.item != nil {
			t.Num = c.item.num
		}
		out = append(out, t)
	}
	return out
}

// threadOrderedSubject implements THREAD=ORDEREDSUBJECT: messages grouped
// by base subject, each group a flat thread under its first message.
func threadOrderedSubject(items []*threadItem) []imapserver.Thread {
	sorted := append([]*threadItem(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.subject != b.subject {
			return a.subject < b.subject
		}
		if !a.sent.Equal(b.sent) {
			return a.sent.Before(b.sent)
		}
		return a.seq < b.seq
	})
	type group struct {
		first *threadItem
		rest  []*threadItem
	}
	var groups []*group
	for _, it := range sorted {
		if n := len(groups); n > 0 && groups[n-1].first.subject == it.subject {
			groups[n-1].rest = append(groups[n-1].rest, it)
			continue
		}
		groups = append(groups, &group{first: it})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i].first, groups[j].first
		if !a.sent.Equal(b.sent) {
			return a.sent.Before(b.sent)
		}
		return a.seq < b.seq
	})
	out := make([]imapserver.Thread, 0, len(groups))
	for _, g := range groups {
		t := imapserver.Thread{Num: g.first.num}
		for _, it := range g.rest {
			t.Children = append(t.Children, imapserver.Thread{Num: it.num})
		}
		out = append(out, t)
	}
	return out
}

// hasReplyMarker reports whether a subject had leading reply or forward
// markers or a trailing "(fwd)", which RFC 5256 calls a reply or forward.
func hasReplyMarker(subject string) bool {
	s := strings.Join(strings.Fields(subject), " ")
	if strings.HasSuffix(strings.ToLower(s), "(fwd)") {
		return true
	}
	for {
		t, ok := stripLeader(s)
		if !ok {
			return false
		}
		l := strings.ToLower(s)
		if strings.HasPrefix(l, "re") || strings.HasPrefix(l, "fw") {
			return true
		}
		s = t
	}
}
