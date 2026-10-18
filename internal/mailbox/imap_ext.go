package mailbox

// The session side of the fork's SORT, THREAD, QUOTA and ID extensions.

import (
	"sort"
	"strings"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/emersion/go-imap/v2"
)

var (
	_ imapserver.SessionSort   = (*imapSession)(nil)
	_ imapserver.SessionThread = (*imapSession)(nil)
	_ imapserver.SessionQuota  = (*imapSession)(nil)
	_ imapserver.SessionID     = (*imapSession)(nil)
)

// matchedKeys runs the search and loads the sort keys of the matches,
// from one query over the folder's summary columns.
func (s *imapSession) matchedKeys(c *imap.SearchCriteria) ([]int, []*SortKeys, error) {
	idx, err := s.match(c)
	if err != nil {
		return nil, nil, err
	}
	byUID, err := s.service.engine.FolderSortKeys(s.ctx, s.folder.ID)
	if err != nil {
		return nil, nil, protocolError(err)
	}
	keys := make([]*SortKeys, len(idx))
	for i, j := range idx {
		m := s.view[j]
		k := byUID[m.UID]
		if k == nil {
			sum, err := s.service.engine.Summary(s.ctx, m)
			if err != nil {
				return nil, nil, protocolError(err)
			}
			k = sum.sortKeys()
		}
		keys[i] = k
	}
	return idx, keys, nil
}

func localPart(addr string) string {
	local, _, _ := strings.Cut(addr, "@")
	return local
}

func (s *imapSession) Sort(kind imapserver.NumKind, sortKeys []imapserver.SortKey, c *imap.SearchCriteria) ([]uint32, error) {
	idx, keys, err := s.matchedKeys(c)
	if err != nil {
		return nil, err
	}
	order := make([]int, len(idx)) // positions into idx and keys
	for i := range order {
		order[i] = i
	}
	compare := func(a, b int, key string) int {
		ma, mb := s.view[idx[a]], s.view[idx[b]]
		sa, sb := keys[a], keys[b]
		str := func(x, y string) int { return strings.Compare(x, y) }
		switch key {
		case "ARRIVAL":
			return ma.Date.Compare(mb.Date)
		case "SIZE":
			switch {
			case ma.Size < mb.Size:
				return -1
			case ma.Size > mb.Size:
				return 1
			}
			return 0
		case "DATE":
			// A message without a usable Date header sorts by arrival.
			da, db := sa.Sent, sb.Sent
			if da.IsZero() {
				da = ma.Date
			}
			if db.IsZero() {
				db = mb.Date
			}
			return da.Compare(db)
		case "SUBJECT":
			return str(sa.BaseSubject, sb.BaseSubject)
		case "FROM":
			return str(localPart(sa.From), localPart(sb.From))
		case "TO":
			return str(localPart(sa.To), localPart(sb.To))
		case "CC":
			return str(localPart(sa.Cc), localPart(sb.Cc))
		case "DISPLAYFROM":
			return str(sa.DisplayFrom, sb.DisplayFrom)
		case "DISPLAYTO":
			return str(sa.DisplayTo, sb.DisplayTo)
		}
		return 0
	}
	// Equal messages keep mailbox order (RFC 5256), which SliceStable over
	// the view-ordered matches gives.
	sort.SliceStable(order, func(i, j int) bool {
		for _, k := range sortKeys {
			if r := compare(order[i], order[j], k.Key); r != 0 {
				if k.Reverse {
					return r > 0
				}
				return r < 0
			}
		}
		return false
	})
	out := make([]uint32, len(order))
	for i, p := range order {
		out[i] = s.number(kind, idx[p])
	}
	return out, nil
}

func (s *imapSession) number(kind imapserver.NumKind, i int) uint32 {
	if kind == imapserver.NumKindUID {
		return s.view[i].UID
	}
	return seqNumber(i + 1)
}

func (s *imapSession) ThreadAlgorithms() []string { return []string{"REFERENCES", "ORDEREDSUBJECT"} }

func (s *imapSession) Thread(kind imapserver.NumKind, algorithm string, c *imap.SearchCriteria) ([]imapserver.Thread, error) {
	idx, keys, err := s.matchedKeys(c)
	if err != nil {
		return nil, err
	}
	items := make([]*threadItem, len(idx))
	for i, j := range idx {
		k := keys[i]
		items[i] = &threadItem{
			num: s.number(kind, j), seq: j, id: k.MessageID, refs: k.References,
			subject: k.BaseSubject, reply: k.Reply, sent: sentOr(k.Sent, s.view[j].Date),
		}
	}
	if algorithm == "ORDEREDSUBJECT" {
		return threadOrderedSubject(items), nil
	}
	return threadReferences(items), nil
}

// The whole account is one quota root, named "", as directory quotas are
// per account.
func (s *imapSession) QuotaRoots(mailbox string) ([]string, error) {
	if _, err := s.service.engine.Folder(s.ctx, s.account.ID, mailbox); err != nil {
		return nil, protocolError(err)
	}
	return []string{""}, nil
}

func (s *imapSession) Quota(root string) ([]imapserver.QuotaResource, error) {
	if root != "" {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such quota root"}
	}
	used, limit, err := s.service.engine.Quota(s.ctx, s.account.ID)
	if err != nil {
		return nil, protocolError(err)
	}
	if limit <= 0 {
		// No limit: RFC 9208 reports no resources rather than a fake one.
		return nil, nil
	}
	return []imapserver.QuotaResource{{Name: "STORAGE", Usage: (used + 1023) / 1024, Limit: limit / 1024}}, nil
}

func (s *imapSession) ID(client map[string]string) map[string]string {
	if len(client) > 0 && s.service.log != nil {
		s.service.log.Debug("mailbox client id", "name", client["name"], "version", client["version"], "os", client["os"])
	}
	return map[string]string{"name": "Elemta", "vendor": "Elemta"}
}
