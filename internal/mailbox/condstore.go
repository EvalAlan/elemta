package mailbox

// The session side of CONDSTORE and QRESYNC (RFC 7162). Every message
// already carries the MODSEQ of its last change and the folder the highest
// one; these report them, and the change journal says what vanished.

import (
	"sort"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/emersion/go-imap/v2"
)

var _ imapserver.SessionQResync = (*imapSession)(nil)

func (s *imapSession) CondStore() {}

// vanishedSince returns the UIDs in want (all UIDs when want is empty) that
// were expunged after MODSEQ since. Without journal coverage it falls back
// to every UID in want below UIDNEXT that no longer exists, which RFC 7162
// allows.
func (s *imapSession) vanishedSince(want imap.UIDSet, since uint64) (imap.UIDSet, error) {
	var out imap.UIDSet
	gone, complete, err := s.service.engine.ExpungedSince(s.ctx, s.folder.ID, since)
	if err != nil {
		return nil, protocolError(err)
	}
	if complete {
		for _, u := range gone {
			if len(want) == 0 || want.Contains(imap.UID(u)) {
				out.AddNum(imap.UID(u))
			}
		}
		return out, nil
	}
	top := s.folder.Next - 1
	if top == 0 {
		return out, nil
	}
	ranges := want
	if len(ranges) == 0 {
		ranges = imap.UIDSet{{Start: 1, Stop: imap.UID(top)}}
	}
	for _, r := range ranges {
		a, b := uint32(r.Start), uint32(r.Stop)
		if a == 0 {
			a = top
		}
		if b == 0 || b > top {
			b = top
		}
		if a > b {
			continue
		}
		// Gaps between the UIDs still present in [a, b].
		i := sort.Search(len(s.uids), func(i int) bool { return s.uids[i] >= a })
		next := a
		for ; i < len(s.uids) && s.uids[i] <= b; i++ {
			if s.uids[i] > next {
				out.AddRange(imap.UID(next), imap.UID(s.uids[i]-1))
			}
			next = s.uids[i] + 1
		}
		if next <= b {
			out.AddRange(imap.UID(next), imap.UID(b))
		}
	}
	return out, nil
}

// writeVanishedSince answers UID FETCH ... (CHANGEDSINCE n VANISHED).
func (s *imapSession) writeVanishedSince(w *imapserver.FetchWriter, set imap.NumSet, since uint64) error {
	want, _ := set.(imap.UIDSet)
	gone, err := s.vanishedSince(want, since)
	if err != nil {
		return err
	}
	return w.WriteVanished(gone)
}

// QResync reports what changed since the client's last state, right after
// SELECT (RFC 7162 3.2.5).
func (s *imapSession) QResync(w *imapserver.FetchWriter, p *imapserver.QResyncParams) error {
	if p.UIDValidity != s.folder.Validity {
		return nil // the client must resynchronise from scratch
	}
	gone, err := s.vanishedSince(p.KnownUIDs, p.ModSeq)
	if err != nil {
		return err
	}
	if err := w.WriteVanished(gone); err != nil {
		return err
	}
	changed, err := s.service.engine.ChangedSince(s.ctx, s.folder.ID, p.ModSeq)
	if err != nil {
		return protocolError(err)
	}
	for _, m := range changed {
		i, ok := s.viewIndex(m.UID)
		if !ok {
			continue
		}
		r := w.CreateMessage(seqNumber(i + 1))
		r.WriteUID(imap.UID(m.UID))
		r.WriteFlags(imapFlags(m.Flags))
		r.WriteModSeq(m.ModSeq)
		if err := r.Close(); err != nil {
			return err
		}
	}
	return nil
}
