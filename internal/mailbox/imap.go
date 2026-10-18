package mailbox

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/emersion/go-imap/v2"
)

type imapSession struct {
	service  *Service
	account  Account
	folder   Folder
	view     []Message
	readOnly bool
	ctx      context.Context
	cancel   context.CancelFunc
}

var _ imapserver.SessionIMAP4rev2 = (*imapSession)(nil)

func (s *imapSession) Close() error { s.cancel(); return nil }
func (s *imapSession) Login(user, password string) error {
	if len(user) > 320 {
		return imapserver.ErrAuthFailed
	}
	user = strings.ToLower(strings.TrimSpace(user))
	if !strings.Contains(user, "@") && s.service.cfg.Auth.DefaultDomain != "" {
		user += "@" + s.service.cfg.Auth.DefaultDomain
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	allowed, err := s.service.allowLogin(user)
	if err != nil {
		return protocolError(err)
	}
	if !allowed {
		return imapserver.ErrAuthFailed
	}
	a, err := s.service.auth.Login(ctx, user, password)
	if err != nil {
		if errors.Is(err, ErrCredentials) {
			s.service.failLogin(user)
			return imapserver.ErrAuthFailed
		}
		return protocolError(err)
	}
	if err = s.service.engine.EnsureAccount(ctx, a); err != nil {
		return protocolError(err)
	}
	s.account = a
	return nil
}
func protocolError(err error) error {
	if err == nil {
		return nil
	}
	code := imap.ResponseCodeUnavailable
	text := "Mailbox operation temporarily unavailable"
	switch {
	case errors.Is(err, ErrNotFound):
		code = imap.ResponseCodeNonExistent
		text = "No such mailbox"
	case errors.Is(err, ErrExists):
		code = imap.ResponseCodeAlreadyExists
		text = "Mailbox already exists"
	case errors.Is(err, ErrQuota):
		code = imap.ResponseCodeOverQuota
		text = "Mailbox quota exceeded"
	case errors.Is(err, ErrReadOnly):
		code = imap.ResponseCode("READ-ONLY")
		text = "Mailbox is read-only"
	case errors.Is(err, ErrTooLarge):
		code = imap.ResponseCodeTooBig
		text = "Message exceeds size limit"
	}
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: code, Text: text}
}
func (s *imapSession) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	f, msgs, err := s.service.engine.Snapshot(s.ctx, s.account.ID, name)
	if err != nil {
		return nil, protocolError(err)
	}
	s.folder = f
	s.view = msgs
	s.readOnly = options.ReadOnly
	var unseen uint32
	for i, m := range msgs {
		if !hasFlag(m.Flags, "\\seen") {
			unseen = seqNumber(i + 1)
			break
		}
	}
	return &imap.SelectData{Flags: allFlags(msgs), PermanentFlags: []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, imap.FlagWildcard}, NumMessages: seqNumber(len(msgs)), FirstUnseenSeqNum: unseen, UIDValidity: f.Validity, UIDNext: imap.UID(f.Next)}, nil
}
func allFlags(msgs []Message) []imap.Flag {
	m := map[imap.Flag]bool{imap.FlagSeen: true, imap.FlagAnswered: true, imap.FlagFlagged: true, imap.FlagDeleted: true, imap.FlagDraft: true}
	for _, v := range msgs {
		for _, f := range v.Flags {
			m[imap.Flag(f)] = true
		}
	}
	out := make([]imap.Flag, 0, len(m))
	for f := range m {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}
func (s *imapSession) Unselect() error { s.folder = Folder{}; s.view = nil; return nil }
func (s *imapSession) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Delim: '/'}}}, nil
}
func (s *imapSession) Create(name string, _ *imap.CreateOptions) error {
	return protocolError(s.service.engine.Create(s.ctx, s.account.ID, name))
}
func (s *imapSession) Delete(name string) error {
	return protocolError(s.service.engine.DeleteFolder(s.ctx, s.account.ID, name))
}
func (s *imapSession) Rename(old, newName string, _ *imap.RenameOptions) error {
	return protocolError(s.service.engine.Rename(s.ctx, s.account.ID, old, newName))
}
func (s *imapSession) Subscribe(name string) error {
	return protocolError(s.service.engine.Subscribe(s.ctx, s.account.ID, name, true))
}
func (s *imapSession) Unsubscribe(name string) error {
	return protocolError(s.service.engine.Subscribe(s.ctx, s.account.ID, name, false))
}
func role(name string) imap.MailboxAttr {
	switch strings.ToLower(name) {
	case "drafts":
		return imap.MailboxAttrDrafts
	case "sent":
		return imap.MailboxAttrSent
	case "junk":
		return imap.MailboxAttrJunk
	case "trash":
		return imap.MailboxAttrTrash
	}
	return ""
}
func (s *imapSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}
	folders, err := s.service.engine.Folders(s.ctx, s.account.ID)
	if err != nil {
		return protocolError(err)
	}
	for _, f := range folders {
		match := false
		for _, p := range patterns {
			if imapserver.MatchList(f.Name, '/', ref, p) {
				match = true
				break
			}
		}
		if !match || (options.SelectSubscribed && !f.Subscribed) {
			continue
		}
		attr := role(f.Name)
		if options.SelectSpecialUse && attr == "" {
			continue
		}
		data := &imap.ListData{Mailbox: f.Name, Delim: '/'}
		if attr != "" {
			data.Attrs = append(data.Attrs, attr)
		}
		if f.Subscribed && options.ReturnSubscribed {
			data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
		}
		if options.ReturnStatus != nil {
			data.Status, err = s.Status(f.Name, options.ReturnStatus)
			if err != nil {
				return err
			}
		}
		if err = w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}
func (s *imapSession) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	f, msgs, err := s.service.engine.Snapshot(s.ctx, s.account.ID, name)
	if err != nil {
		return nil, protocolError(err)
	}
	data := &imap.StatusData{Mailbox: f.Name}
	n := seqNumber(len(msgs))
	unseen := uint32(0)
	size := int64(0)
	for _, m := range msgs {
		if !hasFlag(m.Flags, "\\seen") {
			unseen++
		}
		size += m.Size
	}
	if options.NumMessages {
		data.NumMessages = &n
	}
	if options.NumUnseen {
		data.NumUnseen = &unseen
	}
	if options.NumRecent {
		z := uint32(0)
		data.NumRecent = &z
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(f.Next)
	}
	if options.UIDValidity {
		data.UIDValidity = f.Validity
	}
	if options.Size {
		data.Size = &size
	}
	return data, nil
}
func (s *imapSession) AppendLimit() uint32 {
	v := s.service.engine.MaxBytes
	if v < 0 || v > math.MaxUint32 {
		return 0
	}
	return uint32(v)
}
func (s *imapSession) Append(name string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	release, err := s.service.receiveSlot(s.ctx)
	if err != nil {
		return nil, protocolError(err)
	}
	defer release()

	raw, err := readBounded(r, s.service.engine.MaxBytes)
	if err != nil {
		return nil, protocolError(err)
	}
	flags := make([]string, len(options.Flags))
	for i, f := range options.Flags {
		flags[i] = string(f)
	}
	res, err := s.service.engine.Append(s.ctx, s.account.ID, name, raw, flags, options.Time, "")
	if err != nil {
		return nil, protocolError(err)
	}
	return &imap.AppendData{UIDValidity: res.Validity, UID: imap.UID(res.UID)}, nil
}

// selectedIdx returns the view indices a sequence or UID set names, in view
// order. It is linear in the view: FETCH 1:* on a large folder must not be
// quadratic.
func (s *imapSession) selectedIdx(set imap.NumSet) []int {
	n := len(s.view)
	if n == 0 {
		return nil
	}
	mark := make([]bool, n)
	switch v := set.(type) {
	case imap.UIDSet:
		maxUID := s.view[n-1].UID
		for _, r := range v {
			a, b := uint32(r.Start), uint32(r.Stop)
			if a == 0 {
				a = maxUID
			}
			if b == 0 {
				b = maxUID
			}
			if a > b {
				a, b = b, a
			}
			// The view is in UID order, so each range is one contiguous run.
			i := sort.Search(n, func(i int) bool { return s.view[i].UID >= a })
			for ; i < n && s.view[i].UID <= b; i++ {
				mark[i] = true
			}
		}
	case imap.SeqSet:
		for _, r := range v {
			a, b := r.Start, r.Stop
			if a == 0 {
				a = seqNumber(n)
			}
			if b == 0 {
				b = seqNumber(n)
			}
			if a > b {
				a, b = b, a
			}
			for i := int(a) - 1; i < int(b) && i < n; i++ {
				if i >= 0 {
					mark[i] = true
				}
			}
		}
	}
	var out []int
	for i, m := range mark {
		if m {
			out = append(out, i)
		}
	}
	return out
}

func (s *imapSession) selected(set imap.NumSet) []uint32 {
	idx := s.selectedIdx(set)
	out := make([]uint32, len(idx))
	for i, j := range idx {
		out[i] = s.view[j].UID
	}
	return out
}

// headerOnly reports whether a body section can be answered from the
// stored header block.
func headerOnly(section *imap.FetchItemBodySection) bool {
	if len(section.Part) > 0 {
		return false
	}
	switch section.Specifier {
	case imap.PartSpecifierHeader:
		return true
	}
	return false
}

// fetchChunk bounds how many summaries one query loads.
const fetchChunk = 500

func (s *imapSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	release, err := s.service.receiveSlot(s.ctx)
	if err != nil {
		return protocolError(err)
	}
	defer release()
	idx := s.selectedIdx(set)
	seen := false
	for _, section := range options.BodySection {
		if !section.Peek {
			seen = true
		}
	}
	for _, section := range options.BinarySection {
		if !section.Peek {
			seen = true
		}
	}
	if seen && !s.readOnly && len(idx) > 0 {
		uids := make([]uint32, len(idx))
		for i, j := range idx {
			uids[i] = s.view[j].UID
		}
		if err := s.service.engine.MutateFlags(s.ctx, s.account.ID, s.folder.Name, uids, []string{"\\seen"}, 1); err != nil {
			return protocolError(err)
		}
		if err := s.refreshFlags(); err != nil {
			return err
		}
	}
	bodyNeeded := len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0
	summaryNeeded := options.Envelope || options.BodyStructure != nil
	for _, section := range options.BodySection {
		if headerOnly(section) {
			summaryNeeded = true
		} else {
			bodyNeeded = true
		}
	}
	for start := 0; start < len(idx); start += fetchChunk {
		chunk := idx[start:min(start+fetchChunk, len(idx))]
		var summaries map[string]*Summary
		if summaryNeeded {
			msgs := make([]Message, len(chunk))
			for i, j := range chunk {
				msgs[i] = s.view[j]
			}
			if summaries, err = s.service.engine.Summaries(s.ctx, msgs); err != nil {
				return protocolError(err)
			}
		}
		for _, i := range chunk {
			if err := s.fetchOne(w, i, options, seen, bodyNeeded, summaries); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *imapSession) fetchOne(w *imapserver.FetchWriter, i int, options *imap.FetchOptions, seen, bodyNeeded bool, summaries map[string]*Summary) error {
	m := s.view[i]
	var raw []byte
	var err error
	sum := summaries[m.Body]
	if summaries != nil && sum == nil {
		// Mail stored before summaries existed: compute it now, once.
		if sum, err = s.service.engine.Summary(s.ctx, m); err != nil {
			return protocolError(err)
		}
	}
	if bodyNeeded || (sum != nil && sum.Header == nil && len(options.BodySection) > 0) {
		if raw, err = s.service.engine.Read(s.ctx, m); err != nil {
			return protocolError(err)
		}
	}
	response := w.CreateMessage(seqNumber(i + 1))
	response.WriteUID(imap.UID(m.UID))
	if options.Flags || seen {
		response.WriteFlags(imapFlags(m.Flags))
	}
	if options.InternalDate {
		response.WriteInternalDate(m.Date)
	}
	if options.RFC822Size {
		response.WriteRFC822Size(m.Size)
	}
	if options.Envelope {
		response.WriteEnvelope(sum.Envelope)
	}
	if options.BodyStructure != nil {
		response.WriteBodyStructure(sum.Structure)
	}
	for _, section := range options.BodySection {
		var data []byte
		if headerOnly(section) && raw == nil {
			data = imapserver.ExtractBodySection(bytes.NewReader(sum.Header), section)
		} else {
			data = bodySection(raw, section)
		}
		writer := response.WriteBodySection(section, int64(len(data)))
		if _, err := writer.Write(data); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
	}
	for _, section := range options.BinarySection {
		data := imapserver.ExtractBinarySection(bytes.NewReader(raw), section)
		writer := response.WriteBinarySection(section, int64(len(data)))
		if _, err := writer.Write(data); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
	}
	for _, section := range options.BinarySectionSize {
		response.WriteBinarySectionSize(section, imapserver.ExtractBinarySectionSize(bytes.NewReader(raw), section))
	}
	return response.Close()
}
func imapFlags(flags []string) []imap.Flag {
	out := make([]imap.Flag, len(flags))
	for i, f := range flags {
		out[i] = imap.Flag(f)
	}
	return out
}

// viewIndex finds a UID in the view, which is in UID order.
func (s *imapSession) viewIndex(uid uint32) (int, bool) {
	i := sort.Search(len(s.view), func(i int) bool { return s.view[i].UID >= uid })
	return i, i < len(s.view) && s.view[i].UID == uid
}

// refreshFlags updates the view's flags after this session changed them.
// It doesn't advance the folder's MODSEQ, so the next poll still reports
// what other sessions did meanwhile.
func (s *imapSession) refreshFlags() error {
	ch, err := s.service.engine.Changes(s.ctx, s.account.ID, s.folder.ID, s.folder.ModSeq)
	if err != nil {
		return protocolError(err)
	}
	if !ch.Complete {
		return s.refreshFlagsFull()
	}
	for _, m := range ch.Changed {
		if i, ok := s.viewIndex(m.UID); ok {
			s.view[i] = m
		}
	}
	return nil
}

func (s *imapSession) refreshFlagsFull() error {
	_, msgs, err := s.service.engine.Snapshot(s.ctx, s.account.ID, s.folder.Name)
	if err != nil {
		return protocolError(err)
	}
	byUID := map[uint32]Message{}
	for _, m := range msgs {
		byUID[m.UID] = m
	}
	for i, m := range s.view {
		if next, ok := byUID[m.UID]; ok {
			s.view[i] = next
		}
	}
	return nil
}
func (s *imapSession) Store(w *imapserver.FetchWriter, set imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	if s.readOnly {
		return protocolError(ErrReadOnly)
	}
	uids := s.selected(set)
	values := make([]string, len(flags.Flags))
	for i, f := range flags.Flags {
		values[i] = string(f)
	}
	if err := s.service.engine.MutateFlags(s.ctx, s.account.ID, s.folder.Name, uids, values, int(flags.Op)); err != nil {
		return protocolError(err)
	}
	if err := s.refreshFlags(); err != nil {
		return err
	}
	if !flags.Silent {
		want := make(map[uint32]bool, len(uids))
		for _, u := range uids {
			want[u] = true
		}
		for i, m := range s.view {
			if want[m.UID] {
				r := w.CreateMessage(seqNumber(i + 1))
				r.WriteUID(imap.UID(m.UID))
				r.WriteFlags(imapFlags(m.Flags))
				if err := r.Close(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (s *imapSession) Expunge(w *imapserver.ExpungeWriter, set *imap.UIDSet) error {
	if s.readOnly {
		return protocolError(ErrReadOnly)
	}
	var all imap.UIDSet
	all.AddRange(1, 0)
	if set == nil {
		set = &all
	}
	uids := s.selected(*set)
	removed, err := s.service.engine.Expunge(s.ctx, s.account.ID, s.folder.Name, uids)
	if err != nil {
		return protocolError(err)
	}
	gone := make(map[uint32]bool, len(removed))
	for _, u := range removed {
		gone[u] = true
	}
	// Highest first, so each reported number is still valid when the
	// client applies the ones before it.
	for i := len(s.view) - 1; i >= 0; i-- {
		if gone[s.view[i].UID] {
			if err := w.WriteExpunge(seqNumber(i + 1)); err != nil {
				return err
			}
		}
	}
	kept := s.view[:0]
	for _, m := range s.view {
		if !gone[m.UID] {
			kept = append(kept, m)
		}
	}
	s.view = kept
	return nil
}
func (s *imapSession) Copy(set imap.NumSet, dest string) (*imap.CopyData, error) {
	v, from, to, err := s.service.engine.CopyMove(s.ctx, s.account.ID, s.folder.Name, dest, s.selected(set), false)
	if err != nil {
		return nil, protocolError(err)
	}
	return copyData(v, from, to), nil
}
func copyData(v uint32, from, to []uint32) *imap.CopyData {
	var f, t imap.UIDSet
	for _, id := range from {
		f.AddNum(imap.UID(id))
	}
	for _, id := range to {
		t.AddNum(imap.UID(id))
	}
	return &imap.CopyData{UIDValidity: v, SourceUIDs: f, DestUIDs: t}
}
func (s *imapSession) Move(w *imapserver.MoveWriter, set imap.NumSet, dest string) error {
	if s.readOnly {
		return protocolError(ErrReadOnly)
	}
	v, from, to, err := s.service.engine.CopyMove(s.ctx, s.account.ID, s.folder.Name, dest, s.selected(set), true)
	if err != nil {
		return protocolError(err)
	}
	if err = w.WriteCopyData(copyData(v, from, to)); err != nil {
		return err
	}
	for i := len(s.view) - 1; i >= 0; i-- {
		if slices.Contains(from, s.view[i].UID) {
			if err = w.WriteExpunge(seqNumber(i + 1)); err != nil {
				return err
			}
			s.view = append(s.view[:i], s.view[i+1:]...)
		}
	}
	return nil
}
func (s *imapSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.folder.ID == 0 {
		return nil
	}
	ch, err := s.service.engine.Changes(s.ctx, s.account.ID, s.folder.ID, s.folder.ModSeq)
	if err != nil {
		return protocolError(err)
	}
	s.folder.Name = ch.Folder.Name
	if !ch.Complete {
		return s.pollFull(w, allowExpunge)
	}
	if ch.Folder.ModSeq == s.folder.ModSeq {
		return nil
	}
	pending := false
	count := len(s.view)
	if len(ch.Gone) > 0 {
		gone := make(map[uint32]bool, len(ch.Gone))
		for _, u := range ch.Gone {
			if _, ok := s.viewIndex(u); ok {
				gone[u] = true
			}
		}
		if len(gone) > 0 && !allowExpunge {
			pending = true
		} else if len(gone) > 0 {
			for i := len(s.view) - 1; i >= 0; i-- {
				if gone[s.view[i].UID] {
					if err := w.WriteExpunge(seqNumber(i + 1)); err != nil {
						return err
					}
				}
			}
			kept := s.view[:0]
			for _, m := range s.view {
				if !gone[m.UID] {
					kept = append(kept, m)
				}
			}
			s.view = kept
		}
	}
	var added []Message
	for _, m := range ch.Changed {
		i, ok := s.viewIndex(m.UID)
		if !ok {
			added = append(added, m)
			continue
		}
		if !slices.Equal(m.Flags, s.view[i].Flags) {
			if err := w.WriteMessageFlags(seqNumber(i+1), imap.UID(m.UID), imapFlags(m.Flags)); err != nil {
				return err
			}
		}
		s.view[i] = m
	}
	if len(added) > 0 {
		// UIDs only grow, so new mail goes after everything in the view.
		sort.Slice(added, func(i, j int) bool { return added[i].UID < added[j].UID })
		s.view = append(s.view, added...)
	}
	if len(s.view) != count || len(added) > 0 {
		if err := w.WriteNumMessages(seqNumber(len(s.view))); err != nil {
			return err
		}
	}
	if !pending {
		s.folder = ch.Folder
	}
	return nil
}

// pollFull reconciles the view with a full snapshot, for sessions the
// change journal can no longer answer.
func (s *imapSession) pollFull(w *imapserver.UpdateWriter, allowExpunge bool) error {
	f, msgs, err := s.service.engine.Snapshot(s.ctx, s.account.ID, s.folder.Name)
	if err != nil {
		return protocolError(err)
	}
	next := map[uint32]Message{}
	for _, m := range msgs {
		next[m.UID] = m
	}
	pending := false
	gone := map[uint32]bool{}
	for i := len(s.view) - 1; i >= 0; i-- {
		old := s.view[i]
		m, ok := next[old.UID]
		if !ok {
			if allowExpunge {
				if err := w.WriteExpunge(seqNumber(i + 1)); err != nil {
					return err
				}
				gone[old.UID] = true
			} else {
				pending = true
			}
			continue
		}
		if !slices.Equal(m.Flags, old.Flags) {
			if err := w.WriteMessageFlags(seqNumber(i+1), imap.UID(m.UID), imapFlags(m.Flags)); err != nil {
				return err
			}
		}
		s.view[i] = m
		delete(next, m.UID)
	}
	kept := s.view[:0]
	for _, m := range s.view {
		if !gone[m.UID] {
			kept = append(kept, m)
		}
	}
	s.view = kept
	for _, m := range msgs {
		if _, ok := next[m.UID]; ok {
			s.view = append(s.view, m)
		}
	}
	if err := w.WriteNumMessages(seqNumber(len(s.view))); err != nil {
		return err
	}
	if !pending {
		s.folder = f
	}
	return nil
}
func (s *imapSession) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-s.ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.Poll(w, true); err != nil {
				return err
			}
		}
	}
}

// match returns the view indices of the messages matching c, in view
// order. Summaries are loaded in chunks only when header criteria need
// them; bodies are read only for BODY and TEXT.
func (s *imapSession) match(c *imap.SearchCriteria) ([]int, error) {
	hits, err := s.service.engine.searchIndex(s.ctx, s.folder.ID, c)
	if err != nil {
		return nil, protocolError(err)
	}
	needHeader, needText := searchNeeds(c, hits)
	if needText {
		release, err := s.service.receiveSlot(s.ctx)
		if err != nil {
			return nil, protocolError(err)
		}
		defer release()
	}
	var out []int
	maxUID := uint32(0)
	if len(s.view) > 0 {
		maxUID = s.view[len(s.view)-1].UID
	}
	total := seqNumber(len(s.view))
	for start := 0; start < len(s.view); start += fetchChunk {
		end := min(start+fetchChunk, len(s.view))
		var summaries map[string]*Summary
		if needHeader {
			var err error
			if summaries, err = s.service.engine.Summaries(s.ctx, s.view[start:end]); err != nil {
				return nil, protocolError(err)
			}
		}
		for i := start; i < end; i++ {
			m := s.view[i]
			src := &searchSource{
				summary:     summaries[m.Body],
				loadSummary: func() (*Summary, error) { return s.service.engine.Summary(s.ctx, m) },
				load:        func() ([]byte, error) { return s.service.engine.Read(s.ctx, m) },
				hits:        hits,
			}
			if matchMessage(m, seqNumber(i+1), total, maxUID, src, c) {
				out = append(out, i)
			}
			if src.err != nil {
				return nil, protocolError(src.err)
			}
		}
	}
	return out, nil
}

func (s *imapSession) Search(kind imapserver.NumKind, c *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	idx, err := s.match(c)
	if err != nil {
		return nil, err
	}
	nums := make([]uint32, len(idx))
	for i, j := range idx {
		nums[i] = seqNumber(j + 1)
		if kind == imapserver.NumKindUID {
			nums[i] = s.view[j].UID
		}
	}
	data := &imap.SearchData{Count: seqNumber(len(nums))}
	if len(nums) > 0 {
		data.Min = nums[0]
		data.Max = nums[len(nums)-1]
	}
	if kind == imapserver.NumKindUID {
		set := imap.UIDSet{}
		for _, n := range nums {
			set.AddNum(imap.UID(n))
		}
		data.All = set
	} else {
		set := imap.SeqSet{}
		for _, n := range nums {
			set.AddNum(n)
		}
		data.All = set
	}
	return data, nil
}

func seqNumber(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("mailbox sequence number overflow")
	}
	return uint32(n)
}
