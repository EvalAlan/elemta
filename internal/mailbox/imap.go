package mailbox

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
)

type imapSession struct {
	service *Service
	account Account
	folder  Folder
	// uids is the selected folder's view: the UID at each sequence number.
	// Everything else about a message is loaded when a command needs it.
	uids []uint32
	// reported is the MODSEQ up to which flag changes have been sent.
	reported uint64
	readOnly bool
	// public is a listener mail apps connect to, where a user's app-password
	// requirement applies.
	public   bool
	conn     net.Conn
	user     string
	password string
	recheck  <-chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

var _ imapserver.SessionIMAP4rev2 = (*imapSession)(nil)

func (s *imapSession) Close() error { s.cancel(); return nil }
func (s *imapSession) Login(user, password string) error {
	a, err := s.service.login(s.ctx, user, password, s.public, s.protocol())
	if errors.Is(err, ErrCredentials) {
		return imapserver.ErrAuthFailed
	}
	if errors.Is(err, ErrProtocolDisabled) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm, Text: "IMAP access is turned off for this account"}
	}
	if err != nil {
		return protocolError(err)
	}
	s.account = a
	s.user, s.password = user, password
	go s.watchCredentials()
	return nil
}

// protocol is what the class of service's switches call this session: IMAP
// on the public listeners; nothing on the internal one, which serves the
// webmail and applies the webmail and DAV switches itself.
func (s *imapSession) protocol() string {
	if s.public {
		return mailpolicy.IMAP
	}
	return ""
}

// Revalidate established connections against shared credential and directory
// state, so a reset or app-password deletion reaches idle clients on every
// replica without waiting for them to reconnect.
func (s *imapSession) watchCredentials() {
	ticks := s.recheck
	if ticks == nil {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticks:
			a, err := s.service.login(s.ctx, s.user, s.password, s.public, s.protocol())
			if err != nil || a.ID != s.account.ID {
				_ = s.conn.Close()
				return
			}
		}
	}
}

// ErrProtocolDisabled refuses a sign-in the account's class of service
// doesn't allow. It is not a credential failure: the password was right, so
// it doesn't count towards the failure limit.
var ErrProtocolDisabled = errors.New("this account may not use this protocol")

// login checks a user's credentials for a mail protocol. protocol names it
// for the class of service's protocol switches (mailpolicy.IMAP, POP3), or
// is empty for the internal listener the webmail uses, which applies its
// own switches. On a public listener, an account that requires app
// passwords, or whose class does, refuses its account password
// (security.go).
func (s *Service) login(ctx context.Context, user, password string, public bool, protocol string) (Account, error) {
	if strings.Contains(user, "|") {
		// An administrator access token opens the one mailbox it names,
		// not the shared mailboxes its owner may open.
		if strings.HasPrefix(password, adminTokenPrefix) {
			return Account{}, ErrCredentials
		}
		actorName, mailboxName, ok := strings.Cut(user, "|")
		actorName, mailboxName = strings.ToLower(strings.TrimSpace(actorName)), strings.ToLower(strings.TrimSpace(mailboxName))
		if !ok || actorName == "" || mailboxName == "" || strings.Contains(mailboxName, "|") || !strings.Contains(mailboxName, "@") || protocol == mailpolicy.POP3 {
			return Account{}, ErrCredentials
		}
		actor, err := s.login(ctx, actorName, password, public, protocol)
		if err != nil {
			return Account{}, err
		}
		mailbox, err := s.auth.Resolve(ctx, mailboxName)
		if err != nil {
			return Account{}, err
		}
		// Resolve is the delivery lookup, which returns suspended
		// accounts; a suspended shared mailbox can't be opened.
		if mailbox.Suspended {
			return Account{}, ErrCredentials
		}
		if mailbox.Address != mailboxName {
			return Account{}, ErrCredentials
		}
		allowed, err := s.engine.HasShare(ctx, mailbox.ID, actor.ID, false)
		if err != nil {
			return Account{}, err
		}
		if !allowed {
			s.failLogin(actor.Address)
			return Account{}, ErrCredentials
		}
		if err := s.applyPolicy(ctx, &mailbox); err != nil {
			return Account{}, err
		}
		if protocol != "" && mailbox.Policy != nil && !mailbox.Policy.Allows(protocol) {
			return Account{}, ErrProtocolDisabled
		}
		if protocol == "" && mailbox.Policy != nil && !mailbox.Policy.Allows(mailpolicy.Webmail) {
			return Account{}, ErrProtocolDisabled
		}
		if err := s.engine.EnsureAccount(ctx, mailbox); err != nil {
			return Account{}, err
		}
		return mailbox, nil
	}
	// An administrator access token, on the webmail's internal listener only
	// (admin_access.go). Elsewhere it is just a wrong password.
	if strings.HasPrefix(password, adminTokenPrefix) {
		if public || protocol != "" {
			return Account{}, ErrCredentials
		}
		a, _, _, err := s.adminLogin(ctx, user, password)
		return a, err
	}
	a, app, err := s.authenticate(ctx, user, password)
	if err != nil {
		return a, err
	}
	if protocol != "" && a.Policy != nil && !a.Policy.Allows(protocol) {
		s.log.Info("mailbox: sign-in refused by class of service", "user", a.Address, "protocol", protocol)
		return Account{}, ErrProtocolDisabled
	}
	if app || !public {
		return a, nil
	}
	required, err := s.engine.AppPasswordsRequired(ctx, a.ID)
	if err != nil {
		return Account{}, err
	}
	if required || a.Policy != nil && a.Policy.RequireAppPasswords {
		s.failLogin(a.Address)
		s.log.Info("mailbox: account password refused; app password required", "user", a.Address)
		return Account{}, ErrCredentials
	}
	return a, nil
}

// authenticate checks an app password or the account password, with the
// shared failure limit, and reports which one it was.
func (s *Service) authenticate(ctx context.Context, user, password string) (Account, bool, error) {
	if len(user) > 320 {
		return Account{}, false, ErrCredentials
	}
	user = strings.ToLower(strings.TrimSpace(user))
	if !strings.Contains(user, "@") && s.cfg.Auth.DefaultDomain != "" {
		user += "@" + s.cfg.Auth.DefaultDomain
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	allowed, err := s.allowLogin(user)
	if err != nil {
		return Account{}, false, err
	}
	if !allowed {
		return Account{}, false, ErrCredentials
	}
	// An app password is one indexed lookup, and trying it first keeps a
	// mail app that uses one from counting LDAP failures against the user.
	id, app, err := s.engine.appPasswordAccount(ctx, user, password)
	if err != nil {
		return Account{}, false, err
	}
	if app {
		// The directory still decides whether the account exists and may
		// sign in; an app password doesn't outlive its account.
		a, err := s.auth.Resolve(ctx, user)
		if err == nil && (a.ID != id || a.Suspended) {
			// Resolve is the delivery lookup, so it returns a suspended
			// account; a suspended account may not sign in with an app
			// password either.
			err = ErrCredentials
		}
		if err != nil {
			if errors.Is(err, ErrCredentials) {
				s.failLogin(user)
			}
			return Account{}, false, err
		}
		if err := s.applyPolicy(ctx, &a); err != nil {
			return Account{}, false, err
		}
		if err := s.engine.EnsureAccount(ctx, a); err != nil {
			return Account{}, false, err
		}
		return a, true, nil
	}
	a, err := s.auth.Login(ctx, user, password)
	if err != nil {
		if errors.Is(err, ErrCredentials) {
			s.failLogin(user)
		}
		return Account{}, false, err
	}
	if err = s.applyPolicy(ctx, &a); err != nil {
		return Account{}, false, err
	}
	if err = s.engine.EnsureAccount(ctx, a); err != nil {
		return Account{}, false, err
	}
	return a, false, nil
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
	info, err := s.service.engine.SelectFolder(s.ctx, s.account.ID, name)
	if err != nil {
		return nil, protocolError(err)
	}
	s.folder = info.Folder
	s.uids = info.UIDs
	s.reported = info.Folder.ModSeq
	s.readOnly = options.ReadOnly
	var unseen uint32
	if info.FirstUnseen != 0 {
		if i, ok := s.viewIndex(info.FirstUnseen); ok {
			unseen = seqNumber(i + 1)
		}
	}
	return &imap.SelectData{Flags: allFlags(info.Keywords), PermanentFlags: []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, imap.FlagWildcard}, NumMessages: seqNumber(len(s.uids)), FirstUnseenSeqNum: unseen, UIDValidity: info.Folder.Validity, UIDNext: imap.UID(info.Folder.Next), HighestModSeq: info.Folder.ModSeq}, nil
}
func allFlags(keywords []string) []imap.Flag {
	m := map[imap.Flag]bool{imap.FlagSeen: true, imap.FlagAnswered: true, imap.FlagFlagged: true, imap.FlagDeleted: true, imap.FlagDraft: true}
	for _, k := range keywords {
		m[imap.Flag(k)] = true
	}
	out := make([]imap.Flag, 0, len(m))
	for f := range m {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}
func (s *imapSession) Unselect() error { s.folder = Folder{}; s.uids = nil; return nil }
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
	f, n, unseen, size, err := s.service.engine.FolderStatus(s.ctx, s.account.ID, name)
	if err != nil {
		return nil, protocolError(err)
	}
	data := &imap.StatusData{Mailbox: f.Name}
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
	if options.HighestModSeq {
		data.HighestModSeq = f.ModSeq
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
	n := len(s.uids)
	if n == 0 {
		return nil
	}
	mark := make([]bool, n)
	switch v := set.(type) {
	case imap.UIDSet:
		maxUID := s.uids[n-1]
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
			i := sort.Search(n, func(i int) bool { return s.uids[i] >= a })
			for ; i < n && s.uids[i] <= b; i++ {
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
		out[i] = s.uids[j]
	}
	return out
}

// rows loads the current rows of the messages at these view indices.
func (s *imapSession) rows(idx []int) (map[uint32]Message, error) {
	uids := make([]uint32, len(idx))
	for i, j := range idx {
		uids[i] = s.uids[j]
	}
	return s.service.engine.MessagesByUID(s.ctx, s.folder.ID, uids)
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
			uids[i] = s.uids[j]
		}
		if err := s.service.engine.MutateFlags(s.ctx, s.account.ID, s.folder.Name, uids, []string{"\\seen"}, 1); err != nil {
			return protocolError(err)
		}
	}
	if w.Vanished() {
		if err := s.writeVanishedSince(w, set, options.ChangedSince); err != nil {
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
	// A fetch over much of a large folder (a client's "UID FETCH 1:*
	// (FLAGS)" resync) reads the folder's rows in one query; smaller ones
	// read each batch's.
	var folderRows map[uint32]Message
	if len(idx) > 4*fetchChunk {
		msgs, err := scanMessages(s.ctx, s.service.engine.DB, s.folder.ID)
		if err != nil {
			return protocolError(err)
		}
		folderRows = make(map[uint32]Message, len(msgs))
		for _, m := range msgs {
			folderRows[m.UID] = m
		}
	}
	for start := 0; start < len(idx); start += fetchChunk {
		chunk := idx[start:min(start+fetchChunk, len(idx))]
		rows := folderRows
		if rows == nil {
			if rows, err = s.rows(chunk); err != nil {
				return protocolError(err)
			}
		}
		var summaries map[string]*Summary
		if summaryNeeded {
			msgs := make([]Message, 0, len(chunk))
			for _, i := range chunk {
				if m, ok := rows[s.uids[i]]; ok {
					msgs = append(msgs, m)
				}
			}
			if summaries, err = s.service.engine.Summaries(s.ctx, msgs); err != nil {
				return protocolError(err)
			}
		}
		for _, i := range chunk {
			m, ok := rows[s.uids[i]]
			if !ok {
				// Expunged by another session; it is reported as such on the
				// next poll. RFC 9051 lets the server leave it out here.
				continue
			}
			if options.ChangedSince != 0 && m.ModSeq <= options.ChangedSince {
				continue
			}
			if err := s.fetchOne(w, i, m, options, seen, bodyNeeded, summaries); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *imapSession) fetchOne(w *imapserver.FetchWriter, i int, m Message, options *imap.FetchOptions, seen, bodyNeeded bool, summaries map[string]*Summary) error {
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
	if options.ModSeq || (seen && w.CondStore()) {
		response.WriteModSeq(m.ModSeq)
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
	i := sort.Search(len(s.uids), func(i int) bool { return s.uids[i] >= uid })
	return i, i < len(s.uids) && s.uids[i] == uid
}

func (s *imapSession) Store(w *imapserver.FetchWriter, set imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if s.readOnly {
		return protocolError(ErrReadOnly)
	}
	idx := s.selectedIdx(set)
	uids := make([]uint32, len(idx))
	for i, j := range idx {
		uids[i] = s.uids[j]
	}
	values := make([]string, len(flags.Flags))
	for i, f := range flags.Flags {
		values[i] = string(f)
	}
	var unchangedSince uint64
	if options != nil {
		unchangedSince = options.UnchangedSince
	}
	modified, err := s.service.engine.MutateFlagsIf(s.ctx, s.account.ID, s.folder.Name, uids, values, int(flags.Op), unchangedSince)
	if err != nil {
		return protocolError(err)
	}
	skipped := make(map[uint32]bool, len(modified))
	for _, u := range modified {
		skipped[u] = true
	}
	// RFC 7162 3.1.3: with UNCHANGEDSINCE the new MODSEQs are reported
	// even for .SILENT.
	if flags.Silent && unchangedSince == 0 {
		return nil
	}
	for start := 0; start < len(idx); start += fetchChunk {
		chunk := idx[start:min(start+fetchChunk, len(idx))]
		rows, err := s.rows(chunk)
		if err != nil {
			return protocolError(err)
		}
		for _, i := range chunk {
			m, ok := rows[s.uids[i]]
			if !ok || skipped[m.UID] {
				continue
			}
			r := w.CreateMessage(seqNumber(i + 1))
			r.WriteUID(imap.UID(m.UID))
			if !flags.Silent {
				r.WriteFlags(imapFlags(m.Flags))
			}
			if w.CondStore() {
				r.WriteModSeq(m.ModSeq)
			}
			if err := r.Close(); err != nil {
				return err
			}
		}
	}
	if len(modified) > 0 {
		// Reported in the numbering the client used.
		if _, isUID := set.(imap.UIDSet); isUID {
			var out imap.UIDSet
			for _, u := range modified {
				out.AddNum(imap.UID(u))
			}
			return imapserver.NewModifiedError(out)
		}
		var out imap.SeqSet
		for _, u := range modified {
			if i, ok := s.viewIndex(u); ok {
				out.AddNum(seqNumber(i + 1))
			}
		}
		return imapserver.NewModifiedError(out)
	}
	return nil
}

// dropFromView reports the given UIDs as expunged, highest sequence number
// first so each number is still valid when the client applies the ones
// before it, and removes them from the view.
func (s *imapSession) dropFromView(gone map[uint32]bool, write func(uint32, imap.UID) error) error {
	for i := len(s.uids) - 1; i >= 0; i-- {
		if gone[s.uids[i]] {
			if err := write(seqNumber(i+1), imap.UID(s.uids[i])); err != nil {
				return err
			}
		}
	}
	kept := s.uids[:0]
	for _, u := range s.uids {
		if !gone[u] {
			kept = append(kept, u)
		}
	}
	s.uids = kept
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
	return s.dropFromView(gone, w.WriteExpungeUID)
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
	gone := make(map[uint32]bool, len(from))
	for _, u := range from {
		gone[u] = true
	}
	return s.dropFromView(gone, w.WriteExpungeUID)
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
	count := len(s.uids)
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
			if err := s.dropFromView(gone, w.WriteExpungeUID); err != nil {
				return err
			}
		}
	}
	var added []uint32
	for _, m := range ch.Changed {
		i, ok := s.viewIndex(m.UID)
		if !ok {
			added = append(added, m.UID)
			continue
		}
		// The view keeps no flags to compare against, so every message
		// changed since the session's MODSEQ is reported; RFC 9051 allows
		// unchanged flags to be repeated.
		if m.ModSeq > s.reported {
			if err := w.WriteMessageFlagsModSeq(seqNumber(i+1), imap.UID(m.UID), imapFlags(m.Flags), m.ModSeq); err != nil {
				return err
			}
		}
	}
	if len(added) > 0 {
		// UIDs only grow, so new mail goes after everything in the view.
		slices.Sort(added)
		s.uids = append(s.uids, added...)
	}
	if len(s.uids) != count || len(added) > 0 {
		if err := w.WriteNumMessages(seqNumber(len(s.uids))); err != nil {
			return err
		}
	}
	// Flag changes up to here are reported even when an expunge is held
	// back, so they aren't repeated on every poll until it is sent.
	s.reported = ch.Folder.ModSeq
	if !pending {
		s.folder = ch.Folder
	}
	return nil
}

// pollFull reconciles the view with the folder, for sessions the change
// journal can no longer answer. Flags of every message are reported.
func (s *imapSession) pollFull(w *imapserver.UpdateWriter, allowExpunge bool) error {
	info, err := s.service.engine.SelectFolder(s.ctx, s.account.ID, s.folder.Name)
	if err != nil {
		return protocolError(err)
	}
	present := make(map[uint32]bool, len(info.UIDs))
	for _, u := range info.UIDs {
		present[u] = true
	}
	gone := map[uint32]bool{}
	for _, u := range s.uids {
		if !present[u] {
			gone[u] = true
		}
	}
	pending := len(gone) > 0 && !allowExpunge
	if len(gone) > 0 && allowExpunge {
		if err := s.dropFromView(gone, w.WriteExpungeUID); err != nil {
			return err
		}
	}
	last := uint32(0)
	if len(s.uids) > 0 {
		last = s.uids[len(s.uids)-1]
	}
	for _, u := range info.UIDs {
		if u > last {
			s.uids = append(s.uids, u)
		}
	}
	all := make([]int, len(s.uids))
	for i := range all {
		all[i] = i
	}
	for start := 0; start < len(all); start += fetchChunk {
		chunk := all[start:min(start+fetchChunk, len(all))]
		rows, err := s.rows(chunk)
		if err != nil {
			return protocolError(err)
		}
		for _, i := range chunk {
			if m, ok := rows[s.uids[i]]; ok {
				if err := w.WriteMessageFlagsModSeq(seqNumber(i+1), imap.UID(m.UID), imapFlags(m.Flags), m.ModSeq); err != nil {
					return err
				}
			}
		}
	}
	if err := w.WriteNumMessages(seqNumber(len(s.uids))); err != nil {
		return err
	}
	s.reported = info.Folder.ModSeq
	if !pending {
		s.folder = info.Folder
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
// order. Rows are loaded in chunks; summaries only when header criteria
// need them; bodies only for BODY and TEXT.
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
	if len(s.uids) > 0 {
		maxUID = s.uids[len(s.uids)-1]
	}
	total := seqNumber(len(s.uids))
	// Rows are needed for flag, date and size criteria, for header and text
	// criteria the index can't answer, and for mail not yet indexed. When
	// none apply (SORT ALL, THREAD ALL, indexed text searches) the UIDs are
	// all there is to evaluate.
	var rows map[uint32]Message
	if needHeader || needText || searchNeedsRows(c) || (hits != nil && len(hits.unindexed) > 0) {
		msgs, err := scanMessages(s.ctx, s.service.engine.DB, s.folder.ID)
		if err != nil {
			return nil, protocolError(err)
		}
		rows = make(map[uint32]Message, len(msgs))
		for _, m := range msgs {
			rows[m.UID] = m
		}
	}
	for start := 0; start < len(s.uids); start += fetchChunk {
		end := min(start+fetchChunk, len(s.uids))
		var summaries map[string]*Summary
		if needHeader {
			msgs := make([]Message, 0, end-start)
			for _, u := range s.uids[start:end] {
				if m, ok := rows[u]; ok {
					msgs = append(msgs, m)
				}
			}
			var err error
			if summaries, err = s.service.engine.Summaries(s.ctx, msgs); err != nil {
				return nil, protocolError(err)
			}
		}
		for i := start; i < end; i++ {
			m := Message{UID: s.uids[i]}
			if rows != nil {
				var ok bool
				if m, ok = rows[s.uids[i]]; !ok {
					continue // expunged by another session
				}
			}
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
			nums[i] = s.uids[j]
		}
	}
	data := &imap.SearchData{Count: seqNumber(len(nums))}
	if c.ModSeq != nil && len(idx) > 0 {
		// RFC 7162 3.1.5: a MODSEQ search reports the highest MODSEQ found.
		for start := 0; start < len(idx); start += fetchChunk {
			rows, err := s.rows(idx[start:min(start+fetchChunk, len(idx))])
			if err != nil {
				return nil, protocolError(err)
			}
			for _, m := range rows {
				data.ModSeq = max(data.ModSeq, m.ModSeq)
			}
		}
	}
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
