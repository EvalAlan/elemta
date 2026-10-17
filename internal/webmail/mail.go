package webmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func parseUID(v string) (uint32, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

func (s *Server) maxMessage() int64 { return int64(s.cfg.MaxMessageMB) << 20 }

// listState is what a message list URL carries besides the folder: the
// search, sort and page. Links and redirects preserve it, so acting on a
// message doesn't lose the user's place.
type listState struct {
	Folder  string
	Query   string
	Sort    Sort
	Reverse bool
	Page    int
}

func listStateFrom(v url.Values) listState {
	st := listState{Folder: v.Get("f"), Query: strings.TrimSpace(v.Get("q")), Sort: Sort(v.Get("sort")), Reverse: v.Get("rev") == "1"}
	if st.Folder == "" {
		st.Folder = "INBOX"
	}
	switch st.Sort {
	case SortDate, SortFrom, SortSubject, SortSize:
	default:
		st.Sort = SortDate
	}
	st.Page, _ = strconv.Atoi(v.Get("page"))
	if st.Page < 1 {
		st.Page = 1
	}
	return st
}

func (l listState) values() url.Values {
	v := url.Values{"f": {l.Folder}}
	if l.Page > 1 {
		v.Set("page", strconv.Itoa(l.Page))
	}
	if l.Query != "" {
		v.Set("q", l.Query)
	}
	if l.Sort != SortDate {
		v.Set("sort", string(l.Sort))
	}
	if l.Reverse {
		v.Set("rev", "1")
	}
	return v
}

// URL is the list itself.
func (l listState) URL() string { return "/mail?" + l.values().Encode() }

// PageURL is the same list on another page.
func (l listState) PageURL(page int) string {
	l.Page = page
	return l.URL()
}

// SortURL orders the list by key, flipping the direction when it is already
// ordered that way.
func (l listState) SortURL(key Sort) string {
	if l.Sort == key {
		l.Reverse = !l.Reverse
	} else {
		l.Sort, l.Reverse = key, false
	}
	l.Page = 1
	return l.URL()
}

// MessageURL opens a message within the list.
func (l listState) MessageURL(uid uint32) string {
	v := l.values()
	v.Set("uid", strconv.FormatUint(uint64(uid), 10))
	return "/mail?" + v.Encode()
}

func (s *Server) mailPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	ls := listStateFrom(q)
	uid, hasUID := parseUID(q.Get("uid"))
	remote := q.Get("remote") == "1"
	loc := s.loc(sess)

	lq := parseSearch(ls.Query, loc)
	lq.Sort, lq.Reverse, lq.Page, lq.PageSize = ls.Sort, ls.Reverse, ls.Page, s.pageSize(sess)

	v := view{Title: ls.Folder, Session: sess, Folder: ls.Folder, Query: ls.Query, List: &ls, Notice: notices[q.Get("n")], Remote: remote}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		if hasUID {
			raw, err := st.Raw(r.Context(), ls.Folder, uid, s.maxMessage())
			if err != nil {
				return err
			}
			msg, err := parseMessage(raw)
			if err != nil {
				return err
			}
			msg.UID, msg.Folder = uid, ls.Folder
			// Opening a message is what marks it read; fetching it peeks.
			if err := st.SetFlags(r.Context(), ls.Folder, []uint32{uid}, []string{FlagSeen}, true); err != nil {
				return err
			}
			msg.Seen = true
			v.Message = msg
			if msg.HTML != "" {
				res := sanitizeHTML(msg.HTML, sanitizeOptions{AllowRemote: remote})
				v.Body = &res
			}
			v.Title = msg.Subject
			v.Tags, _ = st.Tags(r.Context(), ls.Folder)
		}
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		if v.Message != nil {
			v.Thread = s.conversation(r.Context(), st, v.Message, folders)
		}
		p, err := st.List(r.Context(), ls.Folder, lq)
		if err != nil {
			return err
		}
		v.Page = &p
		for i, m := range p.Messages {
			if v.Message == nil || m.UID != uid {
				continue
			}
			v.Message.Flagged = m.Flagged
			v.Message.Tags = m.Tags
			if i > 0 {
				v.Message.Newer = p.Messages[i-1].UID
			}
			if i < len(p.Messages)-1 {
				v.Message.Older = p.Messages[i+1].UID
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if v.Message != nil {
		s.decorateMessage(r.Context(), sess, &v)
	}
	s.render(w, "mail.html", http.StatusOK, v)
}

// conversation lists the other messages in the open message's thread, from
// its own folder and from Sent, so the user sees their replies in line.
// Failures only cost the list; the message still shows.
func (s *Server) conversation(ctx context.Context, st Mailstore, m *Message, folders []Folder) []Related {
	ids := threadIDs(m)
	if len(ids) == 0 {
		return nil
	}
	search := []string{m.Folder}
	for _, f := range folders {
		if (f.Role == RoleSent || f.Role == RoleInbox || f.Role == RoleArchive) && f.Name != m.Folder {
			search = append(search, f.Name)
		}
	}
	found, err := st.Related(ctx, search, ids)
	if err != nil {
		s.log.Debug("webmail: conversation", "error", err)
		return nil
	}
	var out []Related
	seen := map[string]bool{}
	for _, r := range found {
		key := r.Folder + "\x00" + strconv.FormatUint(uint64(r.UID), 10)
		if seen[key] || (r.Folder == m.Folder && r.UID == m.UID) {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

// threadIDs are the Message-IDs that tie a message to its conversation.
func threadIDs(m *Message) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && strings.HasPrefix(id, "<") && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, f := range strings.Fields(m.References) {
		add(f)
	}
	add(m.InReplyTo)
	add(m.MessageID)
	return ids
}

// decorateMessage adds what other parts of the webmail know about an open
// message: whether the sender is a contact, and any invitation it carries.
// It is a hook point; each feature registers in messageDecorators.
func (s *Server) decorateMessage(ctx context.Context, sess *Session, v *view) {
	for _, d := range messageDecorators {
		d(s, ctx, sess, v)
	}
}

var messageDecorators []func(*Server, context.Context, *Session, *view)

// loadMessage fetches and parses one message for the body/part handlers.
func (s *Server) loadMessage(r *http.Request, sess *Session) (string, uint32, []byte, error) {
	folder := r.URL.Query().Get("f")
	uid, ok := parseUID(r.URL.Query().Get("uid"))
	if folder == "" || !ok {
		return "", 0, nil, ErrNotFound
	}
	var raw []byte
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		raw, err = st.Raw(r.Context(), folder, uid, s.maxMessage())
		return err
	})
	return folder, uid, raw, err
}

// maxInlineImage caps a cid: image embedded into the body as a data: URI.
const maxInlineImage = 4 << 20

// messageBody serves sanitised message HTML for the reading pane's frame.
//
// It runs under its own CSP: a sandbox with no scripts and a unique origin,
// so even HTML that got past the sanitiser can't reach the webmail's cookies
// or DOM. cid: images are embedded as data: URIs rather than linked, because
// requests from a sandboxed (opaque-origin) frame don't carry the session
// cookie.
func (s *Server) messageBody(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil || msg.HTML == "" {
		http.Error(w, "No HTML body.", http.StatusNotFound)
		return
	}
	remote := r.URL.Query().Get("remote") == "1"
	res := sanitizeHTML(msg.HTML, sanitizeOptions{
		AllowRemote: remote,
		CIDURL: func(cid string) string {
			part, body, err := findPart(raw, 0, cid)
			if err != nil || len(body) > maxInlineImage || !strings.HasPrefix(part.ContentType, "image/") {
				return ""
			}
			return "data:" + part.ContentType + ";base64," + base64.StdEncoding.EncodeToString(body)
		},
	})
	imgSrc := "data:"
	if remote {
		imgSrc = "data: https: http:"
	}
	h := w.Header()
	// The frame is same-origin so the reading pane can size it to the
	// message (no inner scrollbar), and it can run no script at all: the
	// sandbox omits allow-scripts and the policy's default-src 'none'
	// covers scripts. It's the combination of allow-same-origin with
	// allow-scripts that would be dangerous, and that is never granted.
	h.Set("Content-Security-Policy", "sandbox allow-popups allow-popups-to-escape-sandbox allow-same-origin; default-src 'none'; script-src 'none'; img-src "+imgSrc+"; style-src 'unsafe-inline'; font-src data:; form-action 'none'; frame-ancestors 'self'")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-store")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><base target="_blank"><style>body{margin:0;padding:16px 20px;font:15px/1.6 system-ui,sans-serif;color:#0E1726;background:#FFFFFF;word-wrap:break-word}img{max-width:100%%;height:auto}</style><style>%s</style></head><body>%s</body></html>`, res.CSS, res.HTML)
}

// messagePart downloads one attachment. It is always served as an
// attachment with nosniff, never rendered inline, so an HTML or SVG
// "attachment" can't run as a page on the webmail's origin.
func (s *Server) messagePart(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	part, body, err := findPart(raw, n, "")
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	name := part.Filename
	if name == "" {
		name = fmt.Sprintf("part-%d", part.Index)
	}
	if r.URL.Query().Get("inline") == "1" && previewable(part.ContentType) {
		// Raster images only: they can't carry script. SVG never comes
		// this way. The response still gets a sandbox CSP in case a
		// browser is talked into rendering it as a document.
		w.Header().Set("Content-Type", part.ContentType)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": name}))
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "private, max-age=3600")
		// #nosec G705 -- a raster image with its own type, nosniff and a sandbox CSP
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- served as an octet-stream attachment with nosniff, so the browser never renders it
	_, _ = w.Write(body)
}

// previewable reports whether an attachment type can be shown inline as an
// image preview.
func previewable(ct string) bool {
	switch strings.ToLower(ct) {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	}
	return false
}

// messagePrint renders a message on a plain page for printing.
func (s *Server) messagePrint(w http.ResponseWriter, r *http.Request, sess *Session) {
	folder, uid, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg.Folder, msg.UID = folder, uid
	if msg.Text == "" && msg.HTML != "" {
		msg.Text = htmlToText(msg.HTML)
	}
	s.render(w, "print.html", http.StatusOK, view{Title: msg.Subject, Session: sess, Message: msg})
}

// messageSource shows the message exactly as stored, headers and all,
// for checking where it came from or why it was filtered. The source is
// only ever text in a <pre>, escaped by the template, so nothing in it can
// render or run.
func (s *Server) messageSource(w http.ResponseWriter, r *http.Request, sess *Session) {
	folder, uid, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil {
		msg = &Message{}
	}
	msg.Folder, msg.UID = folder, uid
	src := strings.ToValidUTF8(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\uFFFD")
	s.render(w, "source.html", http.StatusOK, view{Title: "Original of " + msg.Subject, Session: sess, Message: msg, Source: src})
}

// messageRaw downloads the message source as .eml.
func (s *Server) messageRaw(w http.ResponseWriter, r *http.Request, sess *Session) {
	_, uid, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fmt.Sprintf("message-%d.eml", uid)}))
	w.Header().Set("Cache-Control", "private, no-store")
	// #nosec G705 -- served as a message/rfc822 attachment with nosniff, so the browser never renders it
	_, _ = w.Write(raw)
}

// tagRE is what a tag may contain. IMAP keywords are atoms, so spaces,
// brackets, quotes and the like can't be stored; this also keeps tags
// readable in other clients.
var tagRE = regexp.MustCompile(`^[\p{L}\p{N}_.\-]{1,40}$`)

// localBack returns back if it is a path within the mail view, so a crafted
// form can't turn the redirect after an action into an open redirect.
func localBack(back, fallback string) string {
	if (strings.HasPrefix(back, "/mail?") || back == "/mail") && !strings.ContainsAny(back, "\\\r\n") {
		return back
	}
	return fallback
}

// redirectLocal redirects to a same-site path built from user input (a
// "back" field). Anything that isn't a plain local path goes to the inbox.
func redirectLocal(w http.ResponseWriter, r *http.Request, target string) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		target = "/mail"
	} else {
		target = (&url.URL{Path: u.Path, RawQuery: u.RawQuery}).String()
	}
	// #nosec G710 -- target is reduced to a local path above, never another host
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// messageAction applies one operation to one or more messages. Selecting
// rows in the list and pressing a button posts several uid values; the
// reading pane's toolbar posts one.
func (s *Server) messageAction(w http.ResponseWriter, r *http.Request, sess *Session) {
	folder := r.PostFormValue("f")
	op := r.PostFormValue("op")
	var uids []uint32
	for _, v := range r.PostForm["uid"] {
		if u, ok := parseUID(v); ok {
			uids = append(uids, u)
		}
	}
	if folder == "" {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	back := localBack(r.PostFormValue("back"), folderURL(folder, 1, ""))
	if len(uids) == 0 && op != "empty" && op != "readall" {
		redirectLocal(w, r, back)
		return
	}
	notice := ""
	// leaves is true for operations after which the open message is no
	// longer in this folder, so the redirect drops it.
	leaves := false
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		ctx := r.Context()
		switch op {
		case "read":
			return st.SetFlags(ctx, folder, uids, []string{FlagSeen}, true)
		case "unread":
			leaves = true // reopening it would mark it read again
			return st.SetFlags(ctx, folder, uids, []string{FlagSeen}, false)
		case "flag":
			return st.SetFlags(ctx, folder, uids, []string{FlagFlagged}, true)
		case "unflag":
			return st.SetFlags(ctx, folder, uids, []string{FlagFlagged}, false)
		case "tag", "untag":
			tag := strings.TrimSpace(r.PostFormValue("tag"))
			if !tagRE.MatchString(tag) || !isTagKeyword(tag) {
				return errBadTag
			}
			return st.SetFlags(ctx, folder, uids, []string{tag}, op == "tag")
		case "delete":
			notice, leaves = plural("deleted", len(uids)), true
			return st.Delete(ctx, folder, uids)
		case "move":
			dest := r.PostFormValue("dest")
			if dest == "" || dest == folder {
				return nil
			}
			notice, leaves = plural("moved", len(uids)), true
			return st.Move(ctx, folder, uids, dest)
		case "junk":
			notice, leaves = plural("moved", len(uids)), true
			if err := st.SetFlags(ctx, folder, uids, []string{"$Junk"}, true); err != nil {
				return err
			}
			return moveToRole(ctx, st, folder, uids, RoleJunk)
		case "notjunk":
			notice, leaves = plural("moved", len(uids)), true
			if err := st.SetFlags(ctx, folder, uids, []string{"$NotJunk"}, true); err != nil {
				return err
			}
			return st.Move(ctx, folder, uids, "INBOX")
		case "archive":
			notice, leaves = plural("archived", len(uids)), true
			return moveToRole(ctx, st, folder, uids, RoleArchive)
		case "empty":
			notice = "emptied"
			return st.EmptyFolder(ctx, folder)
		case "readall":
			notice = "all-read"
			return st.MarkAllRead(ctx, folder)
		}
		return fmt.Errorf("webmail: unknown action %q", op)
	})
	if errors.Is(err, errBadTag) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Tags can use letters, numbers, dots, dashes and underscores, up to 40 characters.")
		return
	}
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if leaves {
		back = dropParam(back, "uid")
	}
	if notice != "" {
		back = setParam(back, "n", notice)
	}
	redirectLocal(w, r, back)
}

var errBadTag = errors.New("webmail: invalid tag")

func plural(notice string, n int) string {
	if n > 1 {
		return notice + "-many"
	}
	return notice
}

func dropParam(u, key string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := p.Query()
	q.Del(key)
	p.RawQuery = q.Encode()
	return p.String()
}

func setParam(u, key, val string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := p.Query()
	q.Set(key, val)
	p.RawQuery = q.Encode()
	return p.String()
}

// defaultFolderRoles are the folders every account is given at sign-in.
var defaultFolderRoles = []Role{RoleDrafts, RoleSent, RoleJunk, RoleTrash}

// moveToRole moves messages to the folder with role, creating it under its
// default name when the account has none (Archive, usually).
func moveToRole(ctx context.Context, st Mailstore, folder string, uids []uint32, role Role) error {
	folders, err := st.Folders(ctx)
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f.Role == role {
			return st.Move(ctx, folder, uids, f.Name)
		}
	}
	name := defaultRoleNames[role]
	if name == "" {
		return ErrNotFound
	}
	if err := st.CreateFolder(ctx, name); err != nil && !errors.Is(err, ErrExists) {
		return err
	}
	return st.Move(ctx, folder, uids, name)
}

// ---- folders ---------------------------------------------------------------

// folderNameRE limits what a user can type as a folder name. The hierarchy
// delimiter is added by the server, never typed, so a name can't escape the
// parent it was created under.
var folderNameRE = regexp.MustCompile(`^[^/.\\%*"\x00-\x1f]{1,80}$`)

func (s *Server) foldersPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	v := view{Title: "Folders", Session: sess, Notice: notices[r.URL.Query().Get("n")]}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		v.Folders, err = st.Folders(r.Context())
		return err
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.render(w, "folders.html", http.StatusOK, v)
}

func (s *Server) foldersSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	op := r.PostFormValue("op")
	name := strings.TrimSpace(r.PostFormValue("name"))
	target := r.PostFormValue("folder")
	parent := r.PostFormValue("parent")
	if op != "delete" && !folderNameRE.MatchString(name) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Folder names can't be empty or contain / . \\ % * or quotes.")
		return
	}
	notice := ""
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		ctx := r.Context()
		delim, err := st.Delimiter(ctx)
		if err != nil {
			return err
		}
		folders, err := st.Folders(ctx)
		if err != nil {
			return err
		}
		find := func(n string) *Folder {
			for i := range folders {
				if folders[i].Name == n {
					return &folders[i]
				}
			}
			return nil
		}
		full := func(parent, leaf string) string {
			if parent == "" {
				return leaf
			}
			return parent + delim + leaf
		}
		switch op {
		case "create":
			if parent != "" && find(parent) == nil {
				return ErrNotFound
			}
			notice = "folder-created"
			return st.CreateFolder(ctx, full(parent, name))
		case "rename":
			f := find(target)
			if f == nil {
				return ErrNotFound
			}
			if f.Role != RoleNone {
				return errProtectedFolder
			}
			notice = "folder-renamed"
			return st.RenameFolder(ctx, target, full(f.Parent, name))
		case "delete":
			f := find(target)
			if f == nil {
				return ErrNotFound
			}
			if f.Role != RoleNone {
				return errProtectedFolder
			}
			for _, g := range folders {
				if g.Parent == target {
					return errFolderHasChildren
				}
			}
			notice = "folder-deleted"
			return st.DeleteFolder(ctx, target)
		}
		return fmt.Errorf("webmail: unknown folder action %q", op)
	})
	switch {
	case errors.Is(err, ErrExists):
		s.renderProblem(w, r, sess, http.StatusConflict, "A folder with that name already exists.")
	case errors.Is(err, errProtectedFolder):
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Inbox, Drafts, Sent, Archive, Junk and Trash can't be renamed or deleted.")
	case errors.Is(err, errFolderHasChildren):
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Delete or move the folders inside it first.")
	case err != nil:
		s.fail(w, r, sess, err)
	default:
		http.Redirect(w, r, "/folders?n="+notice, http.StatusSeeOther)
	}
}

var (
	errProtectedFolder   = errors.New("webmail: special folder")
	errFolderHasChildren = errors.New("webmail: folder has subfolders")
)

// ---- live counts -----------------------------------------------------------

// countsAPI returns each folder's unread count, which the page polls to keep
// the folder tree and the tab title current without a reload.
func (s *Server) countsAPI(w http.ResponseWriter, r *http.Request, sess *Session) {
	counts := map[string]uint32{}
	err := s.sessions.withStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		for _, f := range folders {
			counts[f.Name] = f.Unread
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrAuthFailed) {
			http.Error(w, "signed out", http.StatusUnauthorized)
			return
		}
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"unread": counts, "time": time.Now().Unix()})
}
