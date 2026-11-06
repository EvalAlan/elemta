package webmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/EvalAlan/elemta/internal/mailcategory"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
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
	// Tab is the inbox tab (a mailcategory name), or "" when the list has
	// no tabs: another folder, a search, or tabs turned off.
	Tab string
}

func listStateFrom(v url.Values) listState {
	st := listState{Folder: v.Get("f"), Query: strings.TrimSpace(v.Get("q")), Sort: Sort(v.Get("sort")), Reverse: v.Get("rev") == "1", Tab: v.Get("tab")}
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
	if l.Tab != "" {
		v.Set("tab", l.Tab)
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

	// Tabs split the inbox only. A search looks across every tab, as the
	// user is looking for something rather than browsing.
	tabs := s.prefsCached(sess).InboxTabs && strings.EqualFold(ls.Folder, "INBOX") && ls.Query == ""
	if tabs {
		cat, _ := mailcategory.Parse(ls.Tab)
		ls.Tab = cat.Name()
	} else {
		ls.Tab = ""
	}
	lq := parseSearch(ls.Query, loc)
	lq.Sort, lq.Reverse, lq.Page, lq.PageSize, lq.Category = ls.Sort, ls.Reverse, ls.Page, s.pageSize(sess), ls.Tab

	v := view{Title: ls.Folder, Session: sess, Folder: ls.Folder, Query: ls.Query, List: &ls, Notice: notices[q.Get("n")], Remote: remote}
	if u, ok := decodeUndo(q.Get("undo"), time.Now()); ok && v.Notice != "" {
		v.Undo = &u
	}
	v.SharedMailboxes = s.sharedMailboxes(r.Context(), sess)
	if s.prefsCached(sess).MailCalendar {
		v.Calendar = s.mailCalendar(r.Context(), sess)
	}
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		if hasUID {
			raw, err := s.rawMessage(sess, func() ([]byte, error) { return st.Raw(r.Context(), ls.Folder, uid, s.maxMessage()) }, ls.Folder, uid)
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
			v.Title = msg.Subject
			v.Tags, _ = st.Tags(r.Context(), ls.Folder)
		}
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		if tabs {
			v.InboxTabs = s.inboxTabs(r.Context(), st, ls)
		}
		if v.Message != nil {
			if !remote && s.autoImages(sess, ls.Folder, folders) {
				remote = true
				v.Remote = true
			}
			if v.Message.HTML != "" {
				res := sanitizeHTML(v.Message.HTML, sanitizeOptions{AllowRemote: remote})
				v.Body = &res
			}
		}
		if v.Message != nil {
			v.Thread = s.conversation(r.Context(), st, v.Message, folders)
			for _, rel := range v.Thread {
				if rel.Date.After(v.Message.Date) {
					v.ThreadAfter = append(v.ThreadAfter, rel)
				} else {
					v.ThreadBefore = append(v.ThreadBefore, rel)
				}
			}
		}
		var p Page
		// Conversations are ordered by activity, so they apply to the date
		// order only; Drafts are never grouped.
		if s.prefsCached(sess).GroupConversations() && ls.Sort == SortDate && !isRoleIn(ls.Folder, folders, RoleDrafts) {
			tp, err := st.ListThreads(r.Context(), ls.Folder, lq)
			if err != nil {
				return err
			}
			v.Threaded, v.Conversations = true, tp.Conversations
			p = Page{Folder: tp.Folder, Total: tp.Total, Page: tp.Page, PageSize: tp.PageSize}
			// Newer/older navigation walks the conversations' latest messages,
			// except that the open message stands for its own conversation:
			// a row can open an older one, and the arrows have to find it.
			for _, c := range tp.Conversations {
				row := c.Latest
				if i := slices.IndexFunc(c.Messages, func(m Summary) bool { return hasUID && m.UID == uid }); i >= 0 {
					row = c.Messages[i]
				}
				p.Messages = append(p.Messages, row)
			}
		} else {
			var err error
			p, err = st.List(r.Context(), ls.Folder, lq)
			if err != nil {
				return err
			}
		}
		v.Page = &p
		// Recorded before the open message is decorated, so an open reply
		// already shows as recorded.
		if s.sessions.SelectedMailbox(sess) == "" {
			s.recordReplies(r.Context(), st, ls.Folder, sess.Address, pendingReplies(p, v.Conversations), loc)
		}
		for _, c := range v.Conversations {
			for _, m := range c.Messages {
				if v.Message != nil && m.UID == uid {
					v.Message.Flagged, v.Message.Tags = m.Flagged, m.Tags
				}
			}
		}
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

// autoImages reports whether a message in folder shows remote images
// without the user asking: only when they chose that in Settings, and never
// in Junk, where a tracking pixel would confirm the address to a spammer.
func (s *Server) autoImages(sess *Session, folder string, folders []Folder) bool {
	return s.prefsCached(sess).LoadImages && !isRoleIn(folder, folders, RoleJunk) && !isRoleIn(folder, folders, RoleQuarantine)
}

func isRoleIn(name string, folders []Folder, role Role) bool {
	for _, f := range folders {
		if f.Name == name {
			return f.Role == role
		}
	}
	return false
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
	// The same message can be in two folders: a copy sent to oneself is in
	// Sent and the Inbox. Show each once, preferring the copy in the folder
	// being read, and never repeat the open message itself.
	sort.SliceStable(found, func(i, j int) bool { return found[i].Folder == m.Folder && found[j].Folder != m.Folder })
	var out []Related
	seen := map[string]bool{}
	if id := strings.Trim(strings.TrimSpace(m.MessageID), "<>"); id != "" {
		seen["id:<"+id+">"] = true
	}
	for _, r := range found {
		key := r.Folder + "\x00" + strconv.FormatUint(uint64(r.UID), 10)
		if seen[key] || (r.Folder == m.Folder && r.UID == m.UID) || (r.MessageID != "" && seen["id:"+r.MessageID]) {
			continue
		}
		seen[key] = true
		if r.MessageID != "" {
			seen["id:"+r.MessageID] = true
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Date.Before(out[j].Date) })
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
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		raw, err = s.rawMessage(sess, func() ([]byte, error) { return st.Raw(r.Context(), folder, uid, s.maxMessage()) }, folder, uid)
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
	folder, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil {
		http.Error(w, "The message couldn't be read.", http.StatusNotFound)
		return
	}
	remote := r.URL.Query().Get("remote") == "1"
	if !remote && s.prefsCached(sess).LoadImages {
		// Conversation cards load their bodies here without the reading
		// page's flag, so the preference is applied here too.
		_ = s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
			folders, err := st.Folders(r.Context())
			if err == nil {
				remote = s.autoImages(sess, folder, folders)
			}
			return nil
		})
	}
	if msg.HTML == "" {
		// Plain-text messages render here too, so a conversation can show
		// every message the same way, each in its own frame.
		msg.HTML = `<pre style="white-space:pre-wrap;word-wrap:break-word;font:inherit;margin:0">` + string(linkify(msg.Text)) + `</pre>`
	}
	var imageURL func(string) string
	if s.images != nil {
		imageURL = newImageSigner(sess).url
	}
	res := sanitizeHTML(msg.HTML, sanitizeOptions{
		AllowRemote: remote,
		ImageURL:    imageURL,
		CIDURL: func(cid string) string {
			part, body, err := findPart(raw, 0, cid)
			if err != nil || len(body) > maxInlineImage || !strings.HasPrefix(part.ContentType, "image/") {
				return ""
			}
			return "data:" + part.ContentType + ";base64," + base64.StdEncoding.EncodeToString(body)
		},
	})
	imgSrc := "data:"
	switch {
	case remote && s.images != nil:
		// Every remote image was rewritten to the proxy, so the frame may
		// load images from this origin only. Anything the rewrite missed
		// fails here rather than reaching the sender.
		imgSrc = "data: 'self'"
	case remote:
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
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light"><base target="_blank"><style>:root{color-scheme:light}body{margin:0;padding:16px 20px;font:15px/1.6 system-ui,sans-serif;color:#0E1726;background:#FFFFFF;word-wrap:break-word}img{max-width:100%%;height:auto}</style><style>%s</style></head><body>%s</body></html>`, res.CSS, res.HTML)
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
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/\\") {
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
	// A conversation row posts its messages as one comma-joined value.
	for _, v := range r.PostForm["uid"] {
		for _, part := range strings.Split(v, ",") {
			if u, ok := parseUID(strings.TrimSpace(part)); ok {
				uids = append(uids, u)
			}
		}
	}
	if folder == "" {
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	back := localBack(r.PostFormValue("back"), folderURL(folder, 1, ""))
	s.pages.forgetRaw(sess.ID)
	if len(uids) == 0 && op != "empty" && op != "readall" {
		redirectLocal(w, r, back)
		return
	}
	notice := ""
	// undo is where a move sent the messages, for the notice's Undo button.
	var undo *undoMove
	moved := func(dest string, newUIDs []uint32) {
		if len(newUIDs) > 0 {
			undo = &undoMove{From: dest, To: folder, UIDs: newUIDs}
		}
	}
	var learn []string // senders whose tab the user just chose
	var learnCat mailcategory.Category
	// leaves is true for operations after which the open message is no
	// longer in this folder, so the redirect drops it.
	leaves := false
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
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
		case "category":
			cat, ok := mailcategory.Parse(r.PostFormValue("category"))
			if !ok {
				return fmt.Errorf("webmail: unknown category %q", r.PostFormValue("category"))
			}
			senders, err := st.Senders(ctx, folder, uids)
			if err != nil {
				return err
			}
			if err := setCategory(ctx, st, folder, uids, cat); err != nil {
				return err
			}
			learn, learnCat = uniqueSenders(senders, 20), cat
			notice = "categorized"
			// The message has left the tab being shown.
			leaves = r.PostFormValue("tab") != "" && r.PostFormValue("tab") != cat.Name()
			return nil
		case "delete":
			notice, leaves = plural("deleted", len(uids)), true
			// To Trash is a move, and undoable; in Trash (or with no Trash)
			// it's for good, and Delete does that.
			trash, err := roleFolderName(ctx, st, RoleTrash)
			if err != nil {
				return err
			}
			if trash == "" || trash == folder {
				return st.Delete(ctx, folder, uids)
			}
			newUIDs, err := st.Move(ctx, folder, uids, trash)
			moved(trash, newUIDs)
			return err
		case "move":
			dest := r.PostFormValue("dest")
			if dest == "" || dest == folder {
				return nil
			}
			notice, leaves = plural("moved", len(uids)), true
			newUIDs, err := st.Move(ctx, folder, uids, dest)
			moved(dest, newUIDs)
			return err
		case "undo":
			// The notice's Undo: the same messages back where they came
			// from. Not itself undoable; moving them again is.
			dest := r.PostFormValue("dest")
			if dest == "" || dest == folder {
				return nil
			}
			notice, leaves = "undone", true
			_, err := st.Move(ctx, folder, uids, dest)
			return err
		case "junk":
			notice, leaves = plural("moved", len(uids)), true
			if err := st.SetFlags(ctx, folder, uids, []string{"$Junk"}, true); err != nil {
				return err
			}
			dest, newUIDs, err := moveToRole(ctx, st, folder, uids, RoleJunk)
			moved(dest, newUIDs)
			return err
		case "notjunk":
			notice, leaves = plural("moved", len(uids)), true
			if err := st.SetFlags(ctx, folder, uids, []string{"$NotJunk"}, true); err != nil {
				return err
			}
			newUIDs, err := st.Move(ctx, folder, uids, "INBOX")
			moved("INBOX", newUIDs)
			return err
		case "archive":
			notice, leaves = plural("archived", len(uids)), true
			dest, newUIDs, err := moveToRole(ctx, st, folder, uids, RoleArchive)
			moved(dest, newUIDs)
			return err
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
	if len(learn) > 0 {
		// After the IMAP work, outside the store lock: these are calls to
		// the mailbox service.
		s.learnCategory(r.Context(), sess, learn, learnCat)
	}
	if leaves {
		back = dropParam(back, "uid")
	}
	if notice != "" {
		back = setParam(back, "n", notice)
	}
	if undo != nil {
		back = setParam(back, "undo", undo.encode(time.Now()))
	} else {
		back = dropParam(back, "undo")
	}
	redirectLocal(w, r, back)
}

var errBadTag = errors.New("webmail: invalid tag")

// undoMove is a move to put back: the messages now at UIDs in From go back
// to To. It travels in the redirect's address, not in the session, so the
// Undo button works whichever webmail process serves the next page and
// survives a restart, and nothing is kept for undos nobody takes.
type undoMove struct {
	From, To string
	UIDs     []uint32
}

// undoWindow is how long a move can be undone from its notice. Long enough
// to notice a slip; short enough that a reload or a bookmark doesn't offer
// to undo something from yesterday.
const undoWindow = 2 * time.Minute

// maxUndoUIDs keeps the address a sensible length. A bigger move (a whole
// folder's worth) is undone by moving the messages back by hand.
const maxUndoUIDs = 500

// encode packs u, stamped with now, as <unix>.<from>.<to>.<uid,uid...>, the
// folder names base64url-encoded since they can hold any character.
func (u undoMove) encode(now time.Time) string {
	if len(u.UIDs) == 0 || len(u.UIDs) > maxUndoUIDs {
		return ""
	}
	ids := make([]string, len(u.UIDs))
	for i, id := range u.UIDs {
		ids[i] = strconv.FormatUint(uint64(id), 10)
	}
	b := base64.RawURLEncoding
	return strconv.FormatInt(now.Unix(), 10) + "." + b.EncodeToString([]byte(u.From)) + "." +
		b.EncodeToString([]byte(u.To)) + "." + strings.Join(ids, ",")
}

// decodeUndo reads an undo token, refusing a malformed or expired one. It
// grants nothing: the move it describes is posted back with the session's
// CSRF token and checked like any other, on the user's own folders.
func decodeUndo(s string, now time.Time) (undoMove, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return undoMove{}, false
	}
	at, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return undoMove{}, false
	}
	if age := now.Sub(time.Unix(at, 0)); age < 0 || age > undoWindow {
		return undoMove{}, false
	}
	b := base64.RawURLEncoding
	from, err1 := b.DecodeString(parts[1])
	to, err2 := b.DecodeString(parts[2])
	if err1 != nil || err2 != nil || len(from) == 0 || len(to) == 0 {
		return undoMove{}, false
	}
	u := undoMove{From: string(from), To: string(to)}
	for _, p := range strings.Split(parts[3], ",") {
		id, ok := parseUID(p)
		if !ok {
			return undoMove{}, false
		}
		u.UIDs = append(u.UIDs, id)
	}
	if len(u.UIDs) == 0 || len(u.UIDs) > maxUndoUIDs {
		return undoMove{}, false
	}
	return u, true
}

// UIDList is the UIDs as the action form posts them.
func (u undoMove) UIDList() string {
	ids := make([]string, len(u.UIDs))
	for i, id := range u.UIDs {
		ids[i] = strconv.FormatUint(uint64(id), 10)
	}
	return strings.Join(ids, ",")
}

// roleFolderName is the account's folder with that role, or empty.
func roleFolderName(ctx context.Context, st Mailstore, role Role) (string, error) {
	folders, err := st.Folders(ctx)
	if err != nil {
		return "", err
	}
	for _, f := range folders {
		if f.Role == role {
			return f.Name, nil
		}
	}
	return "", nil
}

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
// moveToRole moves messages to the folder with that role, creating it if
// the account has none, and returns the folder and the messages' UIDs there.
func moveToRole(ctx context.Context, st Mailstore, folder string, uids []uint32, role Role) (string, []uint32, error) {
	name, err := roleFolderName(ctx, st, role)
	if err != nil {
		return "", nil, err
	}
	if name == "" {
		name = defaultRoleNames[role]
		if name == "" {
			return "", nil, ErrNotFound
		}
		if err := st.CreateFolder(ctx, name); err != nil && !errors.Is(err, ErrExists) {
			return "", nil, err
		}
	}
	moved, err := st.Move(ctx, folder, uids, name)
	return name, moved, err
}

// ---- folders ---------------------------------------------------------------

// folderNameRE limits what a user can type as a folder name. The hierarchy
// delimiter is added by the server, never typed, so a name can't escape the
// parent it was created under.
var folderNameRE = regexp.MustCompile(`^[^/.\\%*"\x00-\x1f]{1,80}$`)

func (s *Server) foldersPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	v := view{Title: "Folders", Session: sess, App: "settings", SettingsTab: "folders", Notice: notices[r.URL.Query().Get("n")]}
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		var err error
		v.Folders, err = st.Folders(r.Context())
		return err
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	if settings, err := s.folderRetentions(r.Context(), sess); err == nil {
		byName := make(map[string]int, len(settings))
		for _, setting := range settings {
			byName[setting.Name] = setting.Days
		}
		for i := range v.Folders {
			v.Folders[i].RetentionDays = byName[v.Folders[i].Name]
		}
	}
	s.render(w, "folders.html", http.StatusOK, v)
}

func (s *Server) foldersSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.pages.forgetRaw(sess.ID) // a renamed or recreated folder reuses UIDs
	op := r.PostFormValue("op")
	name := strings.TrimSpace(r.PostFormValue("name"))
	target := r.PostFormValue("folder")
	parent := r.PostFormValue("parent")
	if op != "delete" && !folderNameRE.MatchString(name) {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Folder names can't be empty or contain / . \\ % * or quotes.")
		return
	}
	notice := ""
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
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
		s.renderProblem(w, r, sess, http.StatusBadRequest, "Inbox, Drafts, Sent, Archive, Junk, Quarantine and Trash can't be renamed or deleted.")
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
	totals := map[string]uint32{}
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		for _, f := range folders {
			counts[f.Name] = f.Unread
			totals[f.Name] = f.Total
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
	_ = json.NewEncoder(w).Encode(map[string]any{"unread": counts, "total": totals, "time": time.Now().Unix()})
}
