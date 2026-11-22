package webmail

// Settings > Subscriptions: the newsletters and mailing lists in the inbox
// and archive, busiest first, each with Unsubscribe (unsubscribe.go),
// Archive all, Delete all, a tab to always file it under, and Block.
//
// It reads only the headers of messages that carry list headers, the newest
// few thousand, and keeps the result on the session for a few minutes:
// finding them is a search and a header fetch per folder, quick for a person
// opening the page but not something to repeat on every action.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailcategory"
	"github.com/emersion/go-imap/v2"
)

// BulkMessage is one message carrying mailing-list headers.
type BulkMessage struct {
	UID                 uint32
	From                Address
	Date                time.Time
	Seen                bool
	ListID              string
	ListUnsubscribe     string
	ListUnsubscribePost string
	AuthResults         string
}

// subscriptionScan bounds the messages read per folder.
const subscriptionScan = 3000

// subscriptionsFresh is how long the page's list is reused.
const subscriptionsFresh = 10 * time.Minute

var bulkHeaderSection = &imap.FetchItemBodySection{
	Specifier: imap.PartSpecifierHeader, Peek: true,
	HeaderFields: []string{"From", "Date", "List-Id", "List-Unsubscribe", "List-Unsubscribe-Post", "Authentication-Results"},
}

func (s *imapStore) BulkMessages(ctx context.Context, folder string, limit int) ([]BulkMessage, error) {
	if _, err := s.syncFolder(folder); err != nil {
		return nil, err
	}
	c := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagDeleted},
		Or: [][2]imap.SearchCriteria{{
			{Header: []imap.SearchCriteriaHeaderField{{Key: "List-Unsubscribe"}}},
			{Header: []imap.SearchCriteriaHeaderField{{Key: "List-Id"}}},
		}},
	}
	data, err := s.c.UIDSearch(c, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("webmail: search list mail: %w", err)
	}
	var uids []uint32
	for _, u := range data.AllUIDs() {
		uids = append(uids, uint32(u))
	}
	slices.Sort(uids)
	if len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	var out []BulkMessage
	const batch = 200
	for start := 0; start < len(uids); start += batch {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk := uids[start:min(start+batch, len(uids))]
		msgs, err := s.c.Fetch(uidSet(chunk), &imap.FetchOptions{UID: true, Flags: true, BodySection: []*imap.FetchItemBodySection{bulkHeaderSection}}).Collect()
		if err != nil {
			return nil, fmt.Errorf("webmail: fetch list headers: %w", err)
		}
		for _, m := range msgs {
			b, ok := bulkMessage(m.FindBodySection(bulkHeaderSection))
			if !ok {
				continue
			}
			b.UID = uint32(m.UID)
			b.Seen = slices.Contains(m.Flags, imap.FlagSeen)
			out = append(out, b)
		}
	}
	return out, nil
}

// bulkMessage reads the list headers fetched for a message.
func bulkMessage(header []byte) (BulkMessage, bool) {
	r, err := readMail(append(slices.Clip(header), "\r\n"...))
	if err != nil {
		return BulkMessage{}, false
	}
	defer func() { _ = r.Close() }()
	h := r.Header
	from := headerAddresses(h, "From")
	if len(from) == 0 {
		return BulkMessage{}, false
	}
	b := BulkMessage{
		From: from[0], ListID: h.Get("List-Id"), ListUnsubscribe: h.Get("List-Unsubscribe"),
		ListUnsubscribePost: h.Get("List-Unsubscribe-Post"), AuthResults: h.Get("Authentication-Results"),
	}
	b.Date, _ = h.Date()
	return b, true
}

func (s *imapStore) UIDsFrom(ctx context.Context, folder, sender string) ([]uint32, error) {
	if _, err := s.syncFolder(folder); err != nil {
		return nil, err
	}
	data, err := s.c.UIDSearch(&imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagDeleted},
		Header:  []imap.SearchCriteriaHeaderField{{Key: "From", Value: sender}},
	}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("webmail: search sender: %w", err)
	}
	var uids []uint32
	for _, u := range data.AllUIDs() {
		uids = append(uids, uint32(u))
	}
	// SEARCH FROM matches a substring, so news@shop.example would also
	// find news@shop.example.evil; keep the exact sender only.
	from, err := s.Senders(ctx, folder, uids)
	if err != nil {
		return nil, err
	}
	sender = strings.ToLower(sender)
	return slices.DeleteFunc(uids, func(u uint32) bool { return from[u] != sender }), nil
}

// subscription is one sender's row on the page.
type subscription struct {
	Sender  string
	Address string
	ListID  string
	Count   int
	Unread  int
	Last    time.Time
	// Folder and UID are its newest message, which unsubscribing reads.
	Folder string
	UID    uint32
	Method unsubMethod
	URL    string
	MailTo string
	Done   time.Time
}

// Action is where the row's Unsubscribe posts.
func (s subscription) Action() string {
	return "/mail/unsubscribe?" + url.Values{"f": {s.Folder}, "uid": {strconv.FormatUint(uint64(s.UID), 10)}}.Encode()
}

// groupSubscriptions makes one row per sender address, busiest first.
func groupSubscriptions(byFolder map[string][]BulkMessage) []subscription {
	rows := map[string]*subscription{}
	newest := map[string]BulkMessage{}
	for folder, msgs := range byFolder {
		for _, m := range msgs {
			addr := strings.ToLower(m.From.Email)
			if addr == "" {
				continue
			}
			row, ok := rows[addr]
			if !ok {
				row = &subscription{Address: addr}
				rows[addr] = row
			}
			row.Count++
			if !m.Seen {
				row.Unread++
			}
			if !ok || m.Date.After(row.Last) {
				row.Last, row.Folder, row.UID = m.Date, folder, m.UID
				newest[addr] = m
			}
		}
	}
	out := make([]subscription, 0, len(rows))
	for addr, row := range rows {
		m := newest[addr]
		msg := &Message{From: []Address{m.From}, ListID: m.ListID, ListUnsubscribe: m.ListUnsubscribe, ListUnsubscribePost: m.ListUnsubscribePost, AuthResults: m.AuthResults}
		row.Sender, row.ListID = m.From.Label(), m.ListID
		if t, ok := unsubscribeTarget(msg); ok {
			row.Method, row.URL, row.MailTo = t.Method, t.URL, t.MailTo
		}
		out = append(out, *row)
	}
	slices.SortFunc(out, func(a, b subscription) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return b.Last.Compare(a.Last)
	})
	return out
}

type subscriptionsCache struct {
	rows []subscription
	at   time.Time
}

// subscriptionsView is the page.
type subscriptionsView struct {
	Rows    []subscription
	Tabs    []InboxTab
	Checked time.Time
}

func (s *Server) subscriptions(ctx context.Context, sess *Session, st Mailstore, refresh bool) ([]subscription, time.Time, error) {
	sess.subsMu.Lock()
	c := sess.subs
	sess.subsMu.Unlock()
	if c != nil && !refresh && time.Since(c.at) < subscriptionsFresh {
		return c.rows, c.at, nil
	}
	folders := []string{"INBOX"}
	if name, err := roleFolderName(ctx, st, RoleArchive); err == nil && name != "" {
		folders = append(folders, name)
	}
	byFolder := map[string][]BulkMessage{}
	for _, f := range folders {
		msgs, err := st.BulkMessages(ctx, f, subscriptionScan)
		if err != nil {
			return nil, time.Time{}, err
		}
		byFolder[f] = msgs
	}
	rows := groupSubscriptions(byFolder)
	now := time.Now()
	sess.subsMu.Lock()
	sess.subs = &subscriptionsCache{rows: rows, at: now}
	sess.subsMu.Unlock()
	return rows, now, nil
}

func (s *Server) forgetSubscriptions(sess *Session) {
	sess.subsMu.Lock()
	sess.subs = nil
	sess.subsMu.Unlock()
}

// subscriptionsPage is GET /settings/subscriptions.
func (s *Server) subscriptionsPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	q := r.URL.Query()
	sv := &subscriptionsView{}
	v := view{Title: "Subscriptions", Session: sess, App: "settings", SettingsTab: "subscriptions", Subscriptions: sv, Notice: notices[q.Get("n")]}
	if u, ok := decodeUndo(q.Get("undo"), time.Now()); ok && v.Notice != "" {
		v.Undo = &u
	}
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		folders, err := st.Folders(r.Context())
		if err != nil {
			return err
		}
		v.Folders = folders
		sv.Rows, sv.Checked, err = s.subscriptions(r.Context(), sess, st, q.Get("refresh") == "1")
		return err
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	// Unsubscribed ones show when it happened. The rows may be cached, so
	// this reads the record each time rather than at the scan.
	prefs := s.prefs(r.Context(), sess)
	sv.Rows = slices.Clone(sv.Rows)
	for i := range sv.Rows {
		sv.Rows[i].Done, _ = prefs.unsubscribedAt(sv.Rows[i].key())
	}
	for _, c := range mailcategory.All {
		sv.Tabs = append(sv.Tabs, InboxTab{Name: c.Name(), Label: c.Label()})
	}
	v.Loc = s.loc(sess)
	s.render(w, "subscriptions.html", http.StatusOK, v)
}

// key is the row's unsubscribe record, as listKey makes it.
func (s subscription) key() string {
	return listKey(&Message{ListID: s.ListID, From: []Address{{Email: s.Address}}})
}

// subscriptionsSubmit is POST /settings/subscriptions: archive, delete or
// file everything from one sender in the inbox.
func (s *Server) subscriptionsSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if sess.AdminActor != "" {
		http.Error(w, "Subscriptions can't be changed here.", http.StatusForbidden)
		return
	}
	sender := strings.ToLower(strings.TrimSpace(r.PostFormValue("sender")))
	if !strings.Contains(sender, "@") || strings.ContainsAny(sender, " \r\n\"") {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "That isn't a sender address.")
		return
	}
	op := r.PostFormValue("op")
	cat, catOK := mailcategory.Parse(r.PostFormValue("category"))
	var notice string
	var undo *undoMove
	err := s.sessions.withMailStore(r.Context(), sess, s.dial, func(st Mailstore) error {
		uids, err := st.UIDsFrom(r.Context(), "INBOX", sender)
		if err != nil {
			return err
		}
		switch op {
		case "archive":
			notice = "sender-archived"
			if len(uids) == 0 {
				return nil
			}
			dest, newUIDs, err := moveToRole(r.Context(), st, "INBOX", uids, RoleArchive)
			if len(newUIDs) > 0 {
				undo = &undoMove{From: dest, To: "INBOX", UIDs: newUIDs}
			}
			return err
		case "delete":
			notice = "sender-deleted"
			if len(uids) == 0 {
				return nil
			}
			return st.Delete(r.Context(), "INBOX", uids)
		case "tab":
			if !catOK {
				return ErrNotFound
			}
			notice = "sender-tab"
			if len(uids) > 0 {
				if err := setCategory(r.Context(), st, "INBOX", uids, cat); err != nil {
					return err
				}
			}
			s.learnCategory(r.Context(), sess, []string{sender}, cat)
			return nil
		}
		return ErrNotFound
	})
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	s.forgetSubscriptions(sess)
	back := "/settings/subscriptions?n=" + notice
	if undo != nil {
		back = setParam(back, "undo", undo.encode(time.Now()))
	}
	redirectLocal(w, r, back)
}
