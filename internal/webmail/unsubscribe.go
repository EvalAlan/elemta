package webmail

// Unsubscribe from newsletters and mailing lists, from the message itself.
//
// A sender that wants to be left alone gives a List-Unsubscribe header
// (RFC 2369): an https page, a mailto address, or both. RFC 8058 adds
// one-click: with List-Unsubscribe-Post the https address takes a plain POST
// and needs nothing from the person. The webmail uses the best one the
// message offers:
//
//  1. One-click, posted by this server. Only for https, only when the
//     message passed DKIM (RFC 8058 has the sender sign these headers, so an
//     unsigned one could be anyone's), and only through the image proxy's
//     client, which reaches public addresses alone.
//  2. A mailto address: a short message from the user's own address.
//  3. A web page, opened in the user's browser, never fetched from here.
//
// The addresses are always read again from the stored message, never taken
// from the form, so a crafted post can't aim this server at anything.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type unsubMethod string

const (
	unsubOneClick unsubMethod = "one-click"
	unsubMail     unsubMethod = "mail"
	unsubLink     unsubMethod = "link"
)

// unsubTarget is how to unsubscribe from one message's sender.
type unsubTarget struct {
	Method unsubMethod
	// URL is the https (or, for a page, http) address; for one-click it is
	// where the POST goes.
	URL string
	// MailTo, Subject and Body are the mailto address and what to send.
	MailTo, Subject, Body string
}

// maxUnsubURL bounds the addresses taken from a header.
const maxUnsubURL = 2048

// listURIs reads the angle-bracketed URIs of a List-Unsubscribe header.
func listURIs(h string) []string {
	var out []string
	for {
		i := strings.IndexByte(h, '<')
		if i < 0 {
			return out
		}
		j := strings.IndexByte(h[i+1:], '>')
		if j < 0 {
			return out
		}
		// Folding can leave whitespace inside the brackets (RFC 2369 §2).
		uri := strings.Join(strings.Fields(h[i+1:i+1+j]), "")
		if uri != "" && len(uri) <= maxUnsubURL {
			out = append(out, uri)
		}
		h = h[i+1+j+1:]
	}
}

// unsubscribeTarget picks how to unsubscribe from m, if it says how.
func unsubscribeTarget(m *Message) (unsubTarget, bool) {
	var web, secure string
	var mailTo *url.URL
	for _, raw := range listURIs(m.ListUnsubscribe) {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			if u.Host == "" || u.User != nil {
				continue
			}
			if web == "" {
				web = u.String()
			}
			if secure == "" && strings.EqualFold(u.Scheme, "https") {
				secure = u.String()
			}
		case "mailto":
			if mailTo == nil && u.Opaque != "" {
				mailTo = u
			}
		}
	}
	oneClick := strings.EqualFold(strings.Join(strings.Fields(m.ListUnsubscribePost), ""), "List-Unsubscribe=One-Click")
	switch {
	case secure != "" && oneClick && dkimPassed(m.AuthResults):
		return unsubTarget{Method: unsubOneClick, URL: secure}, true
	case mailTo != nil:
		addr, err := url.PathUnescape(mailTo.Opaque)
		// One address only: a list could otherwise have the user mail many.
		if err == nil && strings.Count(addr, "@") == 1 && !strings.ContainsAny(addr, ",; \r\n") {
			q := mailTo.Query()
			t := unsubTarget{Method: unsubMail, MailTo: addr, Subject: q.Get("subject"), Body: q.Get("body"), URL: web}
			if t.Subject == "" {
				t.Subject = "unsubscribe"
			}
			if t.Body == "" {
				t.Body = "unsubscribe"
			}
			if strings.ContainsAny(t.Subject, "\r\n") || len(t.Subject) > 200 || len(t.Body) > 2000 {
				break
			}
			return t, true
		}
	}
	if web != "" {
		return unsubTarget{Method: unsubLink, URL: web}, true
	}
	return unsubTarget{}, false
}

// dkimPassed is whether this server's own check found a valid signature.
func dkimPassed(authResults string) bool {
	return slices.ContainsFunc(parseAuthResults(authResults), func(c AuthCheck) bool { return c.Method == "DKIM" && c.Pass })
}

// listKey names the subscription: the list's id when it has one, which
// stays the same when a list changes its sending address, else the sender.
func listKey(m *Message) string {
	if id := strings.TrimSpace(m.ListID); id != "" {
		if i, j := strings.LastIndexByte(id, '<'), strings.LastIndexByte(id, '>'); i >= 0 && j > i {
			id = id[i+1 : j]
		}
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			return "list:" + id
		}
	}
	if len(m.From) > 0 {
		return strings.ToLower(m.From[0].Email)
	}
	return ""
}

// unsubRecord remembers an unsubscribe, so the message says so and can
// point out a sender who keeps writing.
type unsubRecord struct {
	Key string    `json:"key"`
	At  time.Time `json:"at"`
}

// maxUnsubRecords keeps the settings object small; the oldest go first.
const maxUnsubRecords = 500

func (p Settings) unsubscribedAt(key string) (time.Time, bool) {
	for _, r := range p.Unsubscribed {
		if r.Key == key {
			return r.At, true
		}
	}
	return time.Time{}, false
}

func (p *Settings) noteUnsubscribed(key string, at time.Time) {
	p.Unsubscribed = slices.DeleteFunc(p.Unsubscribed, func(r unsubRecord) bool { return r.Key == key })
	p.Unsubscribed = append(p.Unsubscribed, unsubRecord{Key: key, At: at})
	if n := len(p.Unsubscribed) - maxUnsubRecords; n > 0 {
		p.Unsubscribed = p.Unsubscribed[n:]
	}
}

// stillSendingAfter is how long a sender gets to act on an unsubscribe
// before the message suggests blocking them. RFC 8058 asks for two days.
const stillSendingAfter = 3 * 24 * time.Hour

// unsubView is the newsletter bar over a message.
type unsubView struct {
	Method unsubMethod
	Sender string
	// Sender's address, for blocking them.
	Address string
	URL     string
	MailTo  string
	// Action is where the bar's form posts, naming this message.
	Action string
	// Done is the day the user unsubscribed, if they have.
	Done string
	// Still is set when this message came well after that.
	Still bool
}

// unsubFor is the bar for msg, or nil. Junk gets none: unsubscribing from
// spam tells the spammer the address is read.
func (s *Server) unsubFor(sess *Session, msg *Message, folders []Folder) *unsubView {
	if sess.AdminActor != "" || len(msg.From) == 0 {
		return nil
	}
	for _, role := range []Role{RoleDrafts, RoleSent, RoleJunk, RoleQuarantine} {
		if isRoleIn(msg.Folder, folders, role) {
			return nil
		}
	}
	t, ok := unsubscribeTarget(msg)
	if !ok {
		return nil
	}
	v := &unsubView{
		Method: t.Method, Sender: msg.From[0].Label(), Address: msg.From[0].Email, URL: t.URL, MailTo: t.MailTo,
		Action: "/mail/unsubscribe?" + url.Values{"f": {msg.Folder}, "uid": {strconv.FormatUint(uint64(msg.UID), 10)}}.Encode(),
	}
	if at, ok := s.prefsCached(sess).unsubscribedAt(listKey(msg)); ok {
		v.Done = at.In(s.loc(sess)).Format("2 Jan 2006")
		v.Still = msg.Date.After(at.Add(stillSendingAfter))
	}
	return v
}

// unsubscriber posts one-click unsubscribes and limits how many.
type unsubscriber struct {
	client *http.Client
	mu     sync.Mutex
	limits map[string]*rate.Limiter
}

func newUnsubscriber() *unsubscriber {
	return &unsubscriber{client: newImageClient(publicDialControl), limits: map[string]*rate.Limiter{}}
}

// allow spaces out one user's unsubscribes: ten at once, then one every
// few seconds, so the Subscriptions page can't be turned into a flood of
// requests from this server.
func (u *unsubscriber) allow(user string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	l, ok := u.limits[user]
	if !ok {
		if len(u.limits) > 10000 {
			clear(u.limits)
		}
		l = rate.NewLimiter(rate.Every(3*time.Second), 10)
		u.limits[user] = l
	}
	return l.Allow()
}

var errUnsubRefused = errors.New("webmail: the sender didn't accept the unsubscribe")

// oneClick sends the RFC 8058 POST.
func (u *unsubscriber) oneClick(ctx context.Context, target string) error {
	if _, err := checkImageURL(target); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// #nosec G704 -- the address is the message's own, re-read server side, https only, and the client's dial control admits public addresses alone
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("List-Unsubscribe=One-Click"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Elemta-Webmail (List-Unsubscribe-Post)")
	resp, err := u.client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%w: HTTP %d", errUnsubRefused, resp.StatusCode)
	}
	return nil
}

// unsubscribeSubmit is POST /mail/unsubscribe?f=…&uid=…. With op=mark it
// only records that the user opened the sender's page (app.js sends it).
func (s *Server) unsubscribeSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if sess.AdminActor != "" {
		http.Error(w, "Unsubscribing isn't available here.", http.StatusForbidden)
		return
	}
	_, _, raw, err := s.loadMessage(r, sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	msg, err := parseMessage(raw)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	t, ok := unsubscribeTarget(msg)
	key := listKey(msg)
	if !ok || key == "" {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "This message doesn't say how to unsubscribe.")
		return
	}
	back := localBack(r.PostFormValue("back"), "/mail")
	if r.PostFormValue("op") == "mark" {
		if t.Method == unsubLink {
			s.recordUnsubscribe(r.Context(), sess, key)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if t.Method == unsubLink {
		s.renderProblem(w, r, sess, http.StatusBadRequest, "This sender unsubscribes on their own web page.")
		return
	}
	if !s.unsub.allow(sess.User) {
		s.renderProblem(w, r, sess, http.StatusTooManyRequests, "That's a lot of unsubscribing at once. Wait a minute and try again.")
		return
	}
	notice := "unsubscribed"
	switch t.Method {
	case unsubOneClick:
		err = s.unsub.oneClick(r.Context(), t.URL)
	case unsubMail:
		notice = "unsubscribe-sent"
		err = s.submitDraft(r.Context(), sess, &Draft{
			From: Address{Email: sess.Address}, To: []Address{{Email: t.MailTo}}, Subject: t.Subject, Text: t.Body,
		})
	}
	if err != nil {
		s.log.Warn("webmail: unsubscribe", "user", sess.User, "method", string(t.Method), "error", err)
		redirectLocal(w, r, setParam(back, "n", "unsubscribe-failed"))
		return
	}
	s.recordUnsubscribe(r.Context(), sess, key)
	redirectLocal(w, r, setParam(back, "n", notice))
}

// recordUnsubscribe remembers it. A failure to save only loses the note.
func (s *Server) recordUnsubscribe(ctx context.Context, sess *Session, key string) {
	p := s.prefs(ctx, sess)
	p.noteUnsubscribed(key, s.now())
	if err := s.savePrefs(ctx, sess, p); err != nil {
		s.log.Warn("webmail: record unsubscribe", "user", sess.User, "error", err)
	}
}
