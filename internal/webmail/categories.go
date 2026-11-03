package webmail

// Inbox tabs: Primary, Social, Promotions, Updates and Forums.
//
// The mailbox service classifies mail as it is delivered and marks each
// message with a hidden keyword (internal/mailcategory). The webmail shows
// the keywords as tabs over the inbox. Moving a message to another tab
// changes its keyword and records the sender with the mailbox service, so
// the next message from them is filed the same way.
//
// Mail that arrived before categories existed has no keyword and would all
// sit in Primary. Turning the tabs on, or Sort now in Settings, classifies
// the most recent of it here, with the same classifier and the user's rules.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailcategory"
	"github.com/emersion/go-imap/v2"
)

// categorizeLimit bounds how many existing inbox messages one Sort now
// reads. Only headers are fetched, a few kilobytes each.
const categorizeLimit = 5000

// categoryCriteria narrows a search to one category.
func categoryCriteria(c *imap.SearchCriteria, cat mailcategory.Category) {
	if cat == mailcategory.Primary {
		for _, k := range mailcategory.Keywords() {
			c.NotFlag = append(c.NotFlag, imap.Flag(k))
		}
		return
	}
	c.Flag = append(c.Flag, imap.Flag(cat.Keyword()))
}

func (s *imapStore) CategoryUnread(ctx context.Context, folder string) (map[string]int, error) {
	if _, err := s.syncFolder(folder); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, cat := range mailcategory.All {
		c := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen, imap.FlagDeleted}}
		categoryCriteria(c, cat)
		data, err := s.c.UIDSearch(c, &imap.SearchOptions{ReturnCount: true}).Wait()
		if err != nil {
			return nil, fmt.Errorf("webmail: count %s: %w", cat.Name(), err)
		}
		// Servers without ESEARCH ignore RETURN and send the UIDs.
		n := int(data.Count)
		if n == 0 {
			n = len(data.AllUIDs())
		}
		out[cat.Name()] = n
	}
	return out, nil
}

func (s *imapStore) Senders(ctx context.Context, folder string, uids []uint32) (map[uint32]string, error) {
	out := map[uint32]string{}
	if len(uids) == 0 {
		return out, nil
	}
	if _, err := s.selectFolder(folder); err != nil {
		return nil, err
	}
	msgs, err := s.c.Fetch(uidSet(uids), &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return nil, fmt.Errorf("webmail: fetch senders: %w", err)
	}
	for _, m := range msgs {
		if m.Envelope != nil && len(m.Envelope.From) > 0 {
			out[uint32(m.UID)] = strings.ToLower(m.Envelope.From[0].Addr())
		}
	}
	return out, nil
}

var headerSection = &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}

func (s *imapStore) Categorize(ctx context.Context, folder string, limit int, overrides mailcategory.Overrides) (int, error) {
	if _, err := s.syncFolder(folder); err != nil {
		return 0, err
	}
	c := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagDeleted}}
	categoryCriteria(c, mailcategory.Primary)
	data, err := s.c.UIDSearch(c, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("webmail: search uncategorised: %w", err)
	}
	var uids []uint32
	for _, u := range data.AllUIDs() {
		uids = append(uids, uint32(u))
	}
	// Newest first: if there are more than the limit, the recent mail is
	// what the user will look at.
	slices.Sort(uids)
	if len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	byKeyword := map[string][]uint32{}
	const batch = 200
	for start := 0; start < len(uids); start += batch {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		chunk := uids[start:min(start+batch, len(uids))]
		msgs, err := s.c.Fetch(uidSet(chunk), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{headerSection}}).Collect()
		if err != nil {
			return 0, fmt.Errorf("webmail: fetch headers: %w", err)
		}
		for _, m := range msgs {
			if k := mailcategory.Classify(m.FindBodySection(headerSection), overrides).Keyword(); k != "" {
				byKeyword[k] = append(byKeyword[k], uint32(m.UID))
			}
		}
	}
	n := 0
	for k, set := range byKeyword {
		if err := s.SetFlags(ctx, folder, set, []string{k}, true); err != nil {
			return n, err
		}
		n += len(set)
	}
	return n, nil
}

// setCategory moves messages to one tab: clears every other category
// keyword and sets this one's.
func setCategory(ctx context.Context, st Mailstore, folder string, uids []uint32, cat mailcategory.Category) error {
	var others []string
	for _, k := range mailcategory.Keywords() {
		if k != cat.Keyword() {
			others = append(others, k)
		}
	}
	if err := st.SetFlags(ctx, folder, uids, others, false); err != nil {
		return err
	}
	if k := cat.Keyword(); k != "" {
		return st.SetFlags(ctx, folder, uids, []string{k}, true)
	}
	return nil
}

// categoryRule mirrors the mailbox service's CategoryRule.
type categoryRule struct {
	Sender   string `json:"sender"`
	Category string `json:"category"`
}

// Label is the rule's tab, as Settings shows it.
func (r categoryRule) Label() string {
	c, _ := mailcategory.Parse(r.Category)
	return c.Label()
}

// categoryRules returns the user's rules, or nil when the mailbox service
// isn't reachable from here (or an administrator is looking).
func (s *Server) categoryRules(ctx context.Context, sess *Session) ([]categoryRule, error) {
	if s.security == nil || sess.AdminActor != "" {
		return nil, nil
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []categoryRule
	if err := s.security.call(ctx, http.MethodGet, "/v1/security/categories", sess.User, pw, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) categoryOverrides(ctx context.Context, sess *Session) mailcategory.Overrides {
	rules, err := s.categoryRules(ctx, sess)
	if err != nil {
		s.log.Warn("webmail: read category rules", "user", sess.User, "error", err)
	}
	out := mailcategory.Overrides{}
	for _, r := range rules {
		c, _ := mailcategory.Parse(r.Category)
		out[r.Sender] = c
	}
	return out
}

// learnCategory records each sender's new tab. Failing to record one only
// means the next message is classified as before, so it is logged, not shown.
func (s *Server) learnCategory(ctx context.Context, sess *Session, senders []string, cat mailcategory.Category) {
	if s.security == nil || sess.AdminActor != "" {
		return
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, sender := range senders {
		in := categoryRule{Sender: sender, Category: cat.Name()}
		if err := s.security.call(ctx, http.MethodPost, "/v1/security/categories", sess.User, pw, in, nil); err != nil {
			s.log.Warn("webmail: record category rule", "user", sess.User, "error", err)
			return
		}
	}
}

// uniqueSenders lists the distinct sender addresses, up to max. Moving a
// hundred newsletters at once shouldn't make a hundred API calls, and the
// first few senders are what the user meant.
func uniqueSenders(byUID map[uint32]string, max int) []string {
	var out []string
	for _, a := range byUID {
		if a != "" && strings.Contains(a, "@") && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// InboxTab is one tab over the inbox, for the template.
type InboxTab struct {
	Name, Label string
	Unread      int
	Active      bool
	URL         string
}

// inboxTabs builds the tab bar for the list, or nil when it doesn't apply.
func (s *Server) inboxTabs(ctx context.Context, st Mailstore, ls listState) []InboxTab {
	unread, err := st.CategoryUnread(ctx, ls.Folder)
	if err != nil {
		s.log.Warn("webmail: count inbox tabs", "error", err)
		unread = map[string]int{}
	}
	var out []InboxTab
	for _, c := range mailcategory.All {
		t := ls
		t.Tab, t.Page = c.Name(), 1
		out = append(out, InboxTab{Name: c.Name(), Label: c.Label(), Unread: unread[c.Name()], Active: ls.Tab == c.Name(), URL: t.URL()})
	}
	return out
}

// CategoryOptions lists the tabs a message can be moved to.
func (v view) CategoryOptions() []InboxTab {
	var out []InboxTab
	for _, c := range mailcategory.All {
		out = append(out, InboxTab{Name: c.Name(), Label: c.Label()})
	}
	return out
}

func (s *Server) categorizeSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	if _, err := s.categorizeInbox(r.Context(), sess); err != nil {
		s.log.Warn("webmail: sort inbox", "user", sess.User, "error", err)
		http.Redirect(w, r, "/settings?n=categorize-failed#tabs", http.StatusSeeOther)
		return
	}
	s.pages.forgetRaw(sess.ID)
	http.Redirect(w, r, "/settings?n=inbox-sorted#tabs", http.StatusSeeOther)
}

func (s *Server) categorizeInbox(ctx context.Context, sess *Session) (int, error) {
	overrides := s.categoryOverrides(ctx, sess)
	n := 0
	err := s.sessions.withMailStore(ctx, sess, s.dial, func(st Mailstore) error {
		var err error
		n, err = st.Categorize(ctx, "INBOX", categorizeLimit, overrides)
		return err
	})
	return n, err
}

// categoryRuleRemove deletes one rule from Settings.
func (s *Server) categoryRuleRemove(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.security == nil || sess.AdminActor != "" {
		http.Error(w, "Tab rules can't be changed here.", http.StatusForbidden)
		return
	}
	rules, err := s.categoryRules(r.Context(), sess)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	sender := strings.ToLower(strings.TrimSpace(r.PostFormValue("sender")))
	rules = slices.DeleteFunc(rules, func(x categoryRule) bool { return x.Sender == sender })
	if rules == nil {
		rules = []categoryRule{} // an empty list clears; null would be refused
	}
	pw, err := s.sessions.password(sess)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.security.call(ctx, http.MethodPut, "/v1/security/categories", sess.User, pw, rules, nil); err != nil {
		if errors.Is(err, errSecurityInput) {
			s.renderProblem(w, r, sess, http.StatusBadRequest, strings.TrimSpace(strings.TrimPrefix(err.Error(), errSecurityInput.Error()+":")))
			return
		}
		s.fail(w, r, sess, err)
		return
	}
	http.Redirect(w, r, "/settings?n=tab-rule-removed#tabs", http.StatusSeeOther)
}
