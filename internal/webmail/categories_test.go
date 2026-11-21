package webmail

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailcategory"
)

func TestInboxTabs(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	csrf := h.login()

	// Off by default: no tab bar, and the list isn't narrowed.
	_, page := h.get("/mail?f=INBOX")
	if strings.Contains(page, `class="inbox-tabs"`) {
		t.Fatal("tabs shown before the user turned them on")
	}
	if h.store.lastQuery.Category != "" {
		t.Fatalf("list narrowed to %q with tabs off", h.store.lastQuery.Category)
	}

	// Turning them on sorts the existing inbox.
	h.store.raw[7] = []byte("From: Shop <deals@shop.example>\r\nSubject: Sale\r\nList-Unsubscribe: <https://x>\r\nX-Mailchimp-Campaign: a\r\n\r\nbuy\r\n")
	resp := h.post("/settings", url.Values{"csrf": {csrf}, "inbox_tabs": {"1"}, "clock": {"24"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "inbox-sorted") {
		t.Fatalf("enable tabs: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !h.store.flags[7][mailcategory.Promotions.Keyword()] {
		t.Fatal("existing mail wasn't sorted when tabs were turned on")
	}

	// The inbox opens on Primary, with unread counts on the tabs.
	_, page = h.get("/mail?f=INBOX")
	if !strings.Contains(page, `class="inbox-tabs"`) || !regexp.MustCompile(`data-category="primary"[^>]*aria-current="page">.*?<span class="tab-label">Primary</span>`).MatchString(page) {
		t.Fatal("inbox lacks the tab bar, or Primary isn't current")
	}
	if !strings.Contains(page, `<span class="tab-label">Promotions</span> <span class="tab-count nums">3</span>`) {
		t.Fatal("tab unread count missing")
	}
	if h.store.lastQuery.Category != "primary" {
		t.Fatalf("list category = %q, want primary", h.store.lastQuery.Category)
	}
	// The live count check carries the tabs' counts when the page asks,
	// so a tab's count rises as mail arrives in it without a reload.
	if _, body := h.get("/api/counts?tabs=1"); !strings.Contains(body, `"tabs":{"primary":1,"promotions":3}`) {
		t.Fatalf("counts lack the tabs: %s", body)
	}
	if _, body := h.get("/api/counts"); strings.Contains(body, `"tabs"`) {
		t.Fatalf("tab counts sent unasked: %s", body)
	}
	h.get("/mail?f=INBOX&tab=social")
	if h.store.lastQuery.Category != "social" {
		t.Fatalf("list category = %q, want social", h.store.lastQuery.Category)
	}
	// A search looks across every tab; other folders have none.
	h.get("/mail?f=INBOX&tab=social&q=invoice")
	if h.store.lastQuery.Category != "" {
		t.Fatalf("search narrowed to %q", h.store.lastQuery.Category)
	}
	_, page = h.get("/mail?f=Sent")
	if strings.Contains(page, `class="inbox-tabs"`) {
		t.Fatal("tabs shown outside the inbox")
	}

	// The heading counts the inbox's unread mail across every tab, not the
	// open tab's messages: an empty Primary showed "Inbox 0" over full tabs.
	h.store.folders[0].Unread = 24
	_, page = h.get("/mail?f=INBOX")
	if !strings.Contains(page, `data-unread-of="INBOX">24 unread</span>`) {
		t.Fatal("heading lacks the inbox's unread count across tabs")
	}
	// Mark all read from the list: the open tab, or the whole inbox.
	_, page = h.get("/mail?f=INBOX&tab=promotions")
	if !strings.Contains(page, `form="mark-read" name="tab" value="promotions">Mark Promotions read`) || !strings.Contains(page, `form="mark-read" name="tab" value="">Mark the whole inbox read`) {
		t.Fatal("list lacks the mark-read menu for the tab and the inbox")
	}
	read := url.Values{"csrf": {csrf}, "f": {"INBOX"}, "op": {"readall"}, "tab": {"promotions"}, "back": {"/mail?f=INBOX&tab=promotions"}}
	if resp := h.post("/mail/action", read); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=tab-read") {
		t.Fatalf("mark tab read: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	read.Set("tab", "")
	if resp := h.post("/mail/action", read); !strings.Contains(resp.Header.Get("Location"), "n=all-read") {
		t.Fatalf("mark inbox read: %q", resp.Header.Get("Location"))
	}
	read.Set("tab", "spam")
	if resp := h.post("/mail/action", read); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown tab: %d, want 400", resp.StatusCode)
	}
	if got := strings.Join(h.store.allRead, " "); got != "INBOX#promotions INBOX" {
		t.Fatalf("marked read: %q", got)
	}

	// Moving a message to a tab swaps its keyword and remembers the sender.
	form := url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"category"}, "category": {"updates"}, "tab": {"promotions"}, "back": {"/mail?f=INBOX&tab=promotions&uid=7"}}
	resp = h.post("/mail/action", form)
	if resp.StatusCode != http.StatusSeeOther || strings.Contains(resp.Header.Get("Location"), "uid=") {
		t.Fatalf("move to tab: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if h.store.flags[7][mailcategory.Promotions.Keyword()] || !h.store.flags[7][mailcategory.Updates.Keyword()] {
		t.Fatalf("keywords after move: %v", h.store.flags[7])
	}
	if len(f.categories) != 1 || f.categories[0] != (categoryRule{"priya@northwind.example", "updates"}) {
		t.Fatalf("rules after move: %+v", f.categories)
	}
	form.Set("category", "spam")
	if resp := h.post("/mail/action", form); resp.StatusCode < 400 {
		t.Fatalf("unknown category accepted: %d", resp.StatusCode)
	}

	// Settings lists the rule and can remove it.
	_, page = h.get("/settings")
	if !strings.Contains(page, `id="tabs"`) || !strings.Contains(page, "priya@northwind.example") {
		t.Fatal("settings lacks the tab rules")
	}
	resp = h.post("/settings/tab-rules/remove", url.Values{"csrf": {csrf}, "sender": {"priya@northwind.example"}})
	if resp.StatusCode != http.StatusSeeOther || len(f.categories) != 0 {
		t.Fatalf("remove rule: %d %+v", resp.StatusCode, f.categories)
	}
}
