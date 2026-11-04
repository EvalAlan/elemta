package webmail

import (
	"net/http"
	"net/url"
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
	if !strings.Contains(page, `class="inbox-tabs"`) || !strings.Contains(page, `aria-current="page">Primary`) {
		t.Fatal("inbox lacks the tab bar, or Primary isn't current")
	}
	if !strings.Contains(page, `Promotions <span class="tab-count mono">3</span>`) {
		t.Fatal("tab unread count missing")
	}
	if h.store.lastQuery.Category != "primary" {
		t.Fatalf("list category = %q, want primary", h.store.lastQuery.Category)
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
