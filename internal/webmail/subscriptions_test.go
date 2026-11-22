package webmail

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGroupSubscriptions(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 9, 0, 0, 0, time.UTC) }
	shop := Address{Name: "Shop", Email: "News@shop.example"}
	club := Address{Name: "Club", Email: "club@lists.example"}
	rows := groupSubscriptions(map[string][]BulkMessage{
		"INBOX": {
			{UID: 1, From: shop, Date: day(1), Seen: true, ListUnsubscribe: "<https://shop.example/old>"},
			{UID: 2, From: shop, Date: day(9), ListUnsubscribe: "<mailto:u@shop.example>"},
			{UID: 3, From: club, Date: day(5), Seen: true, ListID: "<club.lists.example>"},
		},
		"Archive": {{UID: 40, From: shop, Date: day(3), Seen: true}},
	})
	if len(rows) != 2 || rows[0].Address != "news@shop.example" || rows[1].Address != "club@lists.example" {
		t.Fatalf("rows = %+v", rows)
	}
	s := rows[0]
	// The newest message decides how to unsubscribe.
	if s.Count != 3 || s.Unread != 1 || s.UID != 2 || s.Folder != "INBOX" || s.Method != unsubMail || s.MailTo != "u@shop.example" || !s.Last.Equal(day(9)) {
		t.Errorf("shop row = %+v", s)
	}
	if rows[1].Method != "" || rows[1].key() != "list:club.lists.example" {
		t.Errorf("club row = %+v key %q", rows[1], rows[1].key())
	}
}

func addSubscriptionMail(h *harness) {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	for i, uid := range []uint32{21, 22, 23} {
		h.store.raw[uid] = []byte(newsletter("<https://shop.example/prefs>", "", ""))
		h.store.messages["INBOX"] = append(h.store.messages["INBOX"], Summary{UID: uid, From: []Address{{Name: "Shop News", Email: "news@shop.example"}}, Date: time.Now().Add(time.Duration(i) * time.Hour)})
	}
	h.store.folders = append(h.store.folders, Folder{Name: "Archive", Display: "Archive", Role: RoleArchive, Selectable: true})
}

func TestSubscriptionsPage(t *testing.T) {
	h := newHarness(t)
	addSubscriptionMail(h)
	csrf := h.login()

	_, page := h.get("/settings/subscriptions")
	for _, want := range []string{"<h1>Subscriptions</h1>", "news@shop.example", "3 messages", `href="https://shop.example/prefs"`, `href="/settings/subscriptions" aria-current="page"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	// The message the user opened isn't a newsletter, so isn't listed.
	if strings.Contains(page, "priya@northwind.example") {
		t.Error("ordinary mail listed")
	}

	resp := h.post("/settings/subscriptions", url.Values{"csrf": {csrf}, "sender": {"News@Shop.example"}, "op": {"archive"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=sender-archived") {
		t.Fatalf("archive all = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.store.mu.Lock()
	moved := len(h.store.moved)
	_, priyaMoved := h.store.moved[7]
	h.store.mu.Unlock()
	if moved != 3 || priyaMoved {
		t.Errorf("moved %v", h.store.moved)
	}

	resp = h.post("/settings/subscriptions", url.Values{"csrf": {csrf}, "sender": {"news@shop.example"}, "op": {"tab"}, "category": {"promotions"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=sender-tab") {
		t.Fatalf("tab = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := h.post("/settings/subscriptions", url.Values{"csrf": {csrf}, "sender": {"not an address"}, "op": {"delete"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad sender = %d", resp.StatusCode)
	}
}

// Unsubscribing from the page is remembered there, even though the list
// itself is cached.
func TestSubscriptionsShowUnsubscribed(t *testing.T) {
	h := newHarness(t)
	addSubscriptionMail(h)
	csrf := h.login()
	if _, page := h.get("/settings/subscriptions"); strings.Contains(page, "Unsubscribed ") {
		t.Fatal("marked unsubscribed before anything happened")
	}
	if resp := h.post("/mail/unsubscribe?f=INBOX&uid=23", url.Values{"csrf": {csrf}, "op": {"mark"}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("mark = %d", resp.StatusCode)
	}
	if _, page := h.get("/settings/subscriptions"); !strings.Contains(page, "Unsubscribed ") {
		t.Error("page doesn't show the unsubscribe")
	}
}
