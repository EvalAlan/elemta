package webmail

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newsletter(listUnsub, post, authResults string) string {
	h := "From: Shop News <news@shop.example>\r\nTo: user@example.com\r\nSubject: Deals\r\nDate: Mon, 23 Nov 2026 10:00:00 +0000\r\nMessage-ID: <n1@shop.example>\r\nList-Id: Shop deals <deals.shop.example>\r\n"
	if authResults != "" {
		h += "Authentication-Results: mx.example.com; " + authResults + "\r\n"
	}
	if listUnsub != "" {
		h += "List-Unsubscribe: " + listUnsub + "\r\n"
	}
	if post != "" {
		h += "List-Unsubscribe-Post: " + post + "\r\n"
	}
	return h + "Content-Type: text/plain\r\n\r\nBuy things.\r\n"
}

func TestUnsubscribeTarget(t *testing.T) {
	const dkim = "dkim=pass header.d=shop.example; spf=pass"
	for _, tc := range []struct {
		name, unsub, post, ar string
		want                  unsubTarget
		ok                    bool
	}{
		{"none", "", "", dkim, unsubTarget{}, false},
		{"one-click", "<https://shop.example/u?x=1>, <mailto:u@shop.example>", "List-Unsubscribe=One-Click", dkim,
			unsubTarget{Method: unsubOneClick, URL: "https://shop.example/u?x=1"}, true},
		// Unsigned headers could be anyone's, so no server-side POST.
		{"one-click unsigned", "<https://shop.example/u>, <mailto:u@shop.example?subject=stop>", "List-Unsubscribe=One-Click", "dkim=fail",
			unsubTarget{Method: unsubMail, MailTo: "u@shop.example", Subject: "stop", Body: "unsubscribe", URL: "https://shop.example/u"}, true},
		{"one-click needs https", "<http://shop.example/u>", "List-Unsubscribe=One-Click", dkim,
			unsubTarget{Method: unsubLink, URL: "http://shop.example/u"}, true},
		{"page only", "<https://shop.example/u>", "", dkim, unsubTarget{Method: unsubLink, URL: "https://shop.example/u"}, true},
		{"folded", "<https://shop.example/\r\n u>", "List-Unsubscribe = One-Click", dkim,
			unsubTarget{Method: unsubOneClick, URL: "https://shop.example/u"}, true},
		{"several mail recipients refused", "<mailto:a@shop.example,b@shop.example>", "", dkim, unsubTarget{}, false},
		{"other schemes ignored", "<javascript:alert(1)>, <ftp://shop.example/x>", "", dkim, unsubTarget{}, false},
	} {
		m := &Message{ListUnsubscribe: tc.unsub, ListUnsubscribePost: tc.post, AuthResults: "mx.example.com; " + tc.ar}
		got, ok := unsubscribeTarget(m)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: %+v %v, want %+v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestListKey(t *testing.T) {
	if got := listKey(&Message{ListID: "Shop deals <Deals.Shop.Example>"}); got != "list:deals.shop.example" {
		t.Errorf("list id key = %q", got)
	}
	if got := listKey(&Message{From: []Address{{Email: "News@Shop.example"}}}); got != "news@shop.example" {
		t.Errorf("sender key = %q", got)
	}
}

func TestNoteUnsubscribedKeepsTheNewest(t *testing.T) {
	var p Settings
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range maxUnsubRecords + 5 {
		p.noteUnsubscribed(strings.Repeat("x", i%3)+string(rune('a'+i%26))+time.Duration(i).String(), at)
	}
	if len(p.Unsubscribed) != maxUnsubRecords {
		t.Fatalf("kept %d", len(p.Unsubscribed))
	}
	p.noteUnsubscribed("list:again", at)
	p.noteUnsubscribed("list:again", at.Add(time.Hour))
	if got, _ := p.unsubscribedAt("list:again"); !got.Equal(at.Add(time.Hour)) || len(p.Unsubscribed) != maxUnsubRecords {
		t.Errorf("re-unsubscribing: at %v, %d kept", got, len(p.Unsubscribed))
	}
}

// openNewsletter puts a newsletter in the inbox as UID 9.
func openNewsletter(h *harness, raw string) {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	h.store.raw[9] = []byte(raw)
	h.store.messages["INBOX"] = append(h.store.messages["INBOX"], Summary{UID: 9, Subject: "Deals", From: []Address{{Name: "Shop News", Email: "news@shop.example"}}, Date: time.Now()})
}

func TestUnsubscribeOneClick(t *testing.T) {
	var posted []string
	shop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posted = append(posted, r.Method+" "+r.URL.Path+" "+string(b))
	}))
	defer shop.Close()
	old := imagePortAllowed
	imagePortAllowed = func(string) bool { return true }
	t.Cleanup(func() { imagePortAllowed = old })

	h := newHarness(t)
	h.server.unsub.client = newImageClient(func(string, string, syscall.RawConn) error { return nil })
	h.server.unsub.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: shop.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	openNewsletter(h, newsletter("<"+shop.URL+"/unsub/abc>", "List-Unsubscribe=One-Click", "dkim=pass header.d=shop.example"))
	csrf := h.login()

	_, page := h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, "data-unsub") || !strings.Contains(page, `action="/mail/unsubscribe?f=INBOX&amp;uid=9"`) {
		t.Fatalf("no unsubscribe bar:\n%s", page)
	}
	resp := h.post("/mail/unsubscribe?f=INBOX&uid=9", url.Values{"csrf": {csrf}, "back": {"/mail?f=INBOX&uid=9"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=unsubscribed") {
		t.Fatalf("unsubscribe = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(posted) != 1 || posted[0] != "POST /unsub/abc List-Unsubscribe=One-Click" {
		t.Fatalf("sender got %q", posted)
	}
	if _, page = h.get("/mail?f=INBOX&uid=9"); !strings.Contains(page, "You unsubscribed from Shop News on") {
		t.Errorf("bar doesn't say it's done:\n%s", page)
	}
}

func TestUnsubscribeRefusesPrivateAddresses(t *testing.T) {
	h := newHarness(t)
	// The real client: 127.0.0.1 is refused at dial time.
	openNewsletter(h, newsletter("<https://127.0.0.1/unsub>", "List-Unsubscribe=One-Click", "dkim=pass header.d=shop.example"))
	csrf := h.login()
	resp := h.post("/mail/unsubscribe?f=INBOX&uid=9", url.Values{"csrf": {csrf}})
	if !strings.Contains(resp.Header.Get("Location"), "n=unsubscribe-failed") {
		t.Fatalf("private address: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, page := h.get("/mail?f=INBOX&uid=9"); strings.Contains(page, "You unsubscribed") {
		t.Error("a failed unsubscribe was recorded")
	}
}

func TestUnsubscribeByMail(t *testing.T) {
	h := newHarness(t)
	openNewsletter(h, newsletter("<mailto:leave@lists.shop.example?subject=remove%20me>", "", ""))
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, "Send an unsubscribe email to leave@lists.shop.example") {
		t.Fatalf("no mail confirmation:\n%s", page)
	}
	resp := h.post("/mail/unsubscribe?f=INBOX&uid=9", url.Values{"csrf": {csrf}})
	if !strings.Contains(resp.Header.Get("Location"), "n=unsubscribe-sent") {
		t.Fatalf("unsubscribe = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(h.sub.rcpts) != 1 || h.sub.rcpts[0] != "leave@lists.shop.example" || !strings.Contains(string(h.sub.raw), "Subject: remove me") {
		t.Fatalf("sent to %v:\n%s", h.sub.rcpts, h.sub.raw)
	}
}

func TestUnsubscribeLinkIsOpenedNotFetched(t *testing.T) {
	h := newHarness(t)
	openNewsletter(h, newsletter("<https://shop.example/prefs>", "", "dkim=pass"))
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX&uid=9")
	if !strings.Contains(page, `href="https://shop.example/prefs" target="_blank" rel="noopener noreferrer" data-unsub-mark=`) {
		t.Fatalf("no link:\n%s", page)
	}
	if resp := h.post("/mail/unsubscribe?f=INBOX&uid=9", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("server-side unsubscribe for a page = %d", resp.StatusCode)
	}
	if resp := h.post("/mail/unsubscribe?f=INBOX&uid=9", url.Values{"csrf": {csrf}, "op": {"mark"}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("mark = %d", resp.StatusCode)
	}
	if _, page = h.get("/mail?f=INBOX&uid=9"); !strings.Contains(page, "You unsubscribed from Shop News") {
		t.Error("opening the page wasn't remembered")
	}
}

func TestNoUnsubscribeBarInJunk(t *testing.T) {
	h := newHarness(t)
	h.store.mu.Lock()
	h.store.raw[11] = []byte(newsletter("<https://shop.example/prefs>", "", ""))
	h.store.messages["Junk"] = []Summary{{UID: 11, Subject: "Deals", Date: time.Now()}}
	h.store.mu.Unlock()
	h.login()
	if _, page := h.get("/mail?f=Junk&uid=11"); strings.Contains(page, "data-unsub") {
		t.Error("unsubscribe offered for junk")
	}
}
