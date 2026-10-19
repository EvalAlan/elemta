package webmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSearch(t *testing.T) {
	loc := time.UTC
	q := parseSearch(`from:priya subject:"signed msa" is:unread has:attachment after:2026-01-31 before:2026-03-01 tag:legal quarterly report is:bogus`, loc)
	if q.From != "priya" || q.Subject != "signed msa" || !q.Unread || !q.HasAttachment || q.Tag != "legal" {
		t.Fatalf("operators = %+v", q)
	}
	if !q.Since.Equal(time.Date(2026, 1, 31, 0, 0, 0, 0, loc)) || !q.Before.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, loc)) {
		t.Fatalf("dates = %v %v", q.Since, q.Before)
	}
	if q.Text != "quarterly report is:bogus" {
		t.Fatalf("text = %q: unknown operators must stay searchable", q.Text)
	}
	if on := parseSearch("on:2026-02-14", loc); on.Before.Sub(on.Since) != 24*time.Hour {
		t.Fatalf("on: = %v..%v", on.Since, on.Before)
	}
	if parseSearch("hello", loc).Filtered() != true || (ListQuery{}).Filtered() {
		t.Fatal("Filtered wrong")
	}
}

func TestListStateURLs(t *testing.T) {
	ls := listStateFrom(url.Values{"f": {"Projects"}, "q": {"from:priya"}, "page": {"2"}, "sort": {"subject"}})
	if got := ls.SortURL(SortSubject); !strings.Contains(got, "rev=1") || strings.Contains(got, "page=") {
		t.Errorf("re-sorting by the same key should flip and reset the page: %s", got)
	}
	if got := ls.MessageURL(9); !strings.Contains(got, "uid=9") || !strings.Contains(got, "q=from%3Apriya") || !strings.Contains(got, "page=2") {
		t.Errorf("message URL lost list state: %s", got)
	}
	if bad := listStateFrom(url.Values{"sort": {"evil"}}); bad.Sort != SortDate || bad.Folder != "INBOX" {
		t.Errorf("defaults = %+v", bad)
	}
}

func TestMailPageAppliesSearchAndSort(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, _ := h.get("/mail?f=INBOX&q=" + url.QueryEscape("from:priya is:flagged") + "&sort=size&rev=1&page=3")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	q := h.store.lastQuery
	if q.From != "priya" || !q.Flagged || q.Sort != SortSize || !q.Reverse || q.Page != 3 {
		t.Fatalf("query reached the store as %+v", q)
	}
}

func TestBulkActions(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	form := url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7", "8", "bogus"}, "op": {"read"}, "back": {"/mail?f=INBOX&page=2"}}
	resp := h.post("/mail/action", form)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/mail?f=INBOX&page=2" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !h.store.seen[7] || !h.store.seen[8] {
		t.Fatalf("seen = %v", h.store.seen)
	}

	form.Set("op", "delete")
	form.Set("back", "/mail?f=INBOX&uid=7")
	resp = h.post("/mail/action", form)
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "uid=") || !strings.Contains(loc, "n=deleted-many") {
		t.Fatalf("after deleting, the open message must be dropped: %q", loc)
	}

	// An off-site back URL is ignored.
	form.Set("op", "flag")
	form.Set("back", "https://evil.example/")
	resp = h.post("/mail/action", form)
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "evil") {
		t.Fatalf("open redirect: %q", loc)
	}

	// Tags must be valid IMAP atoms.
	form.Set("op", "tag")
	form.Set("tag", `bad tag"`)
	if resp = h.post("/mail/action", form); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad tag status = %d", resp.StatusCode)
	}
	form.Set("tag", "invoices")
	h.post("/mail/action", form)
	if !h.store.flags[7]["invoices"] {
		t.Fatal("tag not set")
	}
}

func TestFolderManagement(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	if resp := h.post("/folders", url.Values{"csrf": {csrf}, "op": {"create"}, "name": {"Receipts"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	if resp := h.post("/folders", url.Values{"csrf": {csrf}, "op": {"create"}, "name": {"a/b"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a name with the delimiter must be refused, got %d", resp.StatusCode)
	}
	if resp := h.post("/folders", url.Values{"csrf": {csrf}, "op": {"rename"}, "folder": {"Sent"}, "name": {"Outbox"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("renaming Sent = %d", resp.StatusCode)
	}
	if resp := h.post("/folders", url.Values{"csrf": {csrf}, "op": {"rename"}, "folder": {"Receipts"}, "name": {"Bills"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rename = %d", resp.StatusCode)
	}
	if resp := h.post("/folders", url.Values{"csrf": {csrf}, "op": {"delete"}, "folder": {"Bills"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	for _, f := range h.store.folders {
		if f.Name == "Bills" || f.Name == "Receipts" {
			t.Fatalf("folder left behind: %+v", h.store.folders)
		}
	}
}

func TestSettingsShapeCompose(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/settings", url.Values{
		"csrf": {csrf}, "display_name": {"Dana Okafor"}, "signature": {"Dana\nNorthwind Legal"},
		"timezone": {"Europe/Paris"}, "clock": {"12"}, "page_size": {"25"}, "reply_to": {"team@example.com"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if resp := h.post("/settings", url.Values{"csrf": {csrf}, "timezone": {"Mars/Olympus"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad zone = %d", resp.StatusCode)
	}

	_, body := h.get("/compose")
	if !strings.Contains(body, "Dana Okafor") || !strings.Contains(body, "-- \nDana\nNorthwind Legal") {
		t.Fatalf("compose missing name or signature:\n%s", body)
	}

	sendForm(t, h, csrf, map[string]string{"op": "send", "to": "priya@northwind.example", "subject": "Hi", "body": "Hello"})
	raw := string(h.sub.raw)
	if !strings.Contains(raw, `From: "Dana Okafor" <dana@example.com>`) && !strings.Contains(raw, "From: Dana Okafor <dana@example.com>") {
		t.Errorf("From header lacks the display name:\n%s", raw)
	}
	if !strings.Contains(raw, "Reply-To: <team@example.com>") {
		t.Errorf("Reply-To missing:\n%s", raw)
	}
	// Settings persist through the object store, not the session.
	objs, _ := h.store.Objects(context.Background(), CollSettings)
	if len(objs) != 1 || !bytes.Contains(objs[0].Data, []byte("Europe/Paris")) {
		t.Fatalf("settings object = %+v", objs)
	}
	// Writing to someone new remembers them.
	contacts, _ := h.store.Objects(context.Background(), CollContacts)
	if len(contacts) != 1 || !bytes.Contains(contacts[0].Data, []byte("priya@northwind.example")) {
		t.Fatalf("recipient not remembered: %+v", contacts)
	}
}

func sendForm(t *testing.T, h *harness, csrf string, fields map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf", csrf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/compose", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func TestDraftEditReplacesOldDraft(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	h.store.folders = append(h.store.folders, Folder{Name: "Drafts", Display: "Drafts", Role: RoleDrafts, Selectable: true})
	_, body := h.get("/compose?mode=draft&f=INBOX&uid=7")
	if !strings.Contains(body, `name="draft_uid" value="7"`) || !strings.Contains(body, "Signed MSA") {
		t.Fatalf("draft not reopened:\n%s", body)
	}
	resp := sendForm(t, h, csrf, map[string]string{"op": "save", "draft_uid": "7", "subject": "Signed MSA v2"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if len(h.store.appended[RoleDrafts]) != 1 || len(h.store.expunged) != 1 || h.store.expunged[0] != 7 {
		t.Fatalf("appended %d drafts, expunged %v", len(h.store.appended[RoleDrafts]), h.store.expunged)
	}
}

func TestForwardCarriesAttachmentsAndMarksOriginal(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, body := h.get("/compose?mode=forward&f=INBOX&uid=7")
	m := hiddenRE("orig_uid").FindStringSubmatch(body)
	if m == nil || m[1] != "7" || !strings.Contains(body, `name="fwd_part"`) {
		t.Fatalf("forward form:\n%s", body)
	}
	msg, _ := parseMessage([]byte(multipartMessage))
	idx := msg.Attachments()[0].Index
	resp := sendForm(t, h, csrf, map[string]string{"op": "send", "mode": "forward", "orig_f": "INBOX", "orig_uid": "7", "to": "x@example.com", "fwd_part": strconv.Itoa(idx)})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("send = %d", resp.StatusCode)
	}
	if !strings.Contains(string(h.sub.raw), "MSA countersigned.pdf") {
		t.Fatalf("forwarded attachment missing:\n%s", h.sub.raw)
	}
	if !h.store.flags[7][FlagForwarded] {
		t.Fatal("original not marked $Forwarded")
	}
}

func TestContactsLifecycle(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/contacts", url.Values{
		"csrf": {csrf}, "op": {"save"}, "name": {"Priya Shah"},
		"email": {"priya@northwind.example", ""}, "email_label": {"work", ""},
		"phone": {"+1 555 0100"}, "phone_label": {"mobile"}, "org": {"Northwind"}, "groups": {"Legal, Partners"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	_, body := h.get("/contacts")
	if !strings.Contains(body, "Priya Shah") || !strings.Contains(body, "Legal") {
		t.Fatalf("list:\n%s", body)
	}

	resp, vcf := h.get("/contacts/export")
	if resp.Header.Get("Content-Type") != "text/vcard; charset=utf-8" || !strings.Contains(vcf, "EMAIL;TYPE=work:priya@northwind.example") || !strings.Contains(vcf, "CATEGORIES:Legal\r\nCATEGORIES:Partners") {
		t.Fatalf("export:\n%s", vcf)
	}

	// Re-importing the export updates in place rather than duplicating.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf", csrf)
	fw, _ := w.CreateFormFile("file", "contacts.vcf")
	_, _ = io.WriteString(fw, vcf+"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Marcus Lee\r\nEMAIL:marcus@example.com\r\nEND:VCARD\r\n")
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/contacts/import", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	all, _ := h.store.Objects(context.Background(), CollContacts)
	if len(all) != 2 {
		t.Fatalf("after import: %d contacts", len(all))
	}

	_, js := h.get("/api/addresses")
	var sugg []map[string]any
	if err := json.Unmarshal([]byte(js), &sugg); err != nil {
		t.Fatal(err)
	}
	var group bool
	for _, s := range sugg {
		if s["group"] == true && strings.Contains(s["value"].(string), "priya@northwind.example") {
			group = true
		}
	}
	if !group || len(sugg) < 3 {
		t.Fatalf("suggestions = %s", js)
	}

	// The reading pane knows Priya is a contact now.
	_, page := h.get("/mail?f=INBOX&uid=7")
	if strings.Contains(page, "Add to contacts") {
		t.Fatal("offered to add a sender who is already a contact")
	}
}

func TestAddSenderFromReader(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX&uid=7")
	if !strings.Contains(page, "Add to contacts") {
		t.Fatal("no Add to contacts for an unknown sender")
	}
	resp := h.post("/contacts", url.Values{"csrf": {csrf}, "op": {"add-sender"}, "name": {"Priya Shah"}, "email": {"priya@northwind.example"}, "back": {"/mail?f=INBOX&uid=7"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/mail?") || !strings.Contains(loc, "contact-saved") {
		t.Fatalf("location = %q", loc)
	}
	resp = h.post("/contacts", url.Values{"csrf": {csrf}, "op": {"add-sender"}, "email": {"priya@northwind.example"}, "back": {"/mail?f=INBOX&uid=7"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "contact-exists") {
		t.Fatalf("second add = %q", loc)
	}
}

func TestLinkifyEscapes(t *testing.T) {
	got := string(linkify(`see https://example.com/a?b=1&c=2. <script>x</script> javascript:alert(1)`))
	if !strings.Contains(got, `<a href="https://example.com/a?b=1&amp;c=2" rel="noopener noreferrer" target="_blank">`) {
		t.Errorf("link = %s", got)
	}
	if strings.Contains(got, "<script>") || strings.Contains(got, `href="javascript`) {
		t.Errorf("unsafe output: %s", got)
	}
}

func TestDraftBuildAlternativeAndCalendar(t *testing.T) {
	d := &Draft{
		From: Address{Email: "dana@example.com"}, To: []Address{{Email: "priya@northwind.example"}},
		Subject: "Invitation", Text: "Join us", HTML: "<p>Join us</p>",
		Calendar:     &CalendarPart{Method: "REQUEST", Data: []byte("BEGIN:VCALENDAR\nEND:VCALENDAR\n")},
		HighPriority: true, ReceiptTo: "dana@example.com",
	}
	raw, err := d.Build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"multipart/alternative", "text/html", "text/calendar; charset=utf-8; method=REQUEST", "Importance: high", "Disposition-Notification-To: <dana@example.com>"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	d.Attachments = []Attachment{{Filename: "a.txt", Data: []byte("x")}}
	raw, _ = d.Build(time.Now())
	if !strings.Contains(string(raw), "multipart/mixed") || !strings.Contains(string(raw), "multipart/alternative") {
		t.Errorf("attachments + alternative:\n%s", raw)
	}
}

func TestConversationAndPrint(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.store.related = []Related{
		{Folder: "Sent", Summary: Summary{UID: 3, Subject: "Re: Signed MSA", From: []Address{{Email: "dana@example.com"}}}},
		{Folder: "INBOX", Summary: Summary{UID: 7, Subject: "Signed MSA"}}, // the open message itself
	}
	_, page := h.get("/mail?f=INBOX&uid=7")
	if !strings.Contains(page, "2 messages in this conversation") || !strings.Contains(page, "dana@example.com (Sent)") && !strings.Contains(page, "(Sent)") {
		t.Fatalf("conversation missing:\n%s", page)
	}
	resp, body := h.get("/mail/print?f=INBOX&uid=7")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `data-print="1"`) || !strings.Contains(body, "Café at ten.") {
		t.Fatalf("print = %d\n%s", resp.StatusCode, body)
	}
}

func TestThreadIDs(t *testing.T) {
	m := &Message{MessageID: "<c@x>", InReplyTo: "<b@x>", References: "<a@x> <b@x>"}
	if got := strings.Join(threadIDs(m), " "); got != "<a@x> <b@x> <c@x>" {
		t.Fatalf("ids = %q", got)
	}
}

func TestInlinePreviewOnlyForRasterImages(t *testing.T) {
	h := newHarness(t)
	h.login()
	msg, _ := parseMessage([]byte(multipartMessage))
	for _, p := range msg.Parts {
		resp, _ := h.get("/mail/part?f=INBOX&uid=7&inline=1&n=" + strconv.Itoa(p.Index))
		ct := resp.Header.Get("Content-Type")
		switch {
		case previewable(p.ContentType):
			if ct != p.ContentType || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "inline") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
				t.Errorf("%s preview headers: %v", p.ContentType, resp.Header)
			}
		default:
			if ct != "application/octet-stream" {
				t.Errorf("%s served inline as %q", p.ContentType, ct)
			}
		}
	}
}

func TestRemindersAndBirthdays(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	now := time.Now().In(time.UTC)
	start := now.Add(10 * time.Minute)
	h.post("/settings", url.Values{"csrf": {csrf}, "timezone": {"UTC"}})
	h.post("/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "summary": {"Soon"}, "start_date": {start.Format("2006-01-02")}, "start_time": {start.Format("15:04")},
		"end_date": {start.Add(time.Hour).Format("2006-01-02")}, "end_time": {start.Add(time.Hour).Format("15:04")}, "reminder": {"15"},
	})
	_, js := h.get("/api/reminders")
	var list []map[string]any
	if err := json.Unmarshal([]byte(js), &list); err != nil || len(list) != 1 || list[0]["title"] != "Soon" {
		t.Fatalf("reminders = %s", js)
	}
	if at := int64(list[0]["at"].(float64)); at > time.Now().Unix() {
		t.Errorf("a reminder 15 minutes before an event 10 minutes away is already due, got at=%d", at)
	}

	h.post("/contacts", url.Values{"csrf": {csrf}, "op": {"save"}, "name": {"Priya Shah"}, "birthday": {"--02-29"}})
	_, page := h.get("/calendar?view=month&date=2028-02-10")
	if !strings.Contains(page, "Priya Shah&#39;s birthday") {
		t.Fatalf("birthday missing from February 2028")
	}
	_, page = h.get("/calendar/event?uid=birthday-" + firstContactID(t, h))
	if strings.Contains(page, ">Edit<") || !strings.Contains(page, "comes from your contacts") {
		t.Error("birthday event offered editing")
	}
}

func firstContactID(t *testing.T, h *harness) string {
	t.Helper()
	objs, _ := h.store.Objects(context.Background(), CollContacts)
	if len(objs) == 0 {
		t.Fatal("no contacts")
	}
	return objs[0].ID
}

func TestRichTextCompose(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfake"))
	resp := sendForm(t, h, csrf, map[string]string{
		"op": "send", "to": "priya@northwind.example", "subject": "Formatted", "format": "html",
		"body": "Hello *world*",
		"html": `<p>Hello <b>world</b> <a href="https://example.com">site</a> <a href="javascript:alert(1)">bad</a></p>` +
			`<script>alert(1)</script><img src="https://tracker.example/p.gif">` +
			`<p style="color: red; position: fixed; background-image: url(https://x.example/a)" onclick="x()">styled</p>` +
			`<img src="data:image/png;base64,` + png + `" width="50%">` +
			`<table border="1"><tr><td>cell</td></tr></table>`,
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("send = %d", resp.StatusCode)
	}
	raw := string(h.sub.raw)
	if !strings.Contains(raw, "multipart/related") {
		t.Fatalf("no multipart/related for the inline picture:\n%s", raw)
	}
	msg, err := parseMessage(h.sub.raw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Text != "Hello *world*" {
		t.Errorf("text part = %q", msg.Text)
	}
	for _, want := range []string{"<b>world</b>", `href="https://example.com"`, "color: red", `src="cid:`, `width="50%"`, "<td>cell</td>"} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("HTML lacks %q:\n%s", want, msg.HTML)
		}
	}
	for _, bad := range []string{"<script", "javascript:", "tracker.example", "onclick", "position", "url(", "data:image"} {
		if strings.Contains(msg.HTML, bad) {
			t.Errorf("HTML kept %q:\n%s", bad, msg.HTML)
		}
	}
	var inline *Part
	for i := range msg.Parts {
		if msg.Parts[i].ContentID != "" {
			inline = &msg.Parts[i]
		}
	}
	if inline == nil || inline.ContentType != "image/png" || !strings.Contains(msg.HTML, "cid:"+inline.ContentID) {
		t.Fatalf("inline picture part = %+v", inline)
	}
	// Without format=html the HTML field is ignored.
	sendForm(t, h, csrf, map[string]string{"op": "send", "to": "priya@northwind.example", "body": "plain", "html": "<b>x</b>"})
	if msg, _ := parseMessage(h.sub.raw); msg.HTML != "" {
		t.Errorf("plain message got an HTML part")
	}
}

func TestInlinePicturesCountTowardsLimit(t *testing.T) {
	big := base64.StdEncoding.EncodeToString(make([]byte, 3000))
	html, parts, over := extractInlineImages(`<img src="data:image/png;base64,`+big+`">`, "example.com", 1000)
	if !over || len(parts) != 0 || strings.Contains(html, "data:") {
		t.Fatalf("over budget: over=%v parts=%d html=%q", over, len(parts), html)
	}
}

func TestReplyQuotesHTMLWithPictures(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, page := h.get("/compose?mode=reply&f=INBOX&uid=7")
	if !strings.Contains(page, "<blockquote>") || !strings.Contains(page, "data:image/png;base64,") {
		t.Fatalf("reply editor lacks the quoted HTML with its inline image")
	}
}

func TestTextToHTML(t *testing.T) {
	got := textToHTML("Hi <there>\n> quoted\n>> deeper\nback")
	want := "Hi &lt;there&gt;<br><blockquote>quoted<br><blockquote>deeper<br></blockquote></blockquote>back<br>"
	if got != want {
		t.Fatalf("textToHTML = %q", got)
	}
}

func TestThemeChoice(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, page := h.get("/mail")
	if strings.Contains(page, "data-theme=") && !strings.Contains(page, "data-theme-toggle") {
		t.Fatal("a theme was forced before the user chose one")
	}
	if strings.Contains(page, `<html lang="en" data-theme`) {
		t.Fatal("default should follow the device")
	}
	resp := h.post("/settings/theme", url.Values{"csrf": {csrf}, "theme": {"light"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("toggle = %d", resp.StatusCode)
	}
	_, page = h.get("/mail")
	if !strings.Contains(page, `<html lang="en" data-theme="light">`) || !strings.Contains(page, `name="theme" value="dark"`) {
		t.Fatalf("light theme not applied")
	}
	h.post("/settings/theme", url.Values{"csrf": {csrf}, "theme": {"purple"}})
	_, page = h.get("/mail")
	if strings.Contains(page, `<html lang="en" data-theme`) {
		t.Fatal("an unknown theme was stored")
	}
	// The sign-in page, which has no session, follows the cookie.
	h.post("/settings/theme", url.Values{"csrf": {csrf}, "theme": {"light"}})
	h.post("/logout", url.Values{"csrf": {csrf}})
	_, login := h.get("/login")
	if !strings.Contains(login, `data-theme="light"`) {
		t.Fatal("sign-in page ignores the chosen theme")
	}
}

// The default palette matches the admin console and needs no attribute;
// Tidewater is opt-in from Settings and follows the user to sign-in.
func TestPaletteChoice(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, page := h.get("/mail")
	if strings.Contains(page, "data-palette=") {
		t.Fatal("a palette was set before the user chose one")
	}
	if !strings.Contains(page, `class="logo"`) {
		t.Fatal("top bar lacks the shared envelope logo")
	}
	h.post("/settings", url.Values{"csrf": {csrf}, "timezone": {"UTC"}, "palette": {"tidewater"}})
	_, page = h.get("/mail")
	if !strings.Contains(page, `data-palette="tidewater"`) {
		t.Fatal("Tidewater not applied")
	}
	_, settings := h.get("/settings")
	if !strings.Contains(settings, `<option value="tidewater" selected>`) {
		t.Fatal("settings page doesn't show the chosen palette")
	}
	h.post("/logout", url.Values{"csrf": {csrf}})
	if _, login := h.get("/login"); !strings.Contains(login, `data-palette="tidewater"`) {
		t.Fatal("sign-in page ignores the chosen palette")
	}
	csrf = h.login()
	h.post("/settings", url.Values{"csrf": {csrf}, "timezone": {"UTC"}, "palette": {"neon"}})
	if _, page = h.get("/mail"); strings.Contains(page, "data-palette=") {
		t.Fatal("an unknown palette was stored")
	}
}

func TestViewOriginal(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.store.raw[8] = []byte("From: x@example.com\r\nSubject: <script>alert(1)</script>\r\nX-Spam: yes\r\n\r\n<b>hi</b>\r\n")
	resp, body := h.get("/mail/source?f=INBOX&uid=8")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "X-Spam: yes") || !strings.Contains(body, "/mail/raw?") {
		t.Fatalf("source page = %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<b>hi</b>") {
		t.Fatal("source not escaped")
	}
}

func TestContextMenuHooksAndMarkAllRead(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX")
	for _, want := range []string{`data-ctx="message"`, `data-ctx="folder"`, `data-role="inbox"`, `data-from="priya@northwind.example"`, `data-back="/mail?f=INBOX"`} {
		if !strings.Contains(page, want) {
			t.Errorf("mail page lacks %s", want)
		}
	}
	// Mark all read needs no selection.
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "op": {"readall"}, "back": {"/mail?f=INBOX"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=all-read") || len(h.store.allRead) != 1 {
		t.Fatalf("readall: %d %q %v", resp.StatusCode, resp.Header.Get("Location"), h.store.allRead)
	}
}

func TestConversationList(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	now := time.Now()
	h.store.messages["INBOX"] = append(h.store.messages["INBOX"],
		Summary{UID: 8, Subject: "Re: Signed MSA", From: []Address{{Name: "Marcus Lee", Email: "marcus@example.com"}}, Date: now.Add(time.Minute)},
		Summary{UID: 9, Subject: "Lunch?", From: []Address{{Email: "sam@example.com"}}, Date: now, Seen: true},
	)
	_, page := h.get("/mail?f=INBOX")
	if h.store.threadCalls == 0 {
		t.Fatal("conversations are the default, but the list wasn't threaded")
	}
	for _, want := range []string{`value="7,8"`, `class="thread-count"`, "Priya Shah, Marcus Lee", "uid=8"} {
		if !strings.Contains(page, want) {
			t.Errorf("threaded list lacks %q", want)
		}
	}
	// Acting on a conversation acts on every message in it.
	h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7,8"}, "op": {"read"}})
	if !h.store.seen[7] || !h.store.seen[8] {
		t.Fatalf("seen = %v", h.store.seen)
	}
	// Switching grouping off lists single messages.
	h.post("/settings/conversations", url.Values{"csrf": {csrf}, "on": {"0"}, "back": {"/mail?f=INBOX"}})
	before := h.store.threadCalls
	_, page = h.get("/mail?f=INBOX")
	if h.store.threadCalls != before || strings.Contains(page, `value="7,8"`) {
		t.Fatal("grouping still on after switching it off")
	}
}

func TestConversationCardsInReader(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.store.related = []Related{
		{Folder: "Sent", Summary: Summary{UID: 3, Subject: "Re: Signed MSA", From: []Address{{Email: "dana@example.com"}}, Date: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{Folder: "INBOX", Summary: Summary{UID: 5, Subject: "MSA draft", From: []Address{{Email: "priya@northwind.example"}}, Date: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}},
	}
	_, page := h.get("/mail?f=INBOX&uid=7")
	if strings.Count(page, `class="thread-card"`) != 2 || !strings.Contains(page, "3 messages in this conversation") {
		t.Fatalf("conversation cards missing")
	}
	// Earlier messages come before the open one, later ones after it.
	open := strings.Index(page, `class="sender"`)
	if strings.Index(page, "uid=5") > open || strings.LastIndex(page, "uid=3") < open {
		t.Error("cards not ordered around the open message")
	}
	// Plain-text messages render in the body frame too.
	h.store.raw[11] = []byte("From: a@example.com\r\nSubject: t\r\n\r\nplain <b>text</b> https://example.com\r\n")
	resp, body := h.get("/mail/body?f=INBOX&uid=11")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "plain &lt;b&gt;text&lt;/b&gt;") || !strings.Contains(body, `href="https://example.com"`) {
		t.Fatalf("text body frame = %d\n%s", resp.StatusCode, body)
	}
}

// TestNoNestedForms guards against a form inside another form: browsers
// drop the inner <form> tag but honour its </form>, which ends the outer
// form early and silently detaches its fields.
func TestNoNestedForms(t *testing.T) {
	h := newHarness(t)
	h.login()
	for _, path := range []string{"/mail?f=INBOX", "/mail?f=INBOX&uid=7", "/compose", "/settings", "/contacts", "/calendar", "/tasks", "/folders", "/filters"} {
		_, page := h.get(path)
		depth := 0
		for _, tok := range regexp.MustCompile(`(?i)<(/?)form\b`).FindAllStringSubmatch(page, -1) {
			if tok[1] == "" {
				depth++
			} else {
				depth--
			}
			if depth > 1 {
				t.Errorf("%s has a form nested inside another form", path)
				break
			}
		}
	}
}

// TestLoadImagesPreference pins that remote images stay blocked until the
// user opts in, then load in the reading page and in the body frames that
// conversation cards fetch on their own, but never in Junk.
func TestLoadImagesPreference(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	h.store.raw[11] = []byte("From: a@example.com\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n<p>hi</p><img src=\"https://tracker.example/p.gif\">\r\n")
	loads := func(path string) bool {
		t.Helper()
		resp, body := h.get(path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
		return strings.Contains(body, "tracker.example")
	}
	if loads("/mail/body?f=INBOX&uid=11") {
		t.Fatal("remote image loaded before the user opted in")
	}
	if _, page := h.get("/mail?f=INBOX&uid=11"); !strings.Contains(page, "Show images") {
		t.Error("no show-images banner while images are blocked")
	}
	if resp := h.post("/settings", url.Values{"csrf": {csrf}, "timezone": {"UTC"}, "load_images": {"1"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings = %d", resp.StatusCode)
	}
	if !loads("/mail/body?f=INBOX&uid=11") {
		t.Error("conversation-card body frame ignored the preference")
	}
	_, page := h.get("/mail?f=INBOX&uid=11")
	if strings.Contains(page, "Show images") || !strings.Contains(page, "remote=1") {
		t.Error("reading page ignored the preference")
	}
	if loads("/mail/body?f=Junk&uid=11") {
		t.Error("remote image loaded automatically in Junk")
	}
	if _, page := h.get("/settings"); !strings.Contains(page, `name="load_images" value="1" checked`) {
		t.Error("settings page doesn't show the preference as on")
	}
}
