package mailbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/google/uuid"
)

func TestComplianceSearch(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	// A second account, in another domain, to search across and to scope away.
	b := Account{ID: uuid.NewString(), Address: uuid.NewString() + "@other.example"}
	if err := e.EnsureAccount(ctx, b); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range []string{a.ID, b.ID} {
			_, _ = e.DB.Exec(`DELETE FROM mailbox_held WHERE account=$1`, id)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_deliveries WHERE account=$1`, id)
			_, _ = e.DB.Exec(`DELETE FROM mailbox_folders WHERE account=$1`, id)
		}
		_, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, b.ID)
	})
	// A word no other test's mail contains, so the database can be shared.
	tag := "zq" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	put := func(acct Account, folder, from, to, subject, body string, date time.Time) uint32 {
		t.Helper()
		if folder != "INBOX" {
			if err := e.Create(ctx, acct.ID, folder); err != nil && !errors.Is(err, ErrExists) {
				t.Fatal(err)
			}
		}
		raw := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: Mon, 02 Nov 2026 10:00:00 +0000\r\n\r\n%s\r\nFrom the start of a line\r\n", from, to, subject, body)
		res, err := e.Append(ctx, acct.ID, folder, []byte(raw), nil, date, "")
		if err != nil {
			t.Fatal(err)
		}
		return res.UID
	}
	jan := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	jun := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	put(a, "INBOX", "Dana <dana@vendor.example>", a.Address, "Contract "+tag, "the merger terms "+tag, jan)
	put(a, "Sent", a.Address, "lee@partner.example", "Re: Contract "+tag, "agreed "+tag, jun)
	deleted := put(a, "INBOX", "Dana <dana@vendor.example>", a.Address, "Shred this "+tag, "merger secrets "+tag, jun)
	put(b, "INBOX", "dana@vendor.example", b.Address, "Other domain "+tag, "merger elsewhere "+tag, jun.AddDate(0, 0, 1))
	// The webmail's data isn't mail, whatever it says.
	put(a, "Calendar", "dana@vendor.example", a.Address, "Event "+tag, "merger meeting "+tag, jun)

	// Held: deleted under a legal hold, and still found.
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Settings: mailpolicy.Settings{LegalHold: bptr(true)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.expunge(ctx, a.ID, "INBOX", []uint32{deleted}, false, ""); err != nil {
		t.Fatal(err)
	}

	search := func(q mailpolicy.ComplianceQuery) mailpolicy.ComplianceResult {
		t.Helper()
		res, err := e.ComplianceSearch(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	subjects := func(res mailpolicy.ComplianceResult) string {
		var s []string
		for _, h := range res.Hits {
			s = append(s, strings.TrimSuffix(h.Subject, " "+tag))
		}
		return strings.Join(s, "|")
	}

	// Words in the body, across accounts, newest first, held mail included.
	res := search(mailpolicy.ComplianceQuery{Text: "merger " + tag})
	if got := subjects(res); got != "Other domain|Shred this|Contract" || res.Total != 3 {
		t.Fatalf("text search = %q (total %d)", got, res.Total)
	}
	for _, h := range res.Hits {
		if h.Subject == "Shred this "+tag && (!h.Held || h.HeldAt == nil || h.Folder != "INBOX" || h.Account != a.Address) {
			t.Errorf("held hit = %+v", h)
		}
		if h.Subject == "Contract "+tag && (h.Held || h.From != "Dana <dana@vendor.example>" || h.Size == 0 || !h.Date.Equal(jan)) {
			t.Errorf("hit = %+v", h)
		}
	}
	// Words match as prefixes, like the webmail's search.
	if got := subjects(search(mailpolicy.ComplianceQuery{Text: "merg " + tag, ExcludeHeld: true})); got != "Other domain|Contract" {
		t.Errorf("prefix search without held mail = %q", got)
	}
	// Scope: a searcher confined to one domain sees only it.
	if got := subjects(search(mailpolicy.ComplianceQuery{Text: tag, Domains: []string{"other.example"}})); got != "Other domain" {
		t.Errorf("scoped search = %q", got)
	}
	// Recipients cover To and Cc; From and Subject are substrings.
	if got := subjects(search(mailpolicy.ComplianceQuery{To: "LEE@partner", Text: tag})); got != "Re: Contract" {
		t.Errorf("to search = %q", got)
	}
	if got := subjects(search(mailpolicy.ComplianceQuery{From: "vendor.example", Subject: "contract " + tag})); got != "Contract" {
		t.Errorf("from and subject search = %q", got)
	}
	// Dates are when the mail arrived; Before is exclusive.
	if got := subjects(search(mailpolicy.ComplianceQuery{Accounts: []string{a.Address}, Since: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Before: jun})); got != "" {
		t.Errorf("before is exclusive: %q", got)
	}
	if got := subjects(search(mailpolicy.ComplianceQuery{Accounts: []string{strings.ToUpper(a.Address)}, Since: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})); got != "Re: Contract|Shred this" && got != "Shred this|Re: Contract" {
		t.Errorf("account and date search = %q", got)
	}
	// The limit pages; the total still counts everything.
	if res := search(mailpolicy.ComplianceQuery{Text: tag, Limit: 1}); len(res.Hits) != 1 || res.Total != 4 {
		t.Errorf("limited: %d hits, total %d", len(res.Hits), res.Total)
	}

	// Nothing to look for, or nothing searchable, is refused.
	for _, q := range []mailpolicy.ComplianceQuery{{}, {Domains: []string{"example.com"}}, {Text: "!!!"}, {Since: jun, Before: jan}} {
		if _, err := e.ComplianceSearch(ctx, q); !errors.Is(err, mailpolicy.ErrInvalid) {
			t.Errorf("query %+v: %v, want a refusal", q, err)
		}
	}

	// Mail the index hasn't reached is counted, not silently missed.
	if _, err := e.DB.Exec(`UPDATE mailbox_summaries SET version=version-1 WHERE body IN (SELECT m.body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1)`, b.ID); err != nil {
		t.Fatal(err)
	}
	if res := search(mailpolicy.ComplianceQuery{Text: tag}); res.Total != 3 || res.Unindexed < 1 {
		t.Errorf("after unindexing: total %d, unindexed %d", res.Total, res.Unindexed)
	}
	if res := search(mailpolicy.ComplianceQuery{Text: tag, Accounts: []string{a.Address}}); res.Unindexed != 0 {
		t.Errorf("unindexed counted outside the searched accounts: %d", res.Unindexed)
	}

	// Export: every match, oldest first, marked with its account and folder.
	var buf bytes.Buffer
	n, err := e.ComplianceExport(ctx, mailpolicy.ComplianceQuery{Text: tag, Accounts: []string{a.Address}}, &buf)
	if err != nil || n != 3 {
		t.Fatalf("export = %d, %v", n, err)
	}
	out := buf.String()
	first, last := strings.Index(out, "Subject: Contract "+tag), strings.Index(out, "Subject: Shred this "+tag)
	if first < 0 || last < 0 || first > last || strings.Count(out, "\nFrom MAILER-DAEMON ")+boolInt(strings.HasPrefix(out, "From MAILER-DAEMON ")) != 3 {
		t.Errorf("export order or count wrong:\n%s", out)
	}
	if !strings.Contains(out, `X-Elemta-Compliance: account="`+a.Address+`"; folder="Sent"`) || !strings.Contains(out, `folder="INBOX"; held `) || !strings.Contains(out, "\n>From the start of a line") {
		t.Errorf("export lacks its markers or From quoting:\n%s", out)
	}

	// One message by its ref, in scope or not at all.
	hit := search(mailpolicy.ComplianceQuery{Subject: "shred this " + tag}).Hits[0]
	raw, account, err := e.ComplianceMessage(ctx, hit.Ref, nil)
	if err != nil || account != a.Address || !strings.Contains(string(raw), "Subject: Shred this") {
		t.Fatalf("held message by ref: %q %q %v", raw, account, err)
	}
	if _, _, err := e.ComplianceMessage(ctx, hit.Ref, []string{"other.example"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("out-of-scope ref: %v", err)
	}
	for _, ref := range []string{"", "m:1", "m:x:1", "h:", "z:1", "m:999999999:1"} {
		if _, _, err := e.ComplianceMessage(ctx, ref, nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("ref %q: %v", ref, err)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestComplianceAdminAPI(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	s.adminToken = "admin-secret"
	ctx := context.Background()
	tag := "zq" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("From: dana@vendor.example\r\nSubject: Audit "+tag+"\r\n\r\nledger "+tag+"\r\n"), nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	call := func(remote, method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		return w
	}
	const local = "127.0.0.1:5000"
	query := `{"text":"ledger ` + tag + `"}`
	for _, path := range []string{"/v1/admin/compliance/search", "/v1/admin/compliance/export"} {
		if w := call(local, "POST", path, "wrong", query); w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong token = %d", path, w.Code)
		}
		if w := call("192.0.2.7:5000", "POST", path, "admin-secret", query); w.Code == http.StatusOK {
			t.Errorf("%s from outside = %d", path, w.Code)
		}
	}
	if w := call("192.0.2.7:5000", "GET", "/v1/admin/compliance/message?ref=m:1:1", "admin-secret", ""); w.Code == http.StatusOK {
		t.Errorf("message from outside = %d", w.Code)
	}

	w := call(local, "POST", "/v1/admin/compliance/search", "admin-secret", query)
	var res mailpolicy.ComplianceResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || w.Code != http.StatusOK || res.Total != 1 || res.Hits[0].Account != a.Address {
		t.Fatalf("search = %d %s", w.Code, w.Body)
	}
	if w := call(local, "POST", "/v1/admin/compliance/search", "admin-secret", `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("empty search = %d %s", w.Code, w.Body)
	}

	w = call(local, "POST", "/v1/admin/compliance/export", "admin-secret", query)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/mbox" || !strings.Contains(w.Body.String(), "Subject: Audit "+tag) {
		t.Fatalf("export = %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	// A refused export answers with an error, not an empty file.
	w = call(local, "POST", "/v1/admin/compliance/export", "admin-secret", `{"text":"!!!"}`)
	if w.Code != http.StatusBadRequest || w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("refused export = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	// A search with no matches exports an empty file.
	w = call(local, "POST", "/v1/admin/compliance/export", "admin-secret", `{"text":"nothingmatches`+tag+`"}`)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("empty export = %d %q", w.Code, w.Body)
	}

	ref := url.QueryEscape(res.Hits[0].Ref)
	w = call(local, "GET", "/v1/admin/compliance/message?ref="+ref, "admin-secret", "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "message/rfc822" || !strings.Contains(w.Body.String(), "ledger "+tag) {
		t.Fatalf("message = %d %s", w.Code, w.Body)
	}
	if w := call(local, "GET", "/v1/admin/compliance/message?ref="+ref+"&domain=elsewhere.example", "admin-secret", ""); w.Code != http.StatusNotFound {
		t.Errorf("out-of-scope message = %d", w.Code)
	}
}
