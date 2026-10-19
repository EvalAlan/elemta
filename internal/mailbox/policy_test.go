package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/google/uuid"
)

func i64(v int64) *int64 { return &v }
func iptr(v int) *int    { return &v }
func bptr(v bool) *bool  { return &v }

// testClass creates a uniquely named class and removes it, and anything
// naming it, when the test ends; the test database is shared.
func testClass(t *testing.T, e *Engine, s mailpolicy.Settings) string {
	t.Helper()
	name := "t-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if _, err := e.PutClass(context.Background(), mailpolicy.Class{Name: name, Settings: s}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE class=$1`, name)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_domain_policy WHERE class=$1`, name)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_classes WHERE name=$1`, name)
	})
	return name
}

func TestEffectivePolicyLayers(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	domain := a.Address[strings.Index(a.Address, "@")+1:]
	// A unique domain keeps this test's domain class away from others'.
	a.Address = strings.Replace(a.Address, "@"+domain, "@"+uuid.NewString()[:8]+".example", 1)
	domain = a.Address[strings.Index(a.Address, "@")+1:]
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address) })

	eff, err := e.EffectivePolicy(ctx, a.Address, 0)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Class != mailpolicy.DefaultClass || !eff.Allows(mailpolicy.IMAP) || !eff.Filters || eff.QuotaBytes != 0 {
		t.Fatalf("with nothing set: %+v", eff)
	}

	staff := testClass(t, e, mailpolicy.Settings{QuotaBytes: i64(5 << 30), MaxMessageBytes: i64(25 << 20), Protocols: map[string]bool{mailpolicy.POP3: false}})
	if _, err := e.SetDomain(ctx, mailpolicy.DomainPolicy{Domain: domain, Class: staff}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.SetDomain(ctx, mailpolicy.DomainPolicy{Domain: domain}) })
	interns := testClass(t, e, mailpolicy.Settings{QuotaBytes: i64(1 << 30), MessagesPerHour: iptr(50)})
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: interns, Settings: mailpolicy.Settings{MessagesPerHour: iptr(200)}}); err != nil {
		t.Fatal(err)
	}

	eff, err = e.EffectivePolicy(ctx, strings.ToUpper(a.Address), 0)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Class != interns {
		t.Errorf("class = %q, want the account's own", eff.Class)
	}
	if eff.QuotaBytes != 1<<30 || eff.Source["quota_bytes"] != "class "+interns {
		t.Errorf("quota = %d from %q: the account's class should beat the domain's", eff.QuotaBytes, eff.Source["quota_bytes"])
	}
	if eff.MaxMessageBytes != 25<<20 || eff.Allows(mailpolicy.POP3) {
		t.Errorf("settings the account's class leaves unset should come from the domain's class: %+v", eff)
	}
	if eff.MessagesPerHour != 200 || eff.Source["messages_per_hour"] != "account" {
		t.Errorf("messages/hour = %d from %q: the account override wins", eff.MessagesPerHour, eff.Source["messages_per_hour"])
	}
	// A quota the directory holds outranks the classes, not the override.
	if eff, _ = e.EffectivePolicy(ctx, a.Address, 3<<30); eff.QuotaBytes != 3<<30 {
		t.Errorf("directory quota ignored: %d", eff.QuotaBytes)
	}
	_ = e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: interns, Settings: mailpolicy.Settings{QuotaBytes: i64(0)}})
	if eff, _ = e.EffectivePolicy(ctx, a.Address, 3<<30); eff.QuotaBytes != 0 {
		t.Errorf("an account override of 0 (unlimited) should beat the directory quota: %d", eff.QuotaBytes)
	}

	// A class in use can't go; the default class never can.
	if err := e.DeleteClass(ctx, interns); !errors.Is(err, ErrInUse) {
		t.Errorf("deleting a class in use: %v", err)
	}
	if err := e.DeleteClass(ctx, mailpolicy.DefaultClass); !errors.Is(err, ErrInUse) {
		t.Errorf("deleting the default class: %v", err)
	}
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address, Class: "no-such-class"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("assigning a missing class: %v", err)
	}
	// Clearing class and overrides removes the account's row.
	if err := e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: a.Address}); err != nil {
		t.Fatal(err)
	}
	var rows int
	_ = e.DB.QueryRow(`SELECT count(*) FROM mailbox_account_policy WHERE address=$1`, a.Address).Scan(&rows)
	if rows != 0 {
		t.Error("cleared account policy left a row")
	}
	if _, err := e.PutClass(ctx, mailpolicy.Class{Name: "Bad Name"}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("invalid class name accepted: %v", err)
	}
	if _, err := e.PutClass(ctx, mailpolicy.Class{Name: "t-bad", Settings: mailpolicy.Settings{Protocols: map[string]bool{"gopher": true}}}); !errors.Is(err, mailpolicy.ErrInvalid) {
		t.Errorf("unknown protocol accepted: %v", err)
	}
}

// TestClassOfServiceEnforcedByMailbox covers what the mailbox itself
// enforces: protocol switches at sign-in, a class quota, per-recipient size
// limits at delivery, filters and external forwarding.
func TestClassOfServiceEnforcedByMailbox(t *testing.T) {
	r := newSieveRig(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = r.e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, r.a.Address) })
	assign := func(s mailpolicy.Settings) {
		t.Helper()
		if err := r.e.PutAccountPolicy(ctx, mailpolicy.AccountPolicy{Address: r.a.Address, Class: testClass(t, r.e, s)}); err != nil {
			t.Fatal(err)
		}
	}

	// Protocols: IMAP refused on the public listener only; the internal
	// listener (the webmail) applies its own switches.
	assign(mailpolicy.Settings{Protocols: map[string]bool{mailpolicy.IMAP: false}})
	if _, err := r.svc.login(ctx, r.a.Address, "testpass", true, mailpolicy.IMAP); !errors.Is(err, ErrProtocolDisabled) {
		t.Fatalf("IMAP sign-in with IMAP turned off: %v", err)
	}
	if _, err := r.svc.login(ctx, r.a.Address, "testpass", false, ""); err != nil {
		t.Fatalf("internal sign-in refused: %v", err)
	}
	if ok, _ := r.svc.allowLogin(r.a.Address); !ok {
		t.Error("a protocol refusal counted as a credential failure")
	}

	// Quota from the class, enforced on delivery.
	assign(mailpolicy.Settings{QuotaBytes: i64(1)})
	if st := r.deliver("bo@example.com", "", r.msg("over quota")); st == nil || st.Code != 452 {
		t.Fatalf("delivery over a class quota: %v", st)
	}

	// Size limits per recipient.
	assign(mailpolicy.Settings{MaxMessageBytes: i64(200)})
	if st := r.deliver("bo@example.com", "", r.msg("big")+strings.Repeat("x", 300)); st == nil || st.Code != 552 {
		t.Fatalf("message over the recipient's limit: %v", st)
	}
	if st := r.deliver("bo@example.com", "", r.msg("small")); st != nil {
		t.Fatalf("message under the limit refused: %v", st)
	}
	assign(mailpolicy.Settings{MaxAttachmentBytes: i64(100)})
	withFile := "From: bo@example.com\r\nTo: " + r.a.Address + "\r\nSubject: file\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=big.pdf\r\n\r\n" + strings.Repeat("y", 500) + "\r\n--b--\r\n"
	if st := r.deliver("bo@example.com", "", withFile); st == nil || st.Code != 552 || !strings.Contains(st.Message, "attachment") {
		t.Fatalf("attachment over the limit: %v", st)
	}

	// Filters off: the stored script is ignored, and ManageSieve refuses.
	if err := r.install(`require ["fileinto", "mailbox"]; fileinto :create "Filed";`); err != nil {
		t.Fatal(err)
	}
	assign(mailpolicy.Settings{Filters: bptr(false)})
	before := r.count("INBOX")
	if st := r.deliver("bo@example.com", "", r.msg("unfiltered")); st != nil {
		t.Fatal(st)
	}
	if r.count("INBOX") != before+1 || r.count("Filed") != 0 {
		t.Error("a script ran with filters turned off")
	}

	// External forwarding off: the redirect becomes a keep, nothing is sent.
	assign(mailpolicy.Settings{ExternalForwarding: bptr(false)})
	if err := r.install(`redirect "elsewhere@example.net";`); err != nil {
		t.Fatal(err)
	}
	before = r.count("INBOX")
	if st := r.deliver("bo@example.com", "", r.msg("forward me")); st != nil {
		t.Fatal(st)
	}
	if got := len(r.submit.messages()); got != 0 {
		t.Errorf("external redirect sent %d messages with forwarding turned off", got)
	}
	if r.count("INBOX") != before+1 {
		t.Error("blocked redirect lost the message")
	}
}

func TestAdminAPI(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	s.adminToken = "admin-secret"
	call := func(remote, method, path, token, body string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	const local = "127.0.0.1:5000"
	if code, _ := call("192.0.2.7:5000", "GET", "/v1/admin/classes", "admin-secret", ""); code != http.StatusForbidden {
		t.Fatalf("outside network = %d", code)
	}
	if code, _ := call(local, "GET", "/v1/admin/classes", "wrong", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d", code)
	}
	name := "t-api-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_classes WHERE name=$1`, name)
	})
	if code, out := call(local, "PUT", "/v1/admin/classes/"+name, "admin-secret", `{"description":"Small","settings":{"quota_bytes":1048576,"protocols":{"pop3":false}}}`); code != http.StatusOK || out["name"] != name {
		t.Fatalf("put class = %d %v", code, out)
	}
	if code, out := call(local, "PUT", "/v1/admin/classes/"+name, "admin-secret", `{"settings":{"quota_bytes":-1}}`); code != http.StatusBadRequest {
		t.Fatalf("negative quota = %d %v", code, out)
	}
	if code, out := call(local, "PUT", "/v1/admin/accounts/"+a.Address+"/policy", "admin-secret", `{"class":"`+name+`"}`); code != http.StatusOK {
		t.Fatalf("put account policy = %d %v", code, out)
	}
	code, out := call(local, "GET", "/v1/admin/effective?address="+a.Address, "admin-secret", "")
	if code != http.StatusOK || out["class"] != name || out["quota_bytes"].(float64) != 1048576 {
		t.Fatalf("effective = %d %v", code, out)
	}
	if code, _ := call(local, "GET", "/v1/admin/effective?address=nobody@example.com", "admin-secret", ""); code != http.StatusNotFound {
		t.Fatalf("effective for an unknown address = %d", code)
	}
	if code, _ := call(local, "DELETE", "/v1/admin/classes/"+name, "admin-secret", ""); code != http.StatusConflict {
		t.Fatalf("deleting a class in use = %d", code)
	}

	// Purge refuses an account the directory still has, and removes
	// everything for one it doesn't.
	if code, _ := call(local, "POST", "/v1/admin/accounts/"+a.Address+"/purge", "admin-secret", ""); code != http.StatusConflict {
		t.Fatalf("purging a live account = %d", code)
	}
	gone := Account{ID: uuid.NewString(), Address: "gone-" + uuid.NewString()[:8] + "@example.com"}
	if err := e.EnsureAccount(context.Background(), gone); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Append(context.Background(), gone.ID, "INBOX", []byte("Subject: left behind\r\n\r\nx\r\n"), nil, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	code, out = call(local, "POST", "/v1/admin/accounts/"+gone.Address+"/purge", "admin-secret", "")
	if code != http.StatusOK || out["accounts"].(float64) != 1 || out["messages"].(float64) != 1 {
		t.Fatalf("purge = %d %v", code, out)
	}
	var left int
	_ = e.DB.QueryRow(`SELECT count(*) FROM mailbox_accounts WHERE id=$1`, gone.ID).Scan(&left)
	if left != 0 {
		t.Error("purged account still has rows")
	}

	// Without a token configured, the API doesn't exist.
	s.adminToken = ""
	if code, _ := call(local, "GET", "/v1/admin/classes", "admin-secret", ""); code != http.StatusNotFound {
		t.Fatalf("admin API without a token = %d", code)
	}
}

// TestRequiredTwoFactorCantBeTurnedOff pins that a class requiring two-step
// verification is reported to the webmail and holds against the user's own
// settings.
func TestRequiredTwoFactorCantBeTurnedOff(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_account_policy WHERE address=$1`, a.Address) })
	if err := e.PutAccountPolicy(context.Background(), mailpolicy.AccountPolicy{Address: a.Address, Class: testClass(t, e, mailpolicy.Settings{RequireTwoFactor: bptr(true), RequireAppPasswords: bptr(true)})}); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:5000"
		r.SetBasicAuth(a.Address, "testpass")
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := call("POST", "/v1/security/check", "")
	if code != http.StatusOK || out["require_two_factor"] != true || out["app_required"] != true {
		t.Fatalf("check = %d %v", code, out)
	}
	if code, out = call("GET", "/v1/security", ""); out["totp_required"] != true || out["app_required_by_class"] != true || out["app_required"] != false {
		t.Fatalf("state = %d %v", code, out)
	}
	if code, _ := call("POST", "/v1/security/totp/disable", `{"code":"123456"}`); code != http.StatusBadRequest {
		t.Fatalf("turning off required two-step verification = %d", code)
	}
}
