package webmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeSecurity stands in for the mailbox service's account-security API.
type fakeSecurity struct {
	mu          sync.Mutex
	totp        bool
	appRequired bool
	codeUsed    bool
	created     []string
	// The class of service the check reports.
	protocols        map[string]bool
	requireTwoFactor bool
	// The company address book /v1/directory returns.
	directory []directoryEntry
	shares    []sharedMailbox
	sendAs    []string
	// Free/busy: what was published, and what lookups return.
	published map[string]any
	freeBusy  []map[string]any
	lookups   []string
	// Allowed and blocked senders, and the most allowed.
	allow, block []string
	maxSenders   int
	maxForward   int
	retention    map[string]int
	// Calendar sharing: what the list returns, and what was changed.
	calendars      calendarShares
	calendarCalls  []string
	calendarDenied bool
}

func (f *fakeSecurity) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		user, pw, _ := r.BasicAuth()
		kind := map[string]string{"secret": "password", "app-pass": "app"}[pw]
		if user != "dana" || kind == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/security/retention" {
			if f.retention == nil {
				f.retention = map[string]int{}
			}
			if r.Method == http.MethodPut {
				var settings []folderRetention
				if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
					http.Error(w, "invalid retention", http.StatusBadRequest)
					return
				}
				for _, setting := range settings {
					if setting.Days < 0 || setting.Days > 36500 {
						http.Error(w, "retention must be 0 to 36500 days", http.StatusBadRequest)
						return
					}
					f.retention[setting.Name] = setting.Days
				}
			}
			out := []folderRetention{}
			for _, name := range []string{"INBOX", "Sent", "Junk", "Trash", "Drafts", "Archive"} {
				out = append(out, folderRetention{Name: name, Days: f.retention[name]})
			}
			for name, days := range f.retention {
				if name != "INBOX" && name != "Sent" && name != "Junk" && name != "Trash" && name != "Drafts" && name != "Archive" {
					out = append(out, folderRetention{Name: name, Days: days})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var in map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&in)
		}
		out := map[string]any{}
		switch {
		case r.URL.Path == "/v1/calendar-shares":
			_ = json.NewEncoder(w).Encode(f.calendars)
			return
		case strings.HasPrefix(r.URL.Path, "/v1/calendar-shares/"):
			level, _ := in["level"].(string)
			f.calendarCalls = append(f.calendarCalls, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+level))
			if f.calendarDenied {
				http.Error(w, "no such account", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		case r.URL.Path == "/v1/security/shares":
			_ = json.NewEncoder(w).Encode(f.shares)
			return
		case r.URL.Path == "/v1/security/send-as":
			if f.sendAs == nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(f.sendAs)
			return
		case r.URL.Path == "/v1/security/senders":
			if r.Method == http.MethodPut {
				toList := func(v any) []string {
					var out []string
					for _, x := range v.([]any) {
						out = append(out, x.(string))
					}
					return out
				}
				allow, block := toList(in["allow"]), toList(in["block"])
				if len(allow)+len(block) > f.maxSenders {
					http.Error(w, "at most 2 allowed and blocked senders", http.StatusBadRequest)
					return
				}
				f.allow, f.block = allow, block
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"allow": f.allow, "block": f.block, "max": f.maxSenders})
			return
		case r.URL.Path == "/v1/directory":
			_ = json.NewEncoder(w).Encode(f.directory)
			return
		case r.URL.Path == "/v1/freebusy" && r.Method == http.MethodPut:
			f.published = in
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		case r.URL.Path == "/v1/freebusy":
			f.lookups = append(f.lookups, r.URL.RawQuery)
			_ = json.NewEncoder(w).Encode(f.freeBusy)
			return
		}
		switch r.URL.Path {
		case "/v1/security/check":
			out = map[string]any{"kind": kind, "totp": f.totp, "app_required": f.appRequired, "protocols": f.protocols, "require_two_factor": f.requireTwoFactor, "max_forward_addresses": f.maxForward}
		case "/v1/security/totp/begin":
			out = map[string]any{"secret": "JBSWY3DPEHPK3PXP", "uri": "otpauth://totp/x"}
		case "/v1/security/totp/confirm":
			if in["code"] != "123456" {
				http.Error(w, "invalid code", http.StatusUnprocessableEntity)
				return
			}
			f.totp = true
			out = map[string]any{"recovery_codes": []string{"aaaa-bbbb", "cccc-dddd"}}
		case "/v1/security":
			out = map[string]any{"totp": f.totp, "app_required": f.appRequired, "recovery_left": 10, "app_passwords": []any{}}
		case "/v1/security/verify":
			if in["code"] != "123456" || f.codeUsed {
				http.Error(w, "invalid code", http.StatusUnprocessableEntity)
				return
			}
			f.codeUsed = true
			out = map[string]any{"recovery": false, "recovery_left": 10}
		case "/v1/security/app-required":
			f.appRequired, _ = in["required"].(bool)
			out = map[string]any{"ok": true}
		case "/v1/security/app-passwords":
			name, _ := in["name"].(string)
			f.created = append(f.created, name)
			out = map[string]any{"app_password": map[string]any{"id": 1, "name": name}, "password": "abcd-efgh-ijkl-mnop"}
		default:
			t.Errorf("unexpected API call %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

func newSecurityHarness(t *testing.T, f *fakeSecurity) *harness {
	t.Helper()
	h := newHarness(t)
	api := httptest.NewServer(f.handler(t))
	t.Cleanup(api.Close)
	h.server.security = newSecurityClient(api.URL)
	// The internal IMAP listener accepts app passwords too.
	h.server.dial = func(_ context.Context, _, pw string) (Mailstore, error) {
		if pw != "secret" && pw != "app-pass" {
			return nil, ErrAuthFailed
		}
		return h.store, nil
	}
	return h
}

func TestSharedMailboxSwitcher(t *testing.T) {
	f := &fakeSecurity{shares: []sharedMailbox{{Mailbox: "support@example.com", Member: "dana@example.com", CanSend: true}}}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	var dialed string
	h.server.dial = func(_ context.Context, user, pw string) (Mailstore, error) {
		dialed = user
		if pw != "secret" {
			return nil, ErrAuthFailed
		}
		return h.store, nil
	}
	resp := h.post("/mail/switch", url.Values{"csrf": {csrf}, "mailbox": {"support@example.com"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("switch = %d", resp.StatusCode)
	}
	_, body := h.get("/mail")
	if dialed != "dana|support@example.com" || !strings.Contains(body, `value="support@example.com" selected`) {
		t.Fatalf("shared mail page used %q: %s", dialed, body[:min(len(body), 500)])
	}
	resp = h.post("/mail/switch", url.Values{"csrf": {csrf}, "mailbox": {"other@example.com"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ungranted switch = %d", resp.StatusCode)
	}
	resp = h.post("/mail/switch", url.Values{"csrf": {csrf}, "mailbox": {""}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("return to own mailbox = %d", resp.StatusCode)
	}
}

func (h *harness) submitLogin(password string) (*http.Response, string) {
	h.t.Helper()
	_, body := h.get("/login")
	m := hiddenRE("token").FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("no login token")
	}
	resp, err := h.client.PostForm(h.srv.URL+"/login", url.Values{"token": {m[1]}, "user": {"dana"}, "password": {password}})
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestTwoStepSignIn(t *testing.T) {
	h := newSecurityHarness(t, &fakeSecurity{totp: true})
	resp, _ := h.submitLogin("secret")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/verify" {
		t.Fatalf("password step = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Nothing needing a session is open halfway through.
	if resp, _ := h.get("/mail"); resp.StatusCode != http.StatusFound {
		t.Fatalf("mail before the code = %d", resp.StatusCode)
	}
	_, page := h.get("/login/verify")
	token := hiddenRE("token").FindStringSubmatch(page)
	if token == nil {
		t.Fatalf("no token on verification page:\n%s", page)
	}
	// The token must come from the form too, not only the cookie.
	if resp := h.post("/login/verify", url.Values{"code": {"123456"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("code without form token = %d", resp.StatusCode)
	}
	if resp := h.post("/login/verify", url.Values{"token": {token[1]}, "code": {"000000"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code = %d", resp.StatusCode)
	}
	resp = h.post("/login/verify", url.Values{"token": {token[1]}, "code": {"123456"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/mail" {
		t.Fatalf("right code = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.get("/mail"); resp.StatusCode != http.StatusOK {
		t.Fatalf("mail after the code = %d", resp.StatusCode)
	}
	// The pending sign-in is spent.
	if resp := h.post("/login/verify", url.Values{"token": {token[1]}, "code": {"123456"}}); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("pending sign-in reused")
	}
}

func TestAppPasswordCannotOpenWebmail(t *testing.T) {
	h := newSecurityHarness(t, &fakeSecurity{totp: true})
	resp, body := h.submitLogin("app-pass")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "app password") {
		t.Fatalf("app password sign-in = %d", resp.StatusCode)
	}
	if resp, _ := h.get("/mail"); resp.StatusCode != http.StatusFound {
		t.Fatal("app password opened a session")
	}
}

func TestDAVHonoursAppPasswordRequirement(t *testing.T) {
	f := &fakeSecurity{appRequired: true}
	h := newSecurityHarness(t, f)
	propfind := func(password string) int {
		req, _ := http.NewRequest("PROPFIND", h.srv.URL+"/dav/", strings.NewReader(""))
		req.Header.Set("Depth", "0")
		req.SetBasicAuth("dana", password)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := propfind("secret"); code != http.StatusUnauthorized {
		t.Fatalf("account password with the requirement = %d", code)
	}
	if code := propfind("app-pass"); code == http.StatusUnauthorized {
		t.Fatal("app password refused")
	}
	f.mu.Lock()
	f.appRequired = false
	f.mu.Unlock()
	if code := propfind("secret"); code == http.StatusUnauthorized {
		t.Fatal("account password refused without the requirement")
	}
}

func TestSecuritySettings(t *testing.T) {
	f := &fakeSecurity{}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	_, page := h.get("/settings/security")
	if !strings.Contains(page, "Set up two-step verification") || !strings.Contains(page, "Create app password") {
		t.Fatal("security card missing")
	}
	resp, err := h.client.PostForm(h.srv.URL+"/settings/app-passwords", url.Values{"csrf": {csrf}, "name": {"Thunderbird"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "abcd-efgh-ijkl-mnop") {
		t.Fatalf("new app password not shown: %d", resp.StatusCode)
	}
	if len(f.created) != 1 || f.created[0] != "Thunderbird" {
		t.Fatalf("created = %v", f.created)
	}
	// Changes need the session's CSRF token like every other form.
	if resp := h.post("/settings/app-passwords", url.Values{"name": {"x"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without CSRF = %d", resp.StatusCode)
	}
}

func TestBlockSenderPreservesRulesAndLimit(t *testing.T) {
	f := &fakeSecurity{allow: []string{"friend@example.org", "priya@northwind.example"}, block: []string{"old@example.org"}, maxSenders: 3}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	_, page := h.get("/mail?f=INBOX&uid=7")
	if !strings.Contains(page, `>Block sender</button>`) || !strings.Contains(page, `name="sender" value="priya@northwind.example"`) {
		t.Fatal("message view lacks the sender action")
	}
	form := url.Values{"csrf": {csrf}, "sender": {"priya@northwind.example"}, "back": {"/mail?f=INBOX&uid=7"}}
	if resp := h.post("/mail/block-sender", form); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "sender-blocked") {
		t.Fatalf("block response: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !slices.Equal(f.allow, []string{"friend@example.org"}) || !slices.Equal(f.block, []string{"old@example.org", "priya@northwind.example"}) {
		t.Fatalf("rules after block: allow=%v block=%v", f.allow, f.block)
	}
	if resp := h.post("/mail/block-sender", form); resp.StatusCode != http.StatusSeeOther || len(f.block) != 2 {
		t.Fatalf("repeat block: %d block=%v", resp.StatusCode, f.block)
	}
	form.Set("sender", "new@example.org")
	if resp := h.post("/mail/block-sender", form); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("over-limit block = %d", resp.StatusCode)
	}
	if len(f.block) != 2 || len(f.allow) != 1 {
		t.Fatalf("failed block changed rules: allow=%v block=%v", f.allow, f.block)
	}
}

func TestRetentionSettingsAndCustomFolder(t *testing.T) {
	f := &fakeSecurity{retention: map[string]int{"Projects": 0}}
	h := newSecurityHarness(t, f)
	csrf := h.login()
	if err := h.store.CreateFolder(context.Background(), "Projects"); err != nil {
		t.Fatal(err)
	}
	_, page := h.get("/settings/account")
	if !strings.Contains(page, `id="retention"`) || !strings.Contains(page, `id="retention-trash"`) || !strings.Contains(page, `id="retention-junk"`) || !strings.Contains(page, `id="retention-sent"`) {
		t.Fatal("account settings lack the three retention controls")
	}
	form := url.Values{"csrf": {csrf}, "folder": {"Trash", "Junk", "Sent"}, "days": {"7", "14", "30"}}
	if resp := h.post("/settings/retention", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save retention = %d", resp.StatusCode)
	}
	if f.retention["Trash"] != 7 || f.retention["Junk"] != 14 || f.retention["Sent"] != 30 {
		t.Fatalf("saved special folder retention = %v", f.retention)
	}
	_, page = h.get("/folders")
	if !strings.Contains(page, `action="/folders/retention"`) || !strings.Contains(page, `value="Projects"`) {
		t.Fatal("custom folder lacks a retention form")
	}
	resp, body := h.get("/folders/retention?folder=Projects")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"days":0`) {
		t.Fatalf("custom folder retention lookup = %d %s", resp.StatusCode, body)
	}
	if resp := h.post("/folders/retention", url.Values{"csrf": {csrf}, "folder": {"Projects"}, "days": {"21"}, "back": {"/mail?f=Projects"}}); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "retention-saved") {
		t.Fatalf("custom folder save = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.retention["Projects"] != 21 {
		t.Fatalf("custom folder retention = %d", f.retention["Projects"])
	}
	if resp := h.post("/folders/retention", url.Values{"csrf": {csrf}, "folder": {"Projects"}, "days": {"36501"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid retention = %d", resp.StatusCode)
	}
	if f.retention["Projects"] != 21 {
		t.Fatal("invalid retention was stored")
	}
}

func TestTOTPURIAndQR(t *testing.T) {
	uri := totpURI(totpIssuer("dana@example.com"), "dana@example.com", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(uri, "otpauth://totp/Elemta%20Mail%20%28example.com%29:dana@example.com?") || !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("uri = %s", uri)
	}
	img, err := qrDataURI(uri)
	if err != nil || !strings.HasPrefix(string(img), "data:image/png;base64,") {
		t.Fatalf("qr = %.40s %v", img, err)
	}
	if got := groupSecret("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Errorf("groupSecret = %q", got)
	}
}

// Settings are split into tabs, each with its own address in the settings
// sidebar, and changes return to the card they were made in, with the notice
// there rather than at the top of the page.
func TestSettingsTabs(t *testing.T) {
	h := newSecurityHarness(t, &fakeSecurity{})
	csrf := h.login()
	tabs := map[string][]string{
		"/settings":          {`action="/settings#general"`, `id="display_name"`},
		"/settings/account":  {"<h1>Account</h1>"},
		"/settings/security": {`action="/settings/2fa/begin#two-step"`, `action="/settings/app-passwords#app-passwords"`, `action="/settings/app-required#app-passwords"`},
		"/settings/devices":  {"993", "587", "/dav/", "/contacts/export"},
		"/filters":           {"Filters and out-of-office"},
		"/folders":           {`action="/folders"`},
	}
	for path, wants := range tabs {
		resp, page := h.get(path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
		for _, want := range wants {
			if !strings.Contains(page, want) {
				t.Errorf("%s lacks %s", path, want)
			}
		}
		// The sidebar marks the tab and the top bar marks Settings.
		if !strings.Contains(page, `href="`+path+`" aria-current="page"`) || !strings.Contains(page, `href="/settings" title="Settings" aria-current="page"`) {
			t.Errorf("%s: current tab not marked", path)
		}
		if strings.Contains(page, "Manage folders") {
			t.Errorf("%s shows the mail sidebar", path)
		}
	}
	// One tab doesn't carry another's forms.
	if _, page := h.get("/settings"); strings.Contains(page, "/settings/password") || strings.Contains(page, "2fa/begin") {
		t.Error("general tab carries other tabs' forms")
	}
	resp := h.post("/settings", url.Values{"csrf": {csrf}, "display_name": {"Dana"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "#general") {
		t.Fatalf("save redirect = %q", loc)
	}
	resp = h.post("/settings/app-required", url.Values{"csrf": {csrf}, "required": {"1"}})
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/settings/security?") || !strings.HasSuffix(loc, "#app-passwords") {
		t.Fatalf("security redirect = %q", loc)
	}
	_, page := h.get(strings.Split(loc, "#")[0])
	card := page[strings.Index(page, `id="app-passwords"`):]
	if !strings.Contains(card, notices["app-required"]) || strings.Count(page, notices["app-required"]) != 1 {
		t.Fatal("notice not shown once, in the app passwords card")
	}
}

// TestClassOfServiceInWebmail covers the switches the webmail applies for
// the mailbox service: webmail access itself, DAV, and required two-step
// verification, which is set up during sign-in before any session exists.
func TestClassOfServiceInWebmail(t *testing.T) {
	f := &fakeSecurity{protocols: map[string]bool{"webmail": false}}
	h := newSecurityHarness(t, f)
	resp, body := h.submitLogin("secret")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Webmail is turned off") {
		t.Fatalf("webmail turned off: %d", resp.StatusCode)
	}

	// DAV turned off refuses sync apps with 403, even with the right password.
	f.mu.Lock()
	f.protocols = map[string]bool{"dav": false}
	f.mu.Unlock()
	if resp := davRequest(t, h, "PROPFIND", "/dav/", "dana", "secret", "", map[string]string{"Depth": "0"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DAV turned off = %d", resp.StatusCode)
	}

	// Required two-step verification: sign-in leads through setup.
	f.mu.Lock()
	f.protocols, f.requireTwoFactor = nil, true
	f.mu.Unlock()
	resp, _ = h.submitLogin("secret")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/setup" {
		t.Fatalf("required setup = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.get("/mail"); resp.StatusCode != http.StatusFound {
		t.Fatalf("mail before setup = %d", resp.StatusCode)
	}
	_, page := h.get("/login/setup")
	token := hiddenRE("token").FindStringSubmatch(page)
	secret := hiddenRE("secret").FindStringSubmatch(page)
	if token == nil || secret == nil || !strings.Contains(page, "data:image/png;base64,") {
		t.Fatalf("setup page:\n%s", page)
	}
	if resp := h.post("/login/setup", url.Values{"secret": {secret[1]}, "code": {"123456"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("setup without the form token = %d", resp.StatusCode)
	}
	if resp := h.post("/login/setup", url.Values{"token": {token[1]}, "secret": {secret[1]}, "code": {"000000"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("wrong setup code = %d", resp.StatusCode)
	}
	resp, err := h.client.PostForm(h.srv.URL+"/login/setup", url.Values{"token": {token[1]}, "secret": {secret[1]}, "code": {"123456"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "aaaa-bbbb") {
		t.Fatalf("setup confirmed = %d\n%s", resp.StatusCode, b)
	}
	if resp, _ := h.get("/mail"); resp.StatusCode != http.StatusOK {
		t.Fatalf("mail after setup = %d", resp.StatusCode)
	}
}

func TestCompanyDirectoryInAutocomplete(t *testing.T) {
	f := &fakeSecurity{directory: []directoryEntry{
		{Address: "lee@example.com", Name: "Lee Park", Kind: "account"},
		{Address: "team@example.com", Name: "Team", Kind: "list"},
	}}
	h := newSecurityHarness(t, f)
	if resp, _ := h.submitLogin("secret"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in = %d", resp.StatusCode)
	}
	// Someone already in contacts isn't offered twice.
	card := "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:lee\r\nFN:Lee P.\r\nEMAIL:lee@example.com\r\nEND:VCARD\r\n"
	if err := h.store.PutObject(context.Background(), CollContacts, Object{ID: "lee", Data: []byte(card)}); err != nil {
		t.Fatal(err)
	}
	_, js := h.get("/api/addresses")
	var sugg []struct {
		Label, Value string
		Directory    bool
	}
	if err := json.Unmarshal([]byte(js), &sugg); err != nil {
		t.Fatal(err)
	}
	labels := map[string]bool{}
	for _, s := range sugg {
		labels[s.Label] = s.Directory
	}
	if !labels["Team <team@example.com> (list)"] {
		t.Errorf("the list from the address book is missing: %s", js)
	}
	if _, dup := labels["Lee Park <lee@example.com>"]; dup {
		t.Errorf("a contact was offered again from the address book: %s", js)
	}
	// Without the mailbox's answer autocomplete still works.
	f.mu.Lock()
	f.directory = nil
	f.mu.Unlock()
	if resp, _ := h.get("/api/addresses"); resp.StatusCode != http.StatusOK {
		t.Fatalf("addresses without directory = %d", resp.StatusCode)
	}
}
