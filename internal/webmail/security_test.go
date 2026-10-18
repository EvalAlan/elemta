package webmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		var in map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&in)
		}
		out := map[string]any{}
		switch r.URL.Path {
		case "/v1/security/check":
			out = map[string]any{"kind": kind, "totp": f.totp, "app_required": f.appRequired}
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
