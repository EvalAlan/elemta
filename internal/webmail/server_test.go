package webmail

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory Mailstore for handler tests.
type fakeStore struct {
	mu        sync.Mutex
	folders   []Folder
	messages  map[string][]Summary
	raw       map[uint32][]byte
	appended  map[Role][][]byte
	seen      map[uint32]bool
	moved     map[uint32]string
	deleted   []uint32
	flags     map[uint32]map[string]bool
	emptied   []string
	expunged  []uint32
	allRead   []string
	objects   map[Collection]map[string]Object
	lastQuery ListQuery
	related   []Related
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		folders: []Folder{
			{Name: "INBOX", Display: "INBOX", Role: RoleInbox, Total: 1, Unread: 1, Selectable: true},
			{Name: "Sent", Display: "Sent", Role: RoleSent, Selectable: true},
			{Name: "Junk", Display: "Junk", Role: RoleJunk, Selectable: true},
		},
		messages: map[string][]Summary{"INBOX": {{UID: 7, Subject: "Signed MSA", From: []Address{{Name: "Priya Shah", Email: "priya@northwind.example"}}, Date: time.Now()}}},
		raw:      map[uint32][]byte{7: []byte(multipartMessage)},
		appended: map[Role][][]byte{},
		seen:     map[uint32]bool{},
		moved:    map[uint32]string{},
		flags:    map[uint32]map[string]bool{},
		objects:  map[Collection]map[string]Object{},
	}
}

func (f *fakeStore) Folders(context.Context) ([]Folder, error) { return f.folders, nil }
func (f *fakeStore) List(_ context.Context, folder string, q ListQuery) (Page, error) {
	f.mu.Lock()
	f.lastQuery = q
	f.mu.Unlock()
	msgs := f.messages[folder]
	return Page{Folder: folder, Messages: msgs, Total: len(msgs), Page: 1, PageSize: q.PageSize}, nil
}
func (f *fakeStore) Raw(_ context.Context, _ string, uid uint32, _ int64) ([]byte, error) {
	if b, ok := f.raw[uid]; ok {
		return b, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) SetFlags(_ context.Context, _ string, uids []uint32, flags []string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range uids {
		for _, fl := range flags {
			if fl == FlagSeen {
				f.seen[u] = on
			}
			if f.flags[u] == nil {
				f.flags[u] = map[string]bool{}
			}
			f.flags[u][fl] = on
		}
	}
	return nil
}
func (f *fakeStore) Move(_ context.Context, _ string, uids []uint32, dest string) error {
	for _, u := range uids {
		f.moved[u] = dest
	}
	return nil
}
func (f *fakeStore) Delete(_ context.Context, _ string, uids []uint32) error {
	f.deleted = append(f.deleted, uids...)
	return nil
}
func (f *fakeStore) Expunge(_ context.Context, _ string, uids []uint32) error {
	f.expunged = append(f.expunged, uids...)
	return nil
}
func (f *fakeStore) Append(_ context.Context, role Role, raw []byte, _, _ bool) error {
	f.mu.Lock()
	f.appended[role] = append(f.appended[role], raw)
	f.mu.Unlock()
	return nil
}
func (f *fakeStore) CreateFolder(_ context.Context, name string) error {
	for _, x := range f.folders {
		if x.Name == name {
			return ErrExists
		}
	}
	f.folders = append(f.folders, Folder{Name: name, Display: name, Selectable: true})
	return nil
}
func (f *fakeStore) EnsureFolders(_ context.Context, roles []Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, role := range roles {
		found := false
		for _, x := range f.folders {
			if x.Role == role {
				found = true
			}
		}
		if !found {
			name := defaultRoleNames[role]
			f.folders = append(f.folders, Folder{Name: name, Display: name, Role: role, Selectable: true})
		}
	}
	return nil
}
func (f *fakeStore) RenameFolder(_ context.Context, from, to string) error {
	for i := range f.folders {
		if f.folders[i].Name == from {
			f.folders[i].Name, f.folders[i].Display = to, to
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeStore) DeleteFolder(_ context.Context, name string) error {
	for i := range f.folders {
		if f.folders[i].Name == name {
			f.folders = append(f.folders[:i], f.folders[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeStore) MarkAllRead(_ context.Context, folder string) error {
	f.mu.Lock()
	f.allRead = append(f.allRead, folder)
	f.mu.Unlock()
	return nil
}
func (f *fakeStore) EmptyFolder(_ context.Context, folder string) error {
	f.emptied = append(f.emptied, folder)
	return nil
}
func (f *fakeStore) Related(_ context.Context, folders []string, ids []string) ([]Related, error) {
	return f.related, nil
}
func (f *fakeStore) Delimiter(context.Context) (string, error)      { return "/", nil }
func (f *fakeStore) Tags(context.Context, string) ([]string, error) { return []string{"invoices"}, nil }
func (f *fakeStore) Objects(_ context.Context, c Collection) ([]Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Object
	for _, o := range f.objects[c] {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (f *fakeStore) PutObject(_ context.Context, c Collection, obj Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[c] == nil {
		f.objects[c] = map[string]Object{}
	}
	f.objects[c][objectID(obj.ID)] = obj
	return nil
}
func (f *fakeStore) DeleteObject(_ context.Context, c Collection, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects[c], id)
	return nil
}
func (f *fakeStore) Close() error { return nil }

type fakeSubmitter struct {
	user, pass, from string
	rcpts            []string
	raw              []byte
	err              error
}

func (f *fakeSubmitter) Submit(_ context.Context, user, pass, from string, rcpts []string, raw []byte) error {
	f.user, f.pass, f.from, f.rcpts, f.raw = user, pass, from, rcpts, raw
	return f.err
}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	store  *fakeStore
	sub    *fakeSubmitter
	server *Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store := newFakeStore()
	sub := &fakeSubmitter{}
	insecure := false
	cfg := Config{IMAPAddr: "imap.test:143", SubmissionAddr: "smtp.test:587", SecureCookies: &insecure, DefaultDomain: "example.com"}
	dial := func(_ context.Context, user, pw string) (Mailstore, error) {
		if pw != "secret" {
			return nil, ErrAuthFailed
		}
		return store, nil
	}
	s, err := NewServer(cfg, dial, sub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{t: t, srv: srv, client: client, store: store, sub: sub, server: s}
}

func (h *harness) get(path string) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (h *harness) post(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.srv.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

var hiddenRE = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`name="` + name + `" value="([^"]+)"`)
}

// login signs in and returns the session's CSRF token.
func (h *harness) login() string {
	h.t.Helper()
	_, body := h.get("/login")
	m := hiddenRE("token").FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("no login token in page:\n%s", body)
	}
	resp := h.post("/login", url.Values{"token": {m[1]}, "user": {"dana"}, "password": {"secret"}})
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login status = %d", resp.StatusCode)
	}
	_, body = h.get("/mail")
	c := hiddenRE("csrf").FindStringSubmatch(body)
	if c == nil {
		h.t.Fatalf("no csrf token on mail page")
	}
	return c[1]
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.get("/mail")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = h.get("/mail/raw?f=INBOX&uid=7")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("raw without session = %d", resp.StatusCode)
	}
}

func TestLoginRequiresFormToken(t *testing.T) {
	h := newHarness(t)
	resp := h.post("/login", url.Values{"user": {"dana"}, "password": {"secret"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login without token = %d, want 403", resp.StatusCode)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h := newHarness(t)
	_, body := h.get("/login")
	tok := hiddenRE("token").FindStringSubmatch(body)[1]
	resp := h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"nope"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMailPageShowsMessageAndMarksSeen(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, body := h.get("/mail?f=INBOX&uid=7")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d\n%s", resp.StatusCode, body)
	}
	for _, want := range []string{"Signed MSA", "Priya Shah", "MSA countersigned.pdf", "DKIM pass", `sandbox="allow-popups allow-popups-to-escape-sandbox"`, "dana@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if !h.store.seen[7] {
		t.Error("opening a message did not mark it seen")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Errorf("page CSP = %q", csp)
	}
}

func TestMessageBodyIsSandboxed(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, body := h.get("/mail/body?f=INBOX&uid=7")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "sandbox ") || strings.Contains(csp, "allow-scripts") || strings.Contains(csp, "allow-same-origin") {
		t.Errorf("body CSP = %q", csp)
	}
	if !strings.Contains(body, "data:image/png;base64,") || strings.Contains(body, "cid:") {
		t.Errorf("cid image not inlined:\n%s", body)
	}
}

func TestAttachmentDownloadIsNeverInline(t *testing.T) {
	h := newHarness(t)
	h.login()
	m, _ := parseMessage([]byte(multipartMessage))
	idx := m.Attachments()[0].Index
	resp, body := h.get("/mail/part?f=INBOX&uid=7&n=" + strconv.Itoa(idx))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type = %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "MSA countersigned.pdf") {
		t.Errorf("disposition = %q", cd)
	}
	if !strings.HasPrefix(body, "%PDF") {
		t.Errorf("body = %q", body)
	}
}

func TestActionsNeedCSRF(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/mail/action", url.Values{"f": {"INBOX"}, "uid": {"7"}, "op": {"delete"}})
	if resp.StatusCode != http.StatusForbidden || len(h.store.deleted) != 0 {
		t.Fatalf("delete without CSRF: status %d deleted %v", resp.StatusCode, h.store.deleted)
	}
	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"delete"}})
	if resp.StatusCode != http.StatusSeeOther || len(h.store.deleted) != 1 {
		t.Fatalf("delete with CSRF: status %d deleted %v", resp.StatusCode, h.store.deleted)
	}
	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"junk"}})
	if resp.StatusCode != http.StatusSeeOther || h.store.moved[7] != "Junk" {
		t.Fatalf("junk: status %d moved %v", resp.StatusCode, h.store.moved)
	}
}

func TestComposeSendsAndSavesCopy(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range map[string]string{
		"csrf": csrf, "op": "send", "to": "Priya Shah <priya@northwind.example>; jonas@example.com",
		"bcc": "archive@example.com", "subject": "Kickoff", "body": "See you Tuesday.",
	} {
		_ = w.WriteField(k, v)
	}
	fw, _ := w.CreateFormFile("attachments", "agenda.txt")
	_, _ = fw.Write([]byte("1. intros"))
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/compose", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "n=sent") {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if h.sub.user != "dana" || h.sub.pass != "secret" || h.sub.from != "dana@example.com" {
		t.Errorf("submitted as %q/%q from %q", h.sub.user, h.sub.pass, h.sub.from)
	}
	if strings.Join(h.sub.rcpts, ",") != "priya@northwind.example,jonas@example.com,archive@example.com" {
		t.Errorf("rcpts = %v", h.sub.rcpts)
	}
	if !strings.Contains(string(h.sub.raw), "agenda.txt") || strings.Contains(string(h.sub.raw), "archive@example.com") {
		t.Errorf("raw message wrong:\n%s", h.sub.raw)
	}
	if len(h.store.appended[RoleSent]) != 1 {
		t.Errorf("sent copy not saved")
	}
}

func TestComposeRejectsBadAddress(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf", csrf)
	_ = w.WriteField("op", "send")
	_ = w.WriteField("to", "not an address")
	_ = w.Close()
	resp, err := h.client.Post(h.srv.URL+"/compose", w.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "Check the addresses in To") || h.sub.raw != nil {
		t.Fatalf("status %d submitted=%v", resp.StatusCode, h.sub.raw != nil)
	}
}

func TestReplyPrefill(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, body := h.get("/compose?mode=replyall&f=INBOX&uid=7")
	for _, want := range []string{"Re: Signed MSA", "priya@northwind.example", "marcus@example.com", "legal@northwind.example", "&gt; Café at ten.", "&lt;msa@northwind.example&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("reply-all prefill missing %q", want)
		}
	}
	if strings.Contains(body, `value="dana@example.com`) {
		t.Error("reply-all copied the sender's own address")
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/logout", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	resp, _ = h.get("/mail")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("after logout /mail = %d", resp.StatusCode)
	}
}

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter(time.Minute)
	for i := 0; i < 3; i++ {
		if l.blocked("ip", 3) {
			t.Fatalf("blocked after %d failures", i)
		}
		l.fail("ip")
	}
	if !l.blocked("ip", 3) {
		t.Fatal("not blocked after 3 failures")
	}
	l.reset("ip")
	if l.blocked("ip", 3) {
		t.Fatal("reset did not clear")
	}
}

func TestSuccessfulSignInsAreNotThrottled(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxFailuresPerIP+5; i++ {
		_, body := h.get("/login")
		tok := hiddenRE("token").FindStringSubmatch(body)[1]
		resp := h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"secret"}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in %d = %d", i+1, resp.StatusCode)
		}
		h.post("/logout", url.Values{"csrf": {hiddenRE("csrf").FindStringSubmatch(func() string { _, b := h.get("/mail"); return b }())[1]}})
	}
	// Failures still lock the account out.
	for i := 0; i < maxFailuresPerUser; i++ {
		_, body := h.get("/login")
		tok := hiddenRE("token").FindStringSubmatch(body)[1]
		h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"wrong"}})
	}
	_, body := h.get("/login")
	tok := hiddenRE("token").FindStringSubmatch(body)[1]
	if resp := h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"secret"}}); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after %d failures the right password got %d, want 429", maxFailuresPerUser, resp.StatusCode)
	}
}
