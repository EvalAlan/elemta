//go:build browser

package api

// Drives the admin console in headless Chromium, for what the HTTP tests can't
// see: that the script runs under the page's CSP and the dialog really renders.
// Needs Chromium (CHROME_PATH, or chromium/google-chrome on PATH).
//
//	go test -tags browser -run Browser ./internal/api/

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/auth"
	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
)

func chromePath(t *testing.T) string {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("no Chromium found; set CHROME_PATH")
	return ""
}

func TestBrowserDomainDNSHealth(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	// The login page is found relative to where the server runs.
	t.Chdir("../..")
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		s.webRoot = webRoot
		s.dnsHealth = func(_ context.Context, o dnshealth.Options) dnshealth.Report {
			return dnshealth.Report{Domain: o.Domain, Status: dnshealth.StatusFail, Checks: []dnshealth.Check{
				{ID: "mx", Name: "Incoming mail (MX)", Status: dnshealth.StatusOK, Summary: "Incoming mail reaches this server.", Found: []string{"10 mail.example.com → 192.0.2.1"}},
				{ID: "spf", Name: "Sending permission (SPF)", Status: dnshealth.StatusFail, Summary: "No SPF record.", Fix: "Publish this TXT record at example.com.", Record: "v=spf1 mx -all"},
				{ID: "dmarc", Name: "Forgery policy (DMARC)", Status: dnshealth.StatusWarn, Summary: "<b>not markup</b>"},
				{ID: "tls-rpt", Name: "Encryption reports (TLS-RPT)", Status: dnshealth.StatusInfo, Summary: "Not set up."},
				{ID: "ptr", Name: "Reverse DNS", Status: dnshealth.StatusUnknown, Summary: "The lookup failed."},
			}}
		}
	})

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.WindowSize(1280, 1100), chromedp.NoSandbox)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 60*time.Second)
	defer cancel()

	var mu sync.Mutex
	var problems []string
	// Subscribing starts the browser, so it can't wait for the goroutine.
	exceptions := chromedp.Events(browserCtx, runtime.ExceptionThrown)
	go func() {
		for ev, err := range exceptions {
			if err != nil {
				return
			}
			mu.Lock()
			problems = append(problems, (&chromedp.ExceptionError{ExceptionDetails: ev.ExceptionDetails}).Error())
			mu.Unlock()
		}
	}()
	require.NoError(t, chromedp.Do(ctx, chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		_, err := cdp.Call(ctx, tg, runtime.Enable, cdp.Empty{})
		return err
	})))

	click := func(selector string) chromedp.Action[chromedp.Void] {
		return chromedp.Click(chromedp.CSS(selector), chromedp.NodeVisible)
	}
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		// A click, because Submit skips the form's onsubmit handler.
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.ID("nav-mailadmin")),
		click("#nav-mailadmin"),
		chromedp.WaitVisible(chromedp.CSS("[data-ma-tab=domains]")),
		click("[data-ma-tab=domains]"),
		chromedp.WaitVisible(chromedp.CSS("#ma-table-body .ma-account-link")),
		click("#ma-table-body .ma-account-link"),
		chromedp.WaitVisible(chromedp.ID("ma-domain-health-run")),
		click("#ma-domain-health-run"),
		chromedp.WaitVisible(chromedp.CSS(".ma-health-fail")),
	))
	text := func(expr string) string {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Evaluate[string](expr))
		require.NoError(t, err)
		return v
	}
	if shot := os.Getenv("ELEMTA_TEST_SCREENSHOT"); shot != "" {
		png, err := chromedp.Run(ctx, chromedp.Screenshot(chromedp.ID("ma-domain-dialog")))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(shot, png, 0o600))
	}
	require.Contains(t, text(`document.getElementById("ma-domain-health-summary").textContent`), "Something is wrong")
	results := text(`document.getElementById("ma-domain-health-results").textContent`)
	for _, want := range []string{"Incoming mail (MX)", "Problem", "Needs attention", "Optional", "Couldn't check", "Publish this TXT record"} {
		require.Contains(t, results, want)
	}
	require.Equal(t, "v=spf1 mx -all", text(`document.querySelector("#ma-domain-health-results .ma-key-field code").textContent`))
	// DNS is written by whoever controls the zone, so it must never become markup.
	require.Contains(t, results, "<b>not markup</b>")
	require.Equal(t, "0", text(`String(document.querySelectorAll("#ma-domain-health-results b").length)`))
	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, problems)
}

// The Health page shows what the scheduled DNS check last found, failing
// domains first, and what DNS said stays text.
func TestBrowserHealthDNSCard(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		s.webRoot = webRoot
		reports := []dnshealth.Report{
			{Domain: "example.com", Checks: []dnshealth.Check{{ID: "mx", Name: "Incoming mail (MX)", Status: dnshealth.StatusOK}}},
			{Domain: "example.net", Checks: []dnshealth.Check{
				{ID: "spf", Name: "Sending permission (SPF)", Status: dnshealth.StatusFail, Summary: "<b>not markup</b>", Fix: "Publish this TXT record at example.net.", Record: "v=spf1 mx -all"},
			}},
		}
		next, _ := dnsChanges(dnsWatchState{}, reports)
		s.saveDNSWatch(recordSweep(dnsWatchFile{}, next, reports, time.Now().UTC()))
	})

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.WindowSize(1280, 1100), chromedp.NoSandbox)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 60*time.Second)
	defer cancel()

	click := func(selector string) chromedp.Action[chromedp.Void] {
		return chromedp.Click(chromedp.CSS(selector), chromedp.NodeVisible)
	}
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.CSS("[data-view=health]")),
		click("[data-view=health]"),
		chromedp.WaitVisible(chromedp.CSS("#dns-health-body .dns-health-problems")),
	))
	text := func(expr string) string {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Evaluate[string](expr))
		require.NoError(t, err)
		return v
	}
	if shot := os.Getenv("ELEMTA_TEST_SCREENSHOT"); shot != "" {
		require.NoError(t, chromedp.Do(ctx, chromedp.ScrollIntoView(chromedp.ID("dns-health-card")), chromedp.Sleep(500*time.Millisecond)))
		png, err := chromedp.Run(ctx, chromedp.Screenshot(chromedp.ID("dns-health-card")))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(shot, png, 0o600))
	}
	card := text(`document.getElementById("dns-health-body").textContent`)
	for _, want := range []string{"1 domain has DNS problems.", "example.net", "Failing", "Sending permission (SPF)", "Publish this TXT record", "v=spf1 mx -all", "example.com", "OK"} {
		require.Contains(t, card, want)
	}
	require.Less(t, strings.Index(card, "example.net"), strings.Index(card, "example.com"), "failing domain first")
	require.Contains(t, card, "<b>not markup</b>")
	require.Equal(t, "0", text(`String(document.querySelectorAll("#dns-health-body b").length)`))
}

// A compliance officer sees their own section and nothing of the server's,
// and found mail, written by anyone, is shown as text.
func TestBrowserComplianceSearch(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	base, fake := startComplianceServer(t, webRoot)

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.WindowSize(1280, 1100), chromedp.NoSandbox)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 60*time.Second)
	defer cancel()
	var mu sync.Mutex
	var problems []string
	exceptions := chromedp.Events(browserCtx, runtime.ExceptionThrown)
	go func() {
		for ev, err := range exceptions {
			if err != nil {
				return
			}
			mu.Lock()
			problems = append(problems, (&chromedp.ExceptionError{ExceptionDetails: ev.ExceptionDetails}).Error())
			mu.Unlock()
		}
	}()
	require.NoError(t, chromedp.Do(ctx, chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		_, err := cdp.Call(ctx, tg, runtime.Enable, cdp.Empty{})
		return err
	})))
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "officer"),
		chromedp.SendKeys(chromedp.ID("password"), testUserPassword),
		chromedp.Click(chromedp.CSS("#login-btn"), chromedp.NodeVisible),
		// Confined to their section, the console opens on it.
		chromedp.WaitVisible(chromedp.ID("compliance-form")),
		chromedp.SendKeys(chromedp.ID("compliance-text"), "merger"),
		chromedp.SendKeys(chromedp.ID("compliance-since"), "01012026"),
		chromedp.Click(chromedp.CSS("#compliance-form button[type=submit]"), chromedp.NodeVisible),
		chromedp.WaitVisible(chromedp.CSS("#compliance-hits a")),
	))
	eval := func(expr string) string {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Evaluate[string](expr))
		require.NoError(t, err)
		return v
	}
	nav := eval(`[...document.querySelectorAll(".nav-item[data-view]")].filter(a => a.offsetParent !== null).map(a => a.dataset.view).join(",")`)
	require.Equal(t, "compliance,settings", nav)
	rows := eval(`document.getElementById("compliance-hits").textContent`)
	require.Contains(t, rows, "dana@example.com")
	require.Contains(t, rows, "found <b>not markup</b>")
	require.Contains(t, rows, "2 KB")
	require.Equal(t, "0", eval(`String(document.querySelectorAll("#compliance-hits b").length)`))
	require.Contains(t, eval(`document.getElementById("compliance-unindexed").textContent`), "2 messages")
	require.Contains(t, eval(`document.querySelector("#compliance-hits a").href`), "/api/compliance/message?ref=m%3A7%3A3")
	fake.mu.Lock()
	require.Len(t, fake.queries, 1)
	require.Equal(t, "merger", fake.queries[0].Text)
	require.Equal(t, 2026, fake.queries[0].Since.Year())
	fake.mu.Unlock()

	// The export downloads in the background and leaves the console open.
	require.NoError(t, chromedp.Do(ctx, chromedp.Click(chromedp.ID("compliance-export"), chromedp.NodeVisible)))
	deadline := time.Now().Add(10 * time.Second)
	for {
		fake.mu.Lock()
		n := len(fake.queries)
		fake.mu.Unlock()
		if n == 2 || time.Now().After(deadline) {
			require.Equal(t, 2, n, "the export never reached the mailbox")
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, base+"/", eval(`location.origin + location.pathname`))
	require.NotEmpty(t, eval(`document.getElementById("compliance-hits").textContent`))
	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, problems)
}

// A passkey, end to end, with Chrome's virtual authenticator: added under
// Settings > Users, then used alone to sign in, and as the second step after
// the password.
func TestBrowserConsolePasskey(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	hash, err := auth.HashPassword(testAdminPassword)
	require.NoError(t, err)
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	require.NoError(t, os.WriteFile(users, []byte("root:"+hash+":admin\n"), 0o600))
	s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: webRoot, AuthEnabled: true, AuthFile: users}, nil, dir, 0, "")
	require.NoError(t, err)
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Stop() })
	_, port, _ := net.SplitHostPort(waitReady(t, s))
	// A passkey belongs to a host name, and only localhost may be plain HTTP.
	base := "http://localhost:" + port

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.WindowSize(1280, 1100), chromedp.NoSandbox)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 90*time.Second)
	defer cancel()
	var mu sync.Mutex
	var problems []string
	exceptions := chromedp.Events(browserCtx, runtime.ExceptionThrown)
	go func() {
		for ev, err := range exceptions {
			if err != nil {
				return
			}
			mu.Lock()
			problems = append(problems, (&chromedp.ExceptionError{ExceptionDetails: ev.ExceptionDetails}).Error())
			mu.Unlock()
		}
	}()
	require.NoError(t, chromedp.Do(ctx, chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		if _, err := cdp.Call(ctx, tg, runtime.Enable, cdp.Empty{}); err != nil {
			return err
		}
		if _, err := cdp.Call(ctx, tg, cdpwebauthn.Enable, cdpwebauthn.EnableParams{}); err != nil {
			return err
		}
		_, err := cdp.Call(ctx, tg, cdpwebauthn.AddVirtualAuthenticator, cdpwebauthn.AddVirtualAuthenticatorParams{Options: &cdpwebauthn.VirtualAuthenticatorOptions{
			Protocol: cdpwebauthn.AuthenticatorProtocolCtap2, Ctap2version: cdpwebauthn.Ctap2versionCtap21, Transport: cdpwebauthn.AuthenticatorTransportInternal,
			HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true,
		}})
		return err
	})))
	eval := func(expr string) string {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Evaluate[string](expr))
		require.NoError(t, err)
		return v
	}
	waitFor := func(expr string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if v, err := chromedp.Run(ctx, chromedp.Evaluate[bool](expr)); err == nil && v {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s (page: %s)", expr, eval(`document.body ? document.body.innerText.slice(0, 400) : ""`))
	}
	click := func(selector string) chromedp.Action[chromedp.Void] {
		return chromedp.Click(chromedp.CSS(selector), chromedp.NodeVisible)
	}

	// Sign in with the password, and add a passkey.
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.CSS(`.nav-item[data-view="settings"]`)),
		click(`.nav-item[data-view="settings"]`),
		click(`.settings-tab[data-tab="users"]`),
		chromedp.WaitVisible(chromedp.ID("tf-card")),
		chromedp.SendKeys(chromedp.ID("tf-password"), testAdminPassword),
		chromedp.SendKeys(chromedp.ID("tf-passkey-name"), "Test laptop"),
		click("#tf-passkey-add"),
	))
	waitFor(`document.getElementById("tf-passkeys").textContent.includes("Test laptop")`)
	require.Contains(t, eval(`document.getElementById("tf-passkeys").textContent`), "localhost")
	require.Contains(t, eval(`document.getElementById("tf-notice").textContent`), "added")
	require.Contains(t, eval(`document.getElementById("users-list").textContent`), "On")

	// Signed out, the passkey alone signs back in.
	require.NoError(t, chromedp.Do(ctx, chromedp.Navigate(base+"/auth/logout"), chromedp.WaitVisible(chromedp.ID("passkey-btn")), click("#passkey-btn")))
	waitFor(`location.pathname === "/" && !!document.querySelector('.nav-item[data-view="settings"]')`)

	// The password alone no longer does: it asks for the passkey too.
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/auth/logout"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.ID("second-passkey-btn")),
	))
	require.Equal(t, "true", eval(`String(document.getElementById("code-group").hidden)`))
	require.Equal(t, "Use my passkey", eval(`document.getElementById("second-passkey-btn").textContent`))
	require.Equal(t, "/login", eval(`location.pathname`))
	require.NoError(t, chromedp.Do(ctx, click("#second-passkey-btn")))
	waitFor(`location.pathname === "/" && !!document.querySelector('.nav-item[data-view="settings"]')`)

	// An authenticator app, set up from the page; then the code signs in.
	require.NoError(t, chromedp.Do(ctx,
		click(`.nav-item[data-view="settings"]`),
		click(`.settings-tab[data-tab="users"]`),
		chromedp.WaitVisible(chromedp.ID("tf-totp-on")),
		chromedp.SendKeys(chromedp.ID("tf-password"), testAdminPassword),
		click("#tf-totp-on"),
		chromedp.WaitVisible(chromedp.ID("tf-qr")),
	))
	secret := eval(`document.getElementById("tf-secret").textContent`)
	require.Equal(t, "image/png", eval(`document.getElementById("tf-qr").src.slice(5, 14)`))
	step := time.Now().Unix() / 30
	require.NoError(t, chromedp.Do(ctx, chromedp.SendKeys(chromedp.ID("tf-code"), totpAt(t, secret, step)), click("#tf-confirm")))
	waitFor(`!document.getElementById("tf-codes").hidden`)
	require.Len(t, strings.Split(eval(`document.getElementById("tf-codes-list").textContent`), "\n"), 10)
	require.Contains(t, eval(`document.getElementById("tf-totp-state").textContent`), "10 recovery codes left")
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/auth/logout"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.ID("code")),
	))
	require.Equal(t, "Use a passkey instead", eval(`document.getElementById("second-passkey-btn").textContent`))
	require.NoError(t, chromedp.Do(ctx, chromedp.SendKeys(chromedp.ID("code"), "000000"), click("#code-btn")))
	waitFor(`document.getElementById("second-error").textContent.includes("isn't right")`)
	require.NoError(t, chromedp.Do(ctx,
		chromedp.SetValue(chromedp.ID("code"), totpAt(t, secret, step+1)),
		click("#code-btn"),
	))
	waitFor(`location.pathname === "/" && !!document.querySelector('.nav-item[data-view="settings"]')`)

	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, problems)
}

// IMAP turned off by the user, in the webmail, shows as off in the
// account's "What applies now", with where that comes from. The class
// still allows it, and the console used to say On.
func TestBrowserAccountShowsUserProtocolChoice(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	base, service := startProvisionAPIWith(t, func(s *Server) { s.webRoot = webRoot })
	service.Directory.(*adminDirectory).account = &provision.Account{Address: "ana@example.com", Name: "Ana", Status: "active", Aliases: []string{}}
	fake := &fakeMailboxAdmin{classes: map[string]mailpolicy.Class{}, policy: map[string]mailpolicy.AccountPolicy{}, lists: map[string]mailpolicy.List{}, routes: map[string]mailpolicy.DomainRoute{},
		userOff: map[string][]string{"ana@example.com": {"imap"}}}
	api := httptest.NewServer(fake)
	t.Cleanup(api.Close)
	client, err := mailpolicy.NewClient(api.URL, "token")
	require.NoError(t, err)
	service.Mailbox = client

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.WindowSize(1280, 1100), chromedp.NoSandbox)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 60*time.Second)
	defer cancel()
	click := func(selector string) chromedp.Action[chromedp.Void] {
		return chromedp.Click(chromedp.CSS(selector), chromedp.NodeVisible)
	}
	require.NoError(t, chromedp.Do(ctx,
		chromedp.Navigate(base+"/login"),
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SendKeys(chromedp.ID("username"), "root"),
		chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
		click("#login-btn"),
		chromedp.WaitVisible(chromedp.ID("nav-mailadmin")),
		click("#nav-mailadmin"),
		chromedp.WaitVisible(chromedp.CSS("[data-ma-tab=accounts]")),
		click("[data-ma-tab=accounts]"),
		chromedp.WaitVisible(chromedp.CSS("#ma-table-body .ma-account-link")),
		click("#ma-table-body .ma-account-link"),
	))
	row := func(label string) string {
		t.Helper()
		var out string
		deadline := time.Now().Add(10 * time.Second)
		for out == "" && time.Now().Before(deadline) {
			v, err := chromedp.Run(ctx, chromedp.Evaluate[string](`(() => { const r = [...document.querySelectorAll("#ma-effective tr")].find(r => r.cells[0] && r.cells[0].textContent === `+strconv.Quote(label)+`); return r ? r.cells[1].textContent + " | " + r.cells[2].textContent : ""; })()`))
			require.NoError(t, err)
			out = v
			if out == "" {
				time.Sleep(100 * time.Millisecond)
			}
		}
		return out
	}
	require.Equal(t, "Off | turned off by the user", row("IMAP"))
	require.True(t, strings.HasPrefix(row("POP3"), "On | "), row("POP3"))
}

// The DMARC page with seeded reports, for both roles and both widths and
// themes: numbers, chart, text that stays text, and setup.
func TestBrowserDMARC(t *testing.T) {
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	for _, c := range []struct {
		name          string
		width, height int64
		theme         string
		delegated     bool
	}{{"desktop", 1280, 1000, "dark", false}, {"phone", 390, 850, "light", false}, {"delegated", 390, 850, "dark", true}} {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			var registered, backfilled bool
			now := time.Now().UTC()
			var summary []mailpolicy.DMARCDay
			for i := 1; i < 28; i++ {
				day := now.AddDate(0, 0, -i).Format("2006-01-02")
				summary = append(summary, mailpolicy.DMARCDay{Domain: "example.com", PolicyDomain: "example.com", Day: day, Sender: "receiver.example",
					Org: "<b>not markup</b>", Verified: true, P: "none", Reports: 1, Messages: int64(400 + i*37%300), Aligned: int64(380 + i*37%300 - i*11%70)})
			}
			summary = append(summary,
				mailpolicy.DMARCDay{Domain: "example.com", Day: now.AddDate(0, 0, -2).Format("2006-01-02"), Sender: "claimed.example", Reports: 3, Messages: 900000},
				mailpolicy.DMARCDay{Domain: "other.example", Day: now.AddDate(0, 0, -2).Format("2006-01-02"), Sender: "receiver.example", Verified: true, P: "reject", Reports: 1, Messages: 5, Aligned: 5})
			src := func(ip, dkim, spf, signer string, n int64) mailpolicy.DMARCSource {
				return mailpolicy.DMARCSource{Domain: "example.com", SourceIP: ip, HeaderFrom: "example.com", Disposition: "none", DKIM: dkim, SPF: spf, DKIMDomain: signer, Verified: true, Messages: n}
			}
			sources := []mailpolicy.DMARCSource{src("192.0.2.1", "pass", "pass", "example.com", 9000), src("198.51.100.20", "pass", "fail", "example.com", 2100),
				src("2001:db8::25", "fail", "fail", "example.com", 340), src("203.0.113.9", "fail", "fail", "<i>evil</i>", 60)}
			mailbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				enc := json.NewEncoder(w)
				// As the mailbox does, only the domains asked for.
				want := func(d string) bool {
					q := r.URL.Query()["domain"]
					return len(q) == 0 || slices.Contains(q, d)
				}
				switch r.URL.Path {
				case "/v1/admin/dmarc/addresses":
					list := []mailpolicy.DMARCAddress{}
					if registered {
						a := mailpolicy.DMARCAddress{Domain: "example.com", Address: "rua@example.com"}
						if backfilled {
							a.BackfillStarted, a.BackfillFinished, a.BackfillRead, a.BackfillStored = &now, &now, 27, 27
						}
						list = append(list, a)
					}
					_ = enc.Encode(list)
				case "/v1/admin/dmarc/summary":
					out := []mailpolicy.DMARCDay{}
					for _, d := range summary {
						if want(d.Domain) {
							out = append(out, d)
						}
					}
					_ = enc.Encode(out)
				case "/v1/admin/dmarc/sources":
					out := []mailpolicy.DMARCSource{}
					for _, s := range sources {
						if want(s.Domain) {
							out = append(out, s)
						}
					}
					_ = enc.Encode(out)
				case "/v1/admin/dmarc/addresses/example.com":
					registered = true
					_, _ = w.Write([]byte("{}"))
				case "/v1/admin/dmarc/addresses/example.com/backfill":
					backfilled = true
					_, _ = w.Write([]byte("{}"))
				default:
					_, _ = w.Write([]byte("{}"))
				}
			}))
			defer mailbox.Close()

			dir := t.TempDir()
			hash, err := auth.HashPassword(testAdminPassword)
			require.NoError(t, err)
			users := filepath.Join(dir, "users")
			require.NoError(t, os.WriteFile(users, []byte("root:"+hash+":admin\ndeleg:"+hash+":domain-admin,domain:example.com\n"), 0o600))
			config := filepath.Join(dir, "elemta.toml")
			require.NoError(t, os.WriteFile(config, []byte("local_domains = [\"example.com\", \"other.example\"]\n"), 0o600))
			s, err := NewServer(&Config{Enabled: true, ListenAddr: "127.0.0.1:0", WebRoot: webRoot, AuthEnabled: true, AuthFile: users}, &MainConfig{Hostname: "mail.example.com"}, dir, 0, config)
			require.NoError(t, err)
			client, err := mailpolicy.NewClient(mailbox.URL, "token")
			require.NoError(t, err)
			s.SetProvisioner(&provision.Service{Directory: &mapDirectory{accounts: map[string]*provision.Account{}}, Routing: provision.FileDomains{Path: config}, Mailbox: client})
			s.dmarcLookup = func(_ context.Context, d string) (dnshealth.DMARCPolicy, error) {
				return dnshealth.DMARCPolicy{From: d, Policy: "none", Reports: []string{"rua@" + d}}, nil
			}
			s.hostLookup = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
			}
			require.NoError(t, s.Start())
			t.Cleanup(func() { _ = s.Stop() })
			base := "http://" + waitReady(t, s)

			opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chromePath(t)), chromedp.NoSandbox)
			allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
			defer cancelAlloc()
			browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
			defer cancelBrowser()
			ctx, cancel := context.WithTimeout(browserCtx, 60*time.Second)
			defer cancel()
			eval := func(expr string) bool {
				t.Helper()
				v, err := chromedp.Run(ctx, chromedp.Evaluate[bool](expr))
				require.NoError(t, err)
				return v
			}
			wait := func(expr string) {
				t.Helper()
				require.Eventually(t, func() bool { return eval(expr) }, 10*time.Second, 50*time.Millisecond, expr)
			}
			run := func(expr string) { t.Helper(); eval(`(` + expr + `, true)`) }
			user := "root"
			if c.delegated {
				user = "deleg"
			}
			require.NoError(t, chromedp.Do(ctx,
				chromedp.EmulateViewport(c.width, c.height),
				chromedp.Navigate(base+"/login"),
				chromedp.WaitVisible(chromedp.ID("password")),
				chromedp.SendKeys(chromedp.ID("username"), user),
				chromedp.SendKeys(chromedp.ID("password"), testAdminPassword),
				chromedp.Click(chromedp.CSS("#login-btn"), chromedp.NodeVisible),
				chromedp.WaitReady(chromedp.CSS("#nav-dmarc:not([hidden])")),
			))
			run(`document.documentElement.setAttribute("data-theme", "` + c.theme + `")`)
			run(`document.getElementById("nav-dmarc").click()`)
			wait(`document.querySelectorAll("#dmarc-chart path").length > 27`)

			text := func(id string) string { return `document.getElementById("` + id + `").textContent` }
			require.True(t, eval(text("dmarc-title")+` === "example.com"`))
			var verified int64
			for _, d := range summary {
				if d.Domain == "example.com" && d.Verified {
					verified += d.Messages
				}
			}
			require.True(t, eval(`document.querySelector("#dmarc-reporters tr td:last-child").textContent === (`+strconv.FormatInt(verified, 10)+`).toLocaleString() && `+text("dmarc-volume")+` === Intl.NumberFormat(undefined, {notation: "compact", maximumFractionDigits: 1}).format(`+strconv.FormatInt(verified, 10)+`)`), "unverified reports in the total")
			require.True(t, eval(text("dmarc-sources")+`.includes("this server") && `+text("dmarc-sources")+`.includes("likely forwarder")`), "source labels")
			require.True(t, eval(text("dmarc-advice")+`.includes("2001:db8::25") && !`+text("dmarc-advice")+`.includes("203.0.113.9")`), "advice")
			require.True(t, eval(text("dmarc-reporters")+`.includes("<b>not markup</b>") && !document.querySelector("#view-dmarc tbody b, #view-dmarc tbody i")`), "report text became markup")
			require.True(t, eval(text("dmarc-unverified-summary")+`.includes("(3)")`), "unverified are shown apart")
			require.True(t, eval(`window.innerWidth === `+strconv.FormatInt(c.width, 10)+` && document.getElementById("view-dmarc").scrollWidth <= document.getElementById("view-dmarc").clientWidth`), "overflows sideways")

			run(`document.querySelector("#dmarc-chart svg").focus()`)
			wait(`!!document.querySelector("#dmarc-chart .dmarc-tip:not([hidden])")`)
			if dir := os.Getenv("ELEMTA_DMARC_SCREENSHOTS"); dir != "" {
				for i, id := range []string{"view-dmarc", "dmarc-chart", "dmarc-sources", "dmarc-setup-status"} {
					run(`document.getElementById("` + id + `").scrollIntoView({block: "` + []string{"start", "center", "center", "center"}[i] + `"})`)
					png, err := chromedp.Run(ctx, chromedp.CaptureScreenshot())
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(filepath.Join(dir, "dmarc-"+c.name+"-"+strconv.Itoa(i)+".png"), png, 0o600))
				}
			}

			run(`document.querySelector("[data-dmarc-days='7']").click()`)
			wait(`document.querySelectorAll("#dmarc-daily tr").length === 7`)
			require.True(t, eval(`!`+text("dmarc-advice")+`.includes("Ready to tighten")`))

			if c.delegated {
				require.True(t, eval(`!`+text("dmarc-domains")+`.includes("other.example")`), "another domain's row")
				require.True(t, eval(`document.getElementById("dmarc-setup-form").hidden && document.getElementById("dmarc-backfill").hidden`), "setup shown to a domain administrator")
				return
			}
			require.True(t, eval(`document.getElementById("dmarc-address").value === "rua@example.com"`), "pre-filled from rua")
			run(`document.getElementById("dmarc-setup-form").requestSubmit()`)
			wait(`!document.getElementById("dmarc-backfill").hidden && !document.getElementById("dmarc-backfill").disabled`)
			run(`window.confirm = () => false`)
			run(`document.getElementById("dmarc-backfill").click()`)
			mu.Lock()
			require.False(t, backfilled, "read a mailbox without a yes")
			mu.Unlock()
			run(`window.confirm = () => true`)
			run(`document.getElementById("dmarc-backfill").click()`)
			wait(text("dmarc-backfill-state") + `.includes("27")`)
		})
	}
}
