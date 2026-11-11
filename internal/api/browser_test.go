//go:build browser

package api

// Drives the admin console in headless Chromium, for what the HTTP tests can't
// see: that the script runs under the page's CSP and the dialog really renders.
// Needs Chromium (CHROME_PATH, or chromium/google-chrome on PATH).
//
//	go test -tags browser -run Browser ./internal/api/

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
