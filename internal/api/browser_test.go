//go:build browser

package api

// Drives the admin console in headless Chromium, for what the HTTP tests can't
// see: that the script runs under the page's CSP and the dialog really renders.
// Needs Chromium (CHROME_PATH, or chromium/google-chrome on PATH).
//
//	go test -tags browser -run Browser ./internal/api/

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/runtime"
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
