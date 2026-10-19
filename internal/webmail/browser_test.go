//go:build browser

package webmail

// Browser tests drive the pages in headless Chromium against the same
// in-memory harness the other tests use, so they need no mail stack, only a
// Chromium binary (CHROME_PATH, or chromium/google-chrome on PATH). They cover
// what the HTTP tests can't see: that app.js runs without errors under the
// CSP, and that the script-driven features (theme toggle, context menu,
// keyboard shortcuts, rich compose) actually work.
//
//	go test -tags browser -run Browser ./internal/webmail/

import (
	"context"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type browser struct {
	t   *testing.T
	h   *harness
	ctx context.Context

	mu       sync.Mutex
	problems []string
}

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

// collect records every event the iterator yields as a problem, until the
// browser context ends.
func collect[E any](b *browser, events iter.Seq2[E, error], describe func(E) string) {
	go func() {
		for ev, err := range events {
			if err != nil {
				return
			}
			if s := describe(ev); s != "" {
				b.problem(s)
			}
		}
	}()
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	h := newHarness(t)
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath(t)),
		chromedp.WindowSize(1400, 900),
		chromedp.NoSandbox,
	)
	actx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancelCtx := chromedp.NewContext(actx)
	t.Cleanup(func() { cancelCtx(); cancelAlloc() })

	b := &browser{t: t, h: h, ctx: ctx}
	// Script errors and CSP violations (reported as error log entries) fail
	// the test at the end, whichever page they happened on. Subscribing
	// starts the browser.
	collect(b, chromedp.Events(ctx, runtime.ExceptionThrown), func(ev runtime.EventExceptionThrown) string {
		return "exception: " + (&chromedp.ExceptionError{ExceptionDetails: ev.ExceptionDetails}).Error()
	})
	collect(b, chromedp.Events(ctx, runtime.ConsoleAPICalled), func(ev runtime.EventConsoleAPICalled) string {
		if ev.Type != runtime.ConsoleAPICalledTypeError {
			return ""
		}
		var parts []string
		for _, a := range ev.Args {
			parts = append(parts, string(a.Value))
		}
		return "console.error: " + strings.Join(parts, " ")
	})
	collect(b, chromedp.Events(ctx, log.EntryAdded), func(ev log.EventEntryAdded) string {
		if ev.Entry.Level != log.EntryLevelError {
			return ""
		}
		return "log: " + ev.Entry.Text + " " + ev.Entry.URL
	})
	b.run(chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		if _, err := cdp.Call(ctx, tg, log.Enable, cdp.Empty{}); err != nil {
			return err
		}
		_, err := cdp.Call(ctx, tg, runtime.Enable, cdp.Empty{})
		return err
	}))
	t.Cleanup(func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, p := range b.problems {
			t.Error(p)
		}
	})
	return b
}

func (b *browser) problem(s string) {
	b.mu.Lock()
	b.problems = append(b.problems, s)
	b.mu.Unlock()
}

func (b *browser) run(steps ...chromedp.Action[chromedp.Void]) {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	if err := chromedp.Do(ctx, steps...); err != nil {
		b.t.Fatal(err)
	}
}

func (b *browser) url(path string) string { return b.h.srv.URL + path }

// login signs in through the real form, as a user would.
func (b *browser) login() {
	b.t.Helper()
	b.run(
		chromedp.Navigate(b.url("/login")),
		chromedp.SendKeys(chromedp.ID("user"), "user@example.com"),
		chromedp.SendKeys(chromedp.ID("password"), "secret"),
		chromedp.Submit(chromedp.ID("password")),
		chromedp.WaitVisible(chromedp.CSS(`[data-ctx="message"]`)),
	)
}

func evalAs[T any](b *browser, expr string) T {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](expr))
	if err != nil {
		b.t.Fatal(err)
	}
	return v
}

func TestBrowserPagesLoadCleanly(t *testing.T) {
	b := newBrowser(t)
	b.login()
	for _, path := range []string{"/mail", "/mail?f=INBOX&uid=7", "/compose", "/calendar", "/contacts", "/tasks", "/settings", "/folders"} {
		b.run(chromedp.Navigate(b.url(path)), chromedp.WaitReady(chromedp.CSS("body")))
		if !evalAs[bool](b, `document.readyState === "complete" && !!document.querySelector("main")`) {
			t.Errorf("%s did not render a main region", path)
		}
	}
}

func TestBrowserSignInPage(t *testing.T) {
	b := newBrowser(t)
	b.run(chromedp.Navigate(b.url("/login")), chromedp.WaitVisible(chromedp.CSS(".login-logo img")))
	// The artwork must actually decode, not just be present.
	if !evalAs[bool](b, `(() => { const i = document.querySelector(".login-logo img"); return i.complete && i.naturalWidth > 0 })()`) {
		t.Fatal("sign-in artwork did not load")
	}
}

func TestBrowserThemeToggle(t *testing.T) {
	b := newBrowser(t)
	b.login()
	before := evalAs[string](b, `document.documentElement.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")`)
	b.run(chromedp.Click(chromedp.CSS(`[data-theme-toggle]`), chromedp.NodeVisible), chromedp.Sleep(300*time.Millisecond))
	after := evalAs[string](b, `document.documentElement.getAttribute("data-theme") || ""`)
	if after == "" || after == before {
		t.Fatalf("toggle went from %q to %q", before, after)
	}
	// The choice was saved in the background and survives a reload.
	b.run(chromedp.Reload(), chromedp.WaitVisible(chromedp.CSS(`[data-ctx="message"]`)))
	if got := evalAs[string](b, `document.documentElement.getAttribute("data-theme") || ""`); got != after {
		t.Fatalf("after reload theme = %q, want %q", got, after)
	}
}

func TestBrowserContextMenu(t *testing.T) {
	b := newBrowser(t)
	b.login()
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	nodes, err := chromedp.Run(ctx, chromedp.Nodes(chromedp.CSS(`[data-ctx="message"]`), chromedp.NodeVisible))
	if err != nil {
		t.Fatal(err)
	}
	b.run(chromedp.MouseClickNode(nodes[0], chromedp.ButtonRight), chromedp.WaitVisible(chromedp.CSS(".ctx-menu")))
	labels := evalAs[[]string](b, `[...document.querySelectorAll(".ctx-menu .ctx-item")].map(e => e.textContent)`)
	joined := strings.Join(labels, "|")
	for _, want := range []string{"Reply", "Forward", "Delete"} {
		if !strings.Contains(joined, want) {
			t.Errorf("context menu %q lacks %q", joined, want)
		}
	}
	// Escape closes it.
	b.run(chromedp.KeyEvent("\x1b"), chromedp.Sleep(100*time.Millisecond))
	if evalAs[bool](b, `!!document.querySelector(".ctx-menu")`) {
		t.Error("Escape left the context menu open")
	}
}

func TestBrowserKeyboardOpensMessage(t *testing.T) {
	b := newBrowser(t)
	b.login()
	// j selects the first message, Enter opens it.
	b.run(chromedp.KeyEvent("j"), chromedp.KeyEvent("\r"), chromedp.Sleep(500*time.Millisecond))
	if path := evalAs[string](b, `location.pathname + location.search`); !strings.Contains(path, "uid=7") {
		t.Fatalf("j then Enter went to %q", path)
	}
}

func TestBrowserRichCompose(t *testing.T) {
	b := newBrowser(t)
	b.h.sub.sent = make(chan struct{}, 1)
	b.login()
	b.run(
		chromedp.Navigate(b.url("/compose")),
		chromedp.WaitVisible(chromedp.ID("to")),
		chromedp.SendKeys(chromedp.ID("to"), "dana@example.com"),
		chromedp.SendKeys(chromedp.ID("subject"), "Browser test"),
	)
	// Write into whichever editor is showing: the rich editor when script
	// is on, otherwise the plain textarea.
	rich := evalAs[bool](b, `(() => { const w = document.querySelector("[data-editor-wrap]"); return !!w && !w.hidden })()`)
	if rich {
		b.run(chromedp.Click(chromedp.CSS("[data-editor]"), chromedp.NodeVisible), chromedp.SendKeys(chromedp.CSS("[data-editor]"), "Hello from the browser"))
		evalAs[bool](b, `document.execCommand("selectAll"); document.execCommand("bold"); true`)
	} else {
		b.run(chromedp.SendKeys(chromedp.ID("body"), "Hello from the browser"))
	}
	b.run(chromedp.Click(chromedp.CSS(`button[name="op"][value="send"]`), chromedp.NodeVisible))
	select {
	case <-b.h.sub.sent:
	case <-time.After(10 * time.Second):
		t.Fatal("message was not submitted")
	}
	raw := string(b.h.sub.raw)
	if !strings.Contains(raw, "Hello from the browser") {
		t.Fatalf("sent message lacks the body:\n%s", raw)
	}
	// The editor may write bold as a tag or as an inline style; both survive
	// sanitising and render in mail clients.
	lower := strings.ToLower(strings.ReplaceAll(raw, "=\r\n", ""))
	lower = strings.ReplaceAll(lower, "=\n", "")
	if rich && !strings.Contains(lower, "<b>") && !strings.Contains(lower, "<strong>") && !strings.Contains(lower, "font-weight: bold") {
		t.Errorf("rich formatting was lost:\n%s", raw)
	}
	if fmt.Sprint(b.h.sub.rcpts) != "[dana@example.com]" {
		t.Errorf("recipients = %v", b.h.sub.rcpts)
	}
}

// The error collection is what makes the other tests catch broken script,
// so check that it sees an error at all.
func TestBrowserCollectsErrors(t *testing.T) {
	b := newBrowser(t)
	b.run(chromedp.Navigate(b.url("/login")))
	evalAs[bool](b, `console.error("probe"); true`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		n := len(b.problems)
		if n > 0 {
			b.problems = nil
		}
		b.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("console.error was not collected")
}

// TestBrowserCalendarFitsWindow pins that the month, week and day views fit
// the window without a page scrollbar, at a large and a small desktop size,
// and that the sidebar import shows as a link rather than a file control.
// Set CALENDAR_SHOTS to a directory to keep screenshots for a look.
func TestBrowserCalendarFitsWindow(t *testing.T) {
	b := newBrowser(t)
	b.login()
	shots := os.Getenv("CALENDAR_SHOTS")
	for _, size := range [][2]int64{{1900, 1000}, {1280, 720}} {
		b.run(chromedp.EmulateViewport(size[0], size[1]))
		for _, view := range []string{"month", "week", "day"} {
			b.run(chromedp.Navigate(b.url("/calendar?view="+view)), chromedp.WaitVisible(chromedp.CSS(".cal-body")))
			if got := evalAs[string](b, `document.querySelector(".segmented [aria-current=page]")?.textContent || ""`); !strings.EqualFold(got, view) {
				t.Fatalf("%s: current view link = %q", view, got)
			}
			if over := evalAs[float64](b, `document.documentElement.scrollHeight - innerHeight`); over > 0 {
				t.Errorf("%dx%d %s view: page scrolls by %vpx", size[0], size[1], view, over)
			}
			if shots != "" {
				ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
				png, err := chromedp.Run(ctx, chromedp.CaptureScreenshot())
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fmt.Sprintf("%s/calendar-%s-%d.png", shots, view, size[0]), png, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if !evalAs[bool](b, `(() => { const r = document.querySelector(".import input[type=file]").getBoundingClientRect(); return r.width <= 1 && r.height <= 1 })()`) {
		t.Error("the import file control is visible")
	}
	if !evalAs[bool](b, `(() => { const l = document.querySelector(".import label"); return l.offsetWidth > 0 && getComputedStyle(document.querySelector(".import button")).display === "none" })()`) {
		t.Error("the import link is not shown in place of the control")
	}
}
