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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
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
	// A row shows before the deferred scripts run, and until they do a right
	// click or a shortcut goes nowhere. The first page of a session then saves
	// the time zone and reloads once, which would swallow whatever came next.
	b.waitFor(`document.readyState === "complete" && !document.body.hasAttribute("data-detect-tz")`)
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
	b.run(chromedp.Click(chromedp.CSS(`[data-theme-toggle]`), chromedp.NodeVisible))
	b.waitFor(`performance.getEntriesByType("resource").some(e => e.name.endsWith("/settings/theme") && e.responseEnd > 0)`)
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
	b.run(chromedp.KeyEvent("\x1b"))
	b.waitFor(`!document.querySelector(".ctx-menu")`)
}

// A conversation row's data-uid lists every message in it, which bulk actions
// want. Actions on one message must use one UID: the list isn't a UID, and the
// server answers it as a message that no longer exists.
func TestBrowserConversationMenuActsOnLatestMessage(t *testing.T) {
	b := newBrowser(t)
	now := time.Now()
	b.h.store.messages["INBOX"] = []Summary{
		{UID: 21, Subject: "Quarterly plan", From: []Address{{Email: "dana@example.com"}}, Date: now.Add(-time.Hour)},
		{UID: 22, Subject: "Re: Quarterly plan", From: []Address{{Email: "lee@example.com"}}, Date: now},
	}
	b.h.store.raw[21] = []byte("From: dana@example.com\r\nSubject: Quarterly plan\r\n\r\nfirst\r\n")
	b.h.store.raw[22] = []byte("From: lee@example.com\r\nSubject: Re: Quarterly plan\r\n\r\nsecond\r\n")
	b.login()
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	// Popups and navigation are recorded rather than followed.
	evalAs[bool](b, `window.__opened = []; window.open = u => { window.__opened.push(u); }; true`)
	for _, label := range []string{"View original", "Print"} {
		nodes, err := chromedp.Run(ctx, chromedp.Nodes(chromedp.CSS(`[data-ctx="message"]`), chromedp.NodeVisible))
		if err != nil {
			t.Fatal(err)
		}
		if got := evalAs[string](b, `document.querySelector('[data-ctx="message"]').getAttribute("data-uid")`); got != "21,22" {
			t.Fatalf("row data-uid = %q, want the conversation's UIDs", got)
		}
		b.run(chromedp.MouseClickNode(nodes[0], chromedp.ButtonRight), chromedp.WaitVisible(chromedp.CSS(".ctx-menu")))
		evalAs[bool](b, `[...document.querySelectorAll(".ctx-menu .ctx-item")].find(e => e.textContent.trim() === `+strconv.Quote(label)+`).click(); true`)
	}
	opened := evalAs[[]string](b, `window.__opened`)
	if len(opened) != 2 {
		t.Fatalf("opened = %q", opened)
	}
	for _, u := range opened {
		if !strings.Contains(u, "uid=22") {
			t.Errorf("menu opened %q, want the conversation's latest message", u)
		}
	}
	b.h.login()
	resp, _ := b.h.get(opened[0])
	if resp.StatusCode != http.StatusOK {
		t.Errorf("%s = %d", opened[0], resp.StatusCode)
	}
}

func TestBrowserKeyboardOpensMessage(t *testing.T) {
	b := newBrowser(t)
	b.login()
	// j selects the first message, Enter opens it.
	b.run(chromedp.KeyEvent("j"), chromedp.KeyEvent("\r"))
	b.waitFor(`location.search.includes("uid=7")`)
}

// A full list, so that opening a message from further down needs scrolling.
func seedLongInbox(b *browser, extra map[uint32]string) {
	now := time.Now()
	var msgs []Summary
	for i := 1; i <= 60; i++ {
		uid := uint32(100 + i)
		msgs = append(msgs, Summary{UID: uid, Subject: fmt.Sprintf("Message %d", i), From: []Address{{Email: "dana@example.com"}}, Date: now.Add(-time.Duration(i) * time.Hour)})
		text := fmt.Sprintf("<p>body %d</p>", i)
		ctype := "text/html"
		if body, ok := extra[uid]; ok {
			text, ctype = body, "text/plain"
		}
		b.h.store.raw[uid] = []byte(fmt.Sprintf("From: dana@example.com\r\nSubject: Message %d\r\nContent-Type: %s\r\n\r\n%s\r\n", i, ctype, text))
	}
	b.h.store.messages["INBOX"] = msgs
}

func (b *browser) clickRow(n int) {
	b.t.Helper()
	evalAs[bool](b, fmt.Sprintf(`document.querySelectorAll("a.row")[%d].click(); true`, n))
}

// waitFor polls until expr is true. A busy CI runner takes many times longer
// than a laptop, so a fixed sleep long enough for one is a flaky test on the
// other. Errors count as not yet, because the page may be navigating.
func (b *browser) waitFor(expr string) {
	b.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		ok, err := chromedp.Run(ctx, chromedp.Evaluate[bool](expr))
		cancel()
		if err == nil && ok {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	b.t.Fatalf("timed out waiting for %s", expr)
}

// The reader's subject, once the pane shows the given message.
func readerShows(subject string) string {
	return fmt.Sprintf(`(document.querySelector("[data-message-subject]") || {textContent: ""}).textContent.includes(%q)`, subject)
}

// Clicking through mail must leave the page alone: a full load repaints
// everything, and it put a message opened from far down the list off screen.
func TestBrowserReadingPaneKeepsThePage(t *testing.T) {
	b := newBrowser(t)
	seedLongInbox(b, nil)
	b.login()
	evalAs[bool](b, `window.__samePage = true; document.querySelector(".list").scrollTop = 1500; true`)
	if got := evalAs[int](b, `document.querySelector(".list").scrollTop`); got == 0 {
		t.Fatal("the list does not scroll by itself")
	}
	b.clickRow(35)
	b.waitFor(`location.search.includes("uid=136") && document.querySelector("iframe.body-frame").classList.contains("autosized")`)
	if !evalAs[bool](b, `window.__samePage === true`) {
		t.Error("opening a message loaded a whole page")
	}
	if !evalAs[bool](b, readerShows("Message 36")) {
		t.Error("the reader does not show the message")
	}
	if !evalAs[bool](b, `document.title.includes("Message 36")`) {
		t.Errorf("title = %q", evalAs[string](b, `document.title`))
	}
	if got := evalAs[int](b, `document.querySelector(".list").scrollTop`); got < 1000 {
		t.Errorf("list scrolled to %d, want it where it was", got)
	}
	if !evalAs[bool](b, `(() => { const r = document.querySelector("li.selected").getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight + 1 })()`) {
		t.Error("the open message's row is off screen")
	}
	if !evalAs[bool](b, `document.querySelectorAll("li.selected").length === 1 && !document.querySelector("li.selected").classList.contains("unread") && document.querySelector("li.selected a.row").getAttribute("aria-current") === "true"`) {
		t.Error("the list does not mark the open message as selected and read")
	}
	// The new frame was sized for its message, and the page itself can't scroll.
	if got := evalAs[int](b, `document.querySelector("iframe.body-frame").offsetHeight`); got > 200 {
		t.Errorf("frame height = %d, want it fitted to a one-line message", got)
	}
	if got := evalAs[string](b, `document.querySelector("iframe.body-frame").contentDocument.body.textContent`); !strings.Contains(got, "body 36") {
		t.Errorf("frame shows %q", got)
	}
	if got := evalAs[int](b, `scrollY`); got != 0 {
		t.Errorf("page scrolled to %d", got)
	}

	// The toolbar's arrows go through the pane as well, and the row follows.
	b.run(chromedp.KeyEvent("j"))
	b.waitFor(readerShows("Message 37"))

	// Back and forward walk the messages without leaving the page.
	b.run(chromedp.Evaluate[chromedp.Void](`history.back()`, chromedp.EvalAsValue))
	b.waitFor(readerShows("Message 36"))
	b.run(chromedp.Evaluate[chromedp.Void](`history.back()`, chromedp.EvalAsValue))
	b.waitFor(`!!document.querySelector(".reader-empty") && !document.querySelector("li.selected")`)
	if !evalAs[bool](b, `window.__samePage === true`) {
		t.Error("back to the list loaded a whole page")
	}
}

// A conversation's row opens its oldest unread message. After each one is
// read in the pane the row has to point at the next, or the last unread
// message can't be reached and the conversation never stops being unread.
func TestBrowserConversationRowReachesEachUnread(t *testing.T) {
	b := newBrowser(t)
	now := time.Now()
	b.h.store.messages["INBOX"] = []Summary{
		{UID: 31, Subject: "Budget", From: []Address{{Email: "dana@example.com"}}, Date: now.Add(-2 * time.Hour)},
		{UID: 32, Subject: "Re: Budget", From: []Address{{Email: "lee@example.com"}}, Date: now.Add(-time.Hour)},
		{UID: 33, Subject: "Re: Budget", From: []Address{{Email: "dana@example.com"}}, Date: now},
	}
	for _, u := range []uint32{31, 32, 33} {
		b.h.store.raw[u] = []byte(fmt.Sprintf("From: dana@example.com\r\nSubject: Budget\r\n\r\nmessage %d\r\n", u))
	}
	b.login()
	evalAs[bool](b, `window.__samePage = true; true`)
	for _, uid := range []string{"31", "32", "33"} {
		b.clickRow(0)
		b.waitFor(`location.search.includes("uid=` + uid + `") && document.querySelector(".reader").textContent.includes("message ` + uid + `")`)
	}
	b.waitFor(`!document.querySelector("li.row-wrap").classList.contains("unread")`)
	b.h.store.mu.Lock()
	read := b.h.store.seen[31] && b.h.store.seen[32] && b.h.store.seen[33]
	b.h.store.mu.Unlock()
	if !read {
		t.Errorf("seen = %v, want every message in the conversation read", b.h.store.seen)
	}
	if !evalAs[bool](b, `window.__samePage === true`) {
		t.Error("reading the conversation loaded a whole page")
	}
}

// Expanding a message in a conversation reads it, as opening it does.
func TestBrowserExpandingACardMarksItRead(t *testing.T) {
	b := newBrowser(t)
	b.h.store.related = []Related{
		{Folder: "INBOX", Summary: Summary{UID: 5, Subject: "MSA draft", From: []Address{{Email: "priya@northwind.example"}}, Date: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}},
	}
	b.h.store.raw[5] = []byte("From: priya@northwind.example\r\nSubject: MSA draft\r\n\r\nearlier\r\n")
	b.login()
	b.run(chromedp.Navigate(b.url("/mail?f=INBOX&uid=7")), chromedp.WaitVisible(chromedp.CSS("details.thread-card summary")))
	b.waitFor(`document.readyState === "complete"`)
	if !evalAs[bool](b, `!!document.querySelector("details.thread-card .unread-dot")`) {
		t.Fatal("the card does not show as unread")
	}
	b.run(chromedp.Click(chromedp.CSS("details.thread-card summary"), chromedp.NodeVisible))
	b.waitFor(`!document.querySelector("details.thread-card .unread-dot")`)
	b.h.store.mu.Lock()
	read := b.h.store.seen[5]
	b.h.store.mu.Unlock()
	if !read {
		t.Error("expanding the card did not mark its message read")
	}
	// Closing and opening it again sends nothing more.
	if evalAs[bool](b, `document.querySelector("details.thread-card").hasAttribute("data-unread-uid")`) {
		t.Error("the card still asks to be marked read")
	}
}

// Whatever the pane can't show, the link still can.
func TestBrowserReadingPaneFallsBackToTheLink(t *testing.T) {
	b := newBrowser(t)
	seedLongInbox(b, nil)
	b.login()
	b.h.store.messages["INBOX"][3].UID = 999
	b.run(chromedp.Reload(), chromedp.WaitVisible(chromedp.CSS(`[data-ctx="message"]`)))
	evalAs[bool](b, `window.__samePage = true; true`)
	b.clickRow(3)
	b.waitFor(`window.__samePage !== true && document.readyState === "complete"`)
	// The error page's failed request is the fallback working.
	b.mu.Lock()
	b.problems = nil
	b.mu.Unlock()
}

// Encrypted mail is set up by pgp.js, which has to run for each message the
// pane shows and not only for the one the page loaded with.
func TestBrowserReadingPaneSetsUpEncryptedMail(t *testing.T) {
	b := newBrowser(t)
	seedLongInbox(b, map[uint32]string{102: "-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMA0Uw\r\n=abcd\r\n-----END PGP MESSAGE-----"})
	b.login()
	b.clickRow(0)
	b.waitFor(readerShows("Message 1"))
	b.clickRow(1)
	// The form appears when the worker answers, and the worker has a large
	// library to load first.
	b.waitFor(`(() => { const f = document.querySelector("[data-pgp-unlock]"); return !!f && !f.hidden })()`)
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
	// A script click, for the reason given in TestBrowserHolidayCountryPicker:
	// Send submits and navigates, which can cut off an inspecting click.
	b.run(chromedp.Evaluate[chromedp.Void](`document.querySelector('button[name="op"][value="send"]').click()`, chromedp.EvalAsValue))
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

// TestBrowserCalendarFitsWindow pins that the month, week, day and agenda views fit
// the window without a page scrollbar, at a large and a small desktop size,
// and that the sidebar import shows as a link rather than a file control.
// Set CALENDAR_SHOTS to a directory to keep screenshots for a look.
func TestBrowserCalendarFitsWindow(t *testing.T) {
	b := newBrowser(t)
	b.login()
	shots := os.Getenv("CALENDAR_SHOTS")
	for _, size := range [][2]int64{{1900, 1000}, {1280, 720}} {
		b.run(chromedp.EmulateViewport(size[0], size[1]))
		for _, view := range []string{"month", "week", "day", "agenda"} {
			b.run(chromedp.Navigate(b.url("/calendar?view="+view)), chromedp.WaitVisible(chromedp.CSS(".cal-body")))
			if got := evalAs[string](b, `document.querySelector(".segmented [aria-current=page]")?.textContent || ""`); !strings.EqualFold(got, view) {
				t.Fatalf("%s: current view link = %q", view, got)
			}
			if view == "agenda" {
				// A long agenda must scroll inside its list, not the page.
				// The harness has few events, so repeat them.
				if !evalAs[bool](b, `(() => { const a = document.querySelector(".agenda"); const html = a.innerHTML; for (let i = 0; i < 40; i++) a.insertAdjacentHTML("beforeend", html); return a.scrollHeight > a.clientHeight })()`) {
					t.Errorf("%dx%d agenda: a long list does not scroll inside itself", size[0], size[1])
				}
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

// TestBrowserHolidayCountryPicker pins the scripted picker: choosing a
// country adds a chip without leaving the page, × removes it, and Save
// keeps what the chips show. Set CALENDAR_SHOTS to keep a screenshot.
func TestBrowserHolidayCountryPicker(t *testing.T) {
	b := newBrowser(t)
	b.login()
	b.run(chromedp.EmulateViewport(1400, 1000), chromedp.Navigate(b.url("/settings#holidays")), chromedp.WaitVisible(chromedp.CSS("[data-country-picker]")))
	choose := func(code string) {
		b.run(chromedp.Evaluate[chromedp.Void](`(() => { const s = document.querySelector("#holiday_extra_add"); s.value = "`+code+`"; s.dispatchEvent(new Event("change", {bubbles: true})) })()`, chromedp.EvalAsValue))
	}
	chips := func() string {
		return evalAs[string](b, `[...document.querySelectorAll(".country-chip input")].map(i => i.value).join(",")`)
	}
	choose("gb")
	choose("fr")
	choose("de")
	if got := chips(); got != "gb,fr,de" {
		t.Fatalf("chips after adding = %q", got)
	}
	if !evalAs[bool](b, `document.querySelector('#holiday_extra_add option[value="fr"]').disabled && document.querySelector("#holiday_extra_add").value === ""`) {
		t.Error("a chosen country is still offered, or the list didn't reset")
	}
	b.run(chromedp.Click(chromedp.CSS(`.country-chip button[value="fr"]`), chromedp.NodeVisible))
	if got := chips(); got != "gb,de" {
		t.Fatalf("chips after removing = %q", got)
	}
	if p := evalAs[string](b, `location.pathname`); p != "/settings" {
		t.Fatalf("removing a chip left the page for %s", p)
	}
	if shots := os.Getenv("CALENDAR_SHOTS"); shots != "" {
		ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
		png, err := chromedp.Run(ctx, chromedp.Screenshot(chromedp.CSS("#holidays")))
		cancel()
		if err == nil {
			_ = os.WriteFile(shots+"/holiday-countries.png", png, 0o600)
		}
	}
	// The form redirects after saving. Clicking through the DevTools input
	// protocol raced that navigation: on a slow runner the page went away
	// while the click was still inspecting the button ("Inspected target
	// navigated or closed"). A script click returns before the submit
	// navigates, and a marker on the old page tells it apart from the
	// reloaded one, so the check below reads what was saved, not what was
	// still on screen.
	b.run(chromedp.Evaluate[chromedp.Void](`window.__beforeSave = true; document.querySelector(".save-bar button").click()`, chromedp.EvalAsValue))
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		reloaded, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`!window.__beforeSave && document.readyState === "complete" && !!document.querySelector("[data-country-picker]")`))
		cancel()
		if err == nil && reloaded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the settings page didn't reload after saving (last error: %v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	got := evalAs[string](b, `[...document.querySelectorAll(".country-chip input")].map(i => i.value).sort().join(",")`)
	if got != "de,gb" {
		t.Fatalf("saved countries = %q, want de,gb", got)
	}
}

// stubAudio counts notes started, since a test browser has nothing to hear.
const stubAudio = `(function () {
  window.notes = 0;
  window.AudioContext = function () { this.state = "running"; this.currentTime = 0; this.destination = {}; };
  var param = function () { return { value: 0, setValueAtTime: function () {}, exponentialRampToValueAtTime: function () {} }; };
  AudioContext.prototype.resume = function () {};
  AudioContext.prototype.createGain = function () { return { gain: param(), connect: function () {} }; };
  AudioContext.prototype.createOscillator = function () {
    return { frequency: param(), connect: function () {}, start: function () { window.notes++; }, stop: function () {} };
  };
})()`

func TestBrowserSettingsPreviewPlaysEachTone(t *testing.T) {
	b := newBrowser(t)
	b.login()
	b.run(chromedp.Navigate(b.url("/settings")), chromedp.Evaluate[chromedp.Void](stubAudio, chromedp.EvalAsValue))
	for _, tone := range mailSounds {
		b.run(chromedp.Evaluate[chromedp.Void](`window.notes = 0; document.getElementById("mail_sound").value = "`+tone.Value+`"; document.querySelector("[data-sound-preview]").click()`, chromedp.EvalAsValue))
		if n := evalAs[int](b, `window.notes`); n == 0 {
			t.Errorf("%s has no recipe in app.js", tone.Value)
		}
	}
}

// Counted through the real page: a rise in the inbox rings once, and nothing
// else does.
func TestBrowserNewMailRings(t *testing.T) {
	b := newBrowser(t)
	if err := b.h.store.PutObject(context.Background(), CollSettings, Object{ID: settingsID, ContentType: "application/json", Data: []byte(`{"mail_sound":"chime"}`)}); err != nil {
		t.Fatal(err)
	}
	b.login()
	counts := func(total, unread int) string {
		return fmt.Sprintf(`window.fetch = function () { return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ unread: { INBOX: %d, Junk: 9 }, total: { INBOX: %d, Junk: 9 } }); } }); };
			document.dispatchEvent(new Event("visibilitychange"));`, unread, total)
	}
	step := func(js string) int {
		b.run(chromedp.Evaluate[chromedp.Void](js, chromedp.EvalAsValue), chromedp.Sleep(150*time.Millisecond))
		return evalAs[int](b, `window.notes`)
	}
	b.run(chromedp.Navigate(b.url("/mail")), chromedp.Evaluate[chromedp.Void](stubAudio+`; try { localStorage.clear(); } catch (e) {}`, chromedp.EvalAsValue))
	// Where things stand, however the page's own first check went.
	step(counts(5, 2))
	b.run(chromedp.Evaluate[chromedp.Void](`window.notes = 0; localStorage.clear()`, chromedp.EvalAsValue))
	if n := step(counts(5, 2)); n != 0 {
		t.Fatalf("rang with nothing new: %d", n)
	}
	if n := step(counts(5, 3)); n != 0 {
		t.Fatalf("rang when something was marked unread: %d", n)
	}
	if n := step(counts(6, 4)); n == 0 {
		t.Fatal("new mail didn't ring")
	}
	first := evalAs[int](b, `window.notes`)
	b.run(chromedp.Evaluate[chromedp.Void](`localStorage.setItem("elemta-mail-sound", String(Date.now()))`, chromedp.EvalAsValue))
	if n := step(counts(7, 5)); n != first {
		t.Fatal("a second tab rang as well")
	}
}

// One click on an event shows its details in a bubble and stays on the
// calendar; a double click opens the event page.
func TestBrowserEventBubble(t *testing.T) {
	b := newBrowser(t)
	csrf := b.h.login()
	resp := b.h.post("/calendar/event", url.Values{
		"csrf": {csrf}, "op": {"save"}, "summary": {"Design review"}, "location": {"Room 4"},
		"start_date": {"2026-10-21"}, "start_time": {"10:00"}, "end_date": {"2026-10-21"}, "end_time": {"11:00"},
		"ends": {"never"}, "interval": {"1"}, "calendar": {"Work"}, "reminder": {"15"}, "busy": {"busy"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	b.login()
	const week = "/calendar?view=week&date=2026-10-21"
	b.run(chromedp.Navigate(b.url(week)), chromedp.WaitVisible(chromedp.CSS(`.ev[data-ctx="event"]`)))
	b.waitFor(`document.readyState === "complete"`)
	ev := func() *chromedp.Node {
		ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
		defer cancel()
		nodes, err := chromedp.Run(ctx, chromedp.Nodes(chromedp.CSS(`.ev[data-ctx="event"]`), chromedp.NodeVisible))
		if err != nil {
			t.Fatal(err)
		}
		return nodes[0]
	}

	b.run(chromedp.MouseClickNode(ev()))
	b.waitFor(`!!document.querySelector(".event-peek .event-view")`)
	if got := evalAs[string](b, `location.pathname + location.search`); got != week {
		t.Errorf("a single click left the calendar for %s", got)
	}
	text := evalAs[string](b, `document.querySelector(".event-peek").textContent`)
	for _, want := range []string{"Design review", "Room 4", "Open", "Edit", "Delete"} {
		if !strings.Contains(text, want) {
			t.Errorf("bubble %q lacks %q", text, want)
		}
	}
	if !evalAs[bool](b, `(() => { const p = document.querySelector(".event-peek").getBoundingClientRect(), e = document.querySelector(".ev").getBoundingClientRect(); return p.left >= e.right || p.right <= e.left || p.top >= e.bottom || p.bottom <= e.top })()`) {
		t.Error("the bubble covers the event it belongs to")
	}
	// Escape closes it and puts the keyboard back on the event.
	b.run(chromedp.KeyEvent("\x1b"))
	b.waitFor(`!document.querySelector(".event-peek") && document.activeElement.matches(".ev")`)
	// So does a click elsewhere.
	b.run(chromedp.MouseClickNode(ev()))
	b.waitFor(`!!document.querySelector(".event-peek .event-view")`)
	b.run(chromedp.MouseClickXY(5, 5))
	b.waitFor(`!document.querySelector(".event-peek")`)

	// A double click as a mouse sends it: one click, then a second that
	// counts two.
	n := ev()
	b.run(chromedp.MouseClickNode(n), chromedp.MouseClickNode(n, chromedp.ClickCount(2)))
	b.waitFor(`location.pathname === "/calendar/event" && !!document.querySelector(".event-view h2")`)
	if text := evalAs[string](b, `document.querySelector(".event-view h2").textContent`); !strings.Contains(text, "Design review") {
		t.Errorf("double click opened %q", text)
	}
}
