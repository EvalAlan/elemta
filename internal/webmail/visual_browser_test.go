//go:build browser

package webmail

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/device"
)

// layoutCheck runs in the page and reports what a person would see as
// broken: the page wider than the window (sideways scrolling on a phone),
// and text that can't be read against what is actually behind it (WCAG
// contrast: 4.5:1, or 3:1 for large text). The background is found by
// walking up from the text and blending translucent layers, as the browser
// paints them.
const layoutCheck = `(() => {
  const out = [];
  const de = document.documentElement;
  if (de.scrollWidth > de.clientWidth + 1) out.push("page is " + de.scrollWidth + "px wide in a " + de.clientWidth + "px window");
  const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return [0,0,0,0]; const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const lum = ([r,g,b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126*f(r) + 0.7152*f(g) + 0.0722*f(b); };
  const over = (top, under) => { const a = top[3]; return [top[0]*a + under[0]*(1-a), top[1]*a + under[1]*(1-a), top[2]*a + under[2]*(1-a), 1]; };
  const background = el => {
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage !== "none" && !cs.backgroundImage.startsWith("linear-gradient")) return null; // a picture: can't judge
      const c = parse(cs.backgroundColor);
      if (c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let bg = [255,255,255,1];
    for (let i = layers.length - 1; i >= 0; i--) bg = over(layers[i], bg);
    return bg;
  };
  const name = el => el.tagName.toLowerCase() + (el.id ? "#" + el.id : "") + (el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".") : "");
  const seen = new Set();
  for (const el of document.querySelectorAll("body *")) {
    if (el.closest(".visually-hidden, [hidden], [aria-hidden=\"true\"], iframe, svg, script, style, noscript, option")) continue;
    const text = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(" ").trim();
    if (!text) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === "hidden" || +cs.opacity === 0 || el.matches(":disabled")) continue;
    const bg = background(el);
    if (!bg) continue;
    let fg = parse(cs.color);
    fg = over([fg[0], fg[1], fg[2], fg[3] * (+cs.opacity || 1)], bg);
    const L1 = lum(fg), L2 = lum(bg);
    const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const size = parseFloat(cs.fontSize), bold = +cs.fontWeight >= 700;
    const need = (size >= 24 || (bold && size >= 18.66)) ? 3 : 4.5;
    if (ratio < need) {
      const key = name(el);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push("contrast " + ratio.toFixed(2) + " < " + need + ": " + key + " \"" + text.slice(0, 40) + "\"");
    }
  }
  return out;
})()`

var visualPalettes = []string{"", "tidewater", "forest", "plum", "sand", "graphite", "ocean", "rose", "ember", "arctic", "contrast"}

// Every page, in every colour scheme, light and dark, on a desktop and a
// phone: nothing wider than the window, and all text readable. Set
// ELEMTA_SCREENSHOTS to a directory to keep a picture of each.
func TestBrowserVisualQA(t *testing.T) {
	b := newBrowser(t)
	seedLongInbox(b, nil)
	b.login()
	shots := os.Getenv("ELEMTA_SCREENSHOTS")
	pages := map[string]string{
		"inbox":    "/mail?f=INBOX",
		"mail":     "/mail?f=INBOX&uid=7",
		"calendar": "/calendar?view=week",
		"compose":  "/compose",
		"settings": "/settings",
		"contacts": "/contacts",
	}
	var problems []string
	for _, width := range []struct {
		name string
		set  chromedp.Action[chromedp.Void]
	}{
		{"desktop", chromedp.EmulateViewport(1400, 900)},
		{"phone", chromedp.Emulate(device.IPhone13)},
	} {
		b.run(width.set)
		for page, path := range pages {
			b.run(chromedp.Navigate(b.url(path)))
			b.waitFor(`document.readyState === "complete"`)
			if width.name == "phone" {
				problems = append(problems, phoneChrome(b, page)...)
			}
			for _, palette := range visualPalettes {
				for _, theme := range []string{"light", "dark"} {
					b.run(chromedp.Evaluate[chromedp.Void](fmt.Sprintf(`(() => { const h = document.documentElement; h.setAttribute("data-theme", %q); if (%q) h.setAttribute("data-palette", %q); else h.removeAttribute("data-palette"); })()`, theme, palette, palette), chromedp.EvalAsValue))
					time.Sleep(30 * time.Millisecond)
					label := fmt.Sprintf("%s/%s/%s/%s", width.name, page, paletteLabel(palette), theme)
					for _, p := range evalAs[[]string](b, layoutCheck) {
						problems = append(problems, label+": "+p)
					}
					if shots != "" {
						ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
						png, err := chromedp.Run(ctx, chromedp.CaptureScreenshot())
						cancel()
						if err == nil {
							_ = os.WriteFile(filepath.Join(shots, strings.ReplaceAll(label, "/", "-")+".png"), png, 0o600)
						}
					}
				}
			}
		}
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func paletteLabel(p string) string {
	if p == "" {
		return "default"
	}
	return p
}

// phoneChrome checks that a phone's screen goes to the page rather than
// its navigation: the content starts within the top eighth of the screen,
// and an open message's subject within the top quarter. Overflow checks
// passed while the phone layout stacked the computer's sidebar and toolbars
// above the mail, half a screen of them.
func phoneChrome(b *browser, page string) []string {
	var problems []string
	got := evalAs[map[string]float64](b, `(() => {
		const h = window.innerHeight;
		const top = (sel) => { const el = document.querySelector(sel); return el ? el.getBoundingClientRect().top / h : -1; };
		return { main: top("#main"), subject: top("[data-message-subject]"), apps: top(".apps") };
	})()`)
	if got["main"] > 0.125 {
		problems = append(problems, fmt.Sprintf("phone/%s: the page starts %.0f%% down the screen", page, got["main"]*100))
	}
	if page == "mail" && (got["subject"] < 0 || got["subject"] > 0.25) {
		problems = append(problems, fmt.Sprintf("phone/%s: the subject starts %.0f%% down the screen", page, got["subject"]*100))
	}
	if page != "compose" && got["apps"] < 0.85 { // composing hides the app bar
		problems = append(problems, fmt.Sprintf("phone/%s: the apps aren't along the bottom (%.0f%%)", page, got["apps"]*100))
	}
	return problems
}

// On a phone the folders are in a drawer behind the menu button: it opens
// over the page, a folder in it is reachable, and Escape closes it. The
// account menu holds sign out, and a message's More menu holds the actions
// its one-row toolbar leaves out.
func TestBrowserPhoneDrawerAndMenus(t *testing.T) {
	b := newBrowser(t)
	seedLongInbox(b, nil)
	b.login()
	b.run(chromedp.Emulate(device.IPhone13))
	b.run(chromedp.Navigate(b.url("/mail?f=INBOX")))
	b.waitFor(`document.readyState === "complete" && !document.querySelector("[data-drawer]").hidden`)
	visible := `(sel) => { const el = document.querySelector(sel); if (!el) return false; const r = el.getBoundingClientRect(); return getComputedStyle(el).visibility === "visible" && r.right > 0 && r.left < innerWidth && r.width > 0; }`
	if evalAs[bool](b, `(`+visible+`)(".sidebar .folder")`) {
		t.Fatal("the folders show before the drawer is opened")
	}
	b.run(chromedp.Click(chromedp.CSS("[data-drawer]")))
	b.waitFor(`(` + visible + `)(".sidebar .folder[data-folder='INBOX']")`)
	if evalAs[string](b, `document.querySelector("[data-drawer]").getAttribute("aria-expanded")`) != "true" {
		t.Error("the menu button doesn't say the drawer is open")
	}
	b.run(chromedp.KeyEvent("\x1b")) // Escape
	b.waitFor(`!document.documentElement.classList.contains("drawer-open")`)

	// The account menu: sign out and settings, which the top bar no longer shows.
	b.run(chromedp.Click(chromedp.CSS(".account-menu > summary")))
	if !evalAs[bool](b, `(`+visible+`)(".account-menu .menu-body") && [...document.querySelectorAll(".account-menu button")].some(b => b.textContent.includes("Sign out"))`) {
		t.Error("the account menu doesn't offer sign out")
	}

	// A message: one row of controls; Reply all is in More.
	b.run(chromedp.Navigate(b.url("/mail?f=INBOX&uid=7")))
	b.waitFor(`document.readyState === "complete" && !!document.querySelector(".reader .toolbar")`)
	if h := evalAs[float64](b, `document.querySelector(".reader .toolbar").getBoundingClientRect().height`); h > 60 {
		t.Errorf("the message toolbar is %.0fpx tall: more than one row", h)
	}
	b.run(chromedp.Click(chromedp.CSS(`.toolbar summary[title="More"]`)))
	if !evalAs[bool](b, `[...document.querySelectorAll(".toolbar details[open] a")].some(a => a.textContent === "Reply all" && a.getBoundingClientRect().width > 0)`) {
		t.Error("Reply all isn't in More on a phone")
	}
}
