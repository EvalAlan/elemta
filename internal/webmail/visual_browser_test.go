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
