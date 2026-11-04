package webmail

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

func TestSanitizeRemovesActiveContent(t *testing.T) {
	in := `<div onclick="steal()" style="color:red;background-image:url(https://t.example/px)">hi</div>` +
		`<script>alert(1)</script><iframe src="https://evil.example"></iframe>` +
		`<form action="https://evil.example"><input name="pw"></form>` +
		`<a href="javascript:alert(1)">js</a><a href="data:text/html,<script>x</script>">data</a>` +
		`<a href="https://example.com/x">ok</a>`
	out := sanitizeHTML(in, sanitizeOptions{}).HTML
	for _, bad := range []string{"onclick", "<script", "<iframe", "<form", "<input", "javascript:", "data:text/html", "background-image", "t.example"} {
		if strings.Contains(out, bad) {
			t.Errorf("sanitised HTML still contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "color: red") && !strings.Contains(out, "color:red") {
		t.Errorf("safe inline style was dropped: %s", out)
	}
	if !strings.Contains(out, `href="https://example.com/x"`) || !strings.Contains(out, `rel="nofollow noreferrer noopener"`) || !strings.Contains(out, `target="_blank"`) {
		t.Errorf("external link not made safe: %s", out)
	}
}

func TestSanitizeBlocksRemoteImagesByDefault(t *testing.T) {
	in := `<img src="https://tracker.example/open.gif"><img src="http://cdn.example/a.png"><img src="data:image/png;base64,AAAA">`
	res := sanitizeHTML(in, sanitizeOptions{})
	if res.BlockedImages != 2 {
		t.Errorf("blocked = %d, want 2", res.BlockedImages)
	}
	if strings.Contains(res.HTML, "tracker.example") || strings.Contains(res.HTML, "cdn.example") {
		t.Errorf("remote image survived: %s", res.HTML)
	}
	if !strings.Contains(res.HTML, "data:image/png;base64,AAAA") {
		t.Errorf("inline data image was removed: %s", res.HTML)
	}

	res = sanitizeHTML(in, sanitizeOptions{AllowRemote: true})
	if res.BlockedImages != 0 || !strings.Contains(res.HTML, "tracker.example") {
		t.Errorf("AllowRemote should keep remote images: %+v", res)
	}
}

func TestSanitizeRewritesCID(t *testing.T) {
	in := `<img src="cid:logo@nw"><img src="cid:missing">`
	res := sanitizeHTML(in, sanitizeOptions{CIDURL: func(cid string) string {
		if cid == "logo@nw" {
			return "data:image/png;base64,QUJD"
		}
		return ""
	}})
	if !strings.Contains(res.HTML, "data:image/png;base64,QUJD") {
		t.Errorf("cid not rewritten: %s", res.HTML)
	}
	if strings.Contains(res.HTML, "cid:") {
		t.Errorf("unresolved cid left in place: %s", res.HTML)
	}
}

func TestHTMLToText(t *testing.T) {
	got := htmlToText("<p>Hello&nbsp;Dana,</p><p>See <b>you</b><br>soon</p><script>x()</script>")
	want := "Hello\u00a0Dana,\nSee you\nsoon"
	if got != want {
		t.Errorf("htmlToText = %q, want %q", got, want)
	}
}

func TestStyleBlocksAreKeptAndCleaned(t *testing.T) {
	in := `<html><head><style><!-- .title{color:#c0392b} @import url(https://evil.example/x.css); .bg{background:url(https://evil.example/p.png)} .x{width:expression(alert(1))} .ok{background:url(data:image/png;base64,AAAA)} </style><x></style><script>alert(1)</script> --></style></head>` +
		`<body bgcolor="#eef2f5" style="color:#222" text="#333"><h1 class="title" id="top">Hi</h1><a style="background:#1F4FA8;color:#fff" href="https://example.com">Confirm</a><p style="background:url(https://evil.example/q.png)">x</p></body></html>`
	res := sanitizeHTML(in, sanitizeOptions{})
	for _, want := range []string{".title{color:#c0392b}", "data:image/png;base64,AAAA"} {
		if !strings.Contains(res.CSS, want) {
			t.Errorf("CSS lacks %q: %s", want, res.CSS)
		}
	}
	for _, bad := range []string{"@import", "evil.example", "expression", "<"} {
		if strings.Contains(res.CSS, bad) {
			t.Errorf("CSS kept %q: %s", bad, res.CSS)
		}
	}
	if res.BlockedImages < 1 {
		t.Error("a remote CSS image should count as blocked")
	}
	for _, want := range []string{`class="title"`, `id="top"`, `background: #1F4FA8`, `bgcolor="#eef2f5"`, `class="elemta-body"`} {
		if !strings.Contains(res.HTML, want) {
			t.Errorf("HTML lacks %q:\n%s", want, res.HTML)
		}
	}
	if strings.Contains(res.HTML, "evil.example") || strings.Contains(res.HTML, "<script") {
		t.Errorf("HTML kept remote or script content:\n%s", res.HTML)
	}
	allowed := sanitizeHTML(in, sanitizeOptions{AllowRemote: true})
	if !strings.Contains(allowed.CSS, "https://evil.example/p.png") {
		t.Error("remote CSS image not restored when images are allowed")
	}
}

// A hidden preview line keeps the styles that hide it, and utility class
// names keep their class attribute, so the message's stylesheet applies.
func TestSanitizeKeepsHiddenPreheaderAndUtilityClasses(t *testing.T) {
	in := `<div class="h-0 invisible max-h-[0] md:w-1/2" style="visibility: hidden; height: 0px; max-height: 0; width: 0px; overflow: hidden; opacity: 0; mso-hide: all;">preview</div>`
	out := sanitizeHTML(in, sanitizeOptions{}).HTML
	for _, want := range []string{"visibility: hidden", "overflow: hidden", "opacity: 0", `class="h-0 invisible max-h-[0] md:w-1/2"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	// The newly allowed properties still load nothing.
	out = sanitizeHTML(`<div style="opacity: url(https://t.example/p); overflow: url(https://t.example/q); visibility: expression(alert(1))">x</div>`, sanitizeOptions{}).HTML
	if strings.Contains(out, "t.example") || strings.Contains(out, "expression") {
		t.Errorf("unsafe value kept: %s", out)
	}
}

// Inline background images (LinkedIn's post photos) go through the proxy
// when images are shown, are blocked and counted when they aren't, and no
// other url() survives in an inline style.
func TestSanitizeInlineBackgroundImages(t *testing.T) {
	signer := imageSigner{key: []byte("k")}
	in := `<td style="height:252px;background-color:#cfcfcf;background-size:cover;background-position:center;background-image:url(&quot;https://media.example.com/Post.JPG?t=AbC&quot;)">x</td>`

	res := sanitizeHTML(in, sanitizeOptions{AllowRemote: true, ImageURL: signer.url})
	want := html.EscapeString(`url("` + signer.url("https://media.example.com/Post.JPG?t=AbC") + `")`)
	if !strings.Contains(res.HTML, want) || !strings.Contains(res.HTML, "background-size: cover") {
		t.Fatalf("background not proxied (want %s):\n%s", want, res.HTML)
	}

	res = sanitizeHTML(in, sanitizeOptions{ImageURL: signer.url})
	if strings.Contains(res.HTML, "media.example.com") || strings.Contains(res.HTML, "/mail/image") || res.BlockedImages != 1 {
		t.Fatalf("blocked background leaked or wasn't counted (%d):\n%s", res.BlockedImages, res.HTML)
	}
	// Images allowed, proxy off: dropped, and not offered again by the banner.
	res = sanitizeHTML(in, sanitizeOptions{AllowRemote: true})
	if strings.Contains(res.HTML, "media.example.com") || res.BlockedImages != 0 {
		t.Fatalf("proxy off: %d\n%s", res.BlockedImages, res.HTML)
	}

	for _, attack := range []string{
		// A sender can't write a proxy address in: it isn't remote, so it's dropped.
		`<div style="background-image:url('/mail/image?u=https://x.example/a&amp;s=forged')">x</div>`,
		`<div style="background:url(javascript:alert(1))">x</div>`,
		`<div style="background-image:url(//x.example/a.png)">x</div>`,
		`<div style="background-image:expression(alert(1))">x</div>`,
		`<div style='background-image:url("https://x.example/a.png")'>x</div>`,
	} {
		out := sanitizeHTML(attack, sanitizeOptions{AllowRemote: true, ImageURL: signer.url}).HTML
		if strings.Contains(out, "forged") || strings.Contains(out, "javascript") || strings.Contains(out, "x.example/a.png\"") || strings.Contains(out, "expression") || strings.Contains(out, "//x.example") {
			t.Errorf("unsafe background kept:\n%s\n%s", attack, out)
		}
	}
}

func TestOnlyProxyURLs(t *testing.T) {
	for v, want := range map[string]bool{
		`url("/mail/image?u=https%3A%2F%2Fa&s=Ab-_")`: true,
		`#ccc url("/mail/image?u=x&s=y") no-repeat`:   true,
		`#1F4FA8`: true,
		`none`:    true,
		`url("/mail/image?u=x&s=y"), url(https://evil.example/a.png)`: false,
		`url(https://evil.example/a.png)`:                             false,
		`url("/mail/image?u=x&s=y\") url(https://e)")`:                false,
		`url("/mail/image?u=x"onerror=1)`:                             false,
		`url(/mail/image?u=x&s=y)`:                                    false, // never produced unquoted
		`url("data:image/png;base64,iVBORw0KGgo=")`:                   true,
		`url("data:text/html;base64,PHNjcmlwdD4=")`:                   false,
		`url("/mail/image?u=x") <script>`:                             false,
	} {
		if got := onlyProxyURLs(v); got != want {
			t.Errorf("onlyProxyURLs(%s) = %v, want %v", v, got, want)
		}
	}
}

// The background shorthand keeps colours and gradients, as before, but no
// other function gets through.
func TestBackgroundShorthandValues(t *testing.T) {
	for v, want := range map[string]bool{
		`linear-gradient(to right, #1F4FA8 0%, rgba(0, 0, 0, 0.5) 100%)`: true,
		`#fff none repeat scroll 0% 0%`:                                  true,
		`transparent`:                                                    true,
		`expression(alert(1))`:                                           false,
		`linear-gradient(red, expression(alert(1)))`:                     false,
		`-moz-element(#x)`:                                               false,
		`image-set("https://e.example/a.png" 1x)`:                        false,
	} {
		if got := onlyProxyURLs(v); got != want {
			t.Errorf("onlyProxyURLs(%s) = %v, want %v", v, got, want)
		}
	}
}

// A message's dark-mode rules never apply: mail is shown on a light page,
// and they would turn its text near-white over its own white background.
func TestSanitizeDropsDarkSchemeRules(t *testing.T) {
	in := `<style>@media (prefers-color-scheme: dark ) { .main { color: #eeeeee !important; } }` +
		`@media screen and (PREFERS-COLOR-SCHEME:dark) { a { color: #fff } }` +
		`@media (prefers-color-scheme: light) { .logo-light { display: block } }</style><p class="main">x</p>`
	css := sanitizeHTML(in, sanitizeOptions{}).CSS
	if regexp.MustCompile(`(?i)prefers-color-scheme\s*:\s*dark`).MatchString(css) {
		t.Fatalf("a dark-scheme query survived:\n%s", css)
	}
	if !strings.Contains(css, "prefers-color-scheme: light") {
		t.Fatalf("the light-scheme query was changed:\n%s", css)
	}
}
