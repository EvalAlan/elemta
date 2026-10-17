package webmail

import (
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
