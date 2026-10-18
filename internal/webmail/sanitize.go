package webmail

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/microcosm-cc/bluemonday"
)

// safeStyleProperties are the inline CSS properties kept in message HTML.
// Email layouts depend on inline styles, so dropping them all makes most
// newsletters unreadable. Anything that can load a URL (background-image,
// list-style-image, content, cursor...) is left out, so remote content can't
// slip past the remote-image block through CSS.
var safeStyleProperties = []string{
	"color", "background-color", "font", "font-family", "font-size", "font-style",
	"font-weight", "line-height", "letter-spacing", "text-align", "text-decoration",
	"text-transform", "vertical-align", "white-space", "word-break", "word-wrap",
	"width", "max-width", "min-width", "height", "max-height", "min-height",
	"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
	"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
	"border", "border-top", "border-right", "border-bottom", "border-left",
	"border-color", "border-style", "border-width", "border-radius", "border-collapse",
	"border-spacing", "display", "table-layout",
}

// sanitizeOptions controls how message HTML is rewritten.
type sanitizeOptions struct {
	// AllowRemote keeps http(s) image sources. Off by default, because a
	// remote image tells the sender when, where and whether mail was read.
	AllowRemote bool
	// CIDURL maps a cid: reference to the URL that serves that part.
	CIDURL func(cid string) string
}

// sanitizeResult is cleaned HTML plus what the cleaning removed.
type sanitizeResult struct {
	HTML          string
	BlockedImages int
	// CSS is the message's own stylesheets (<style> blocks), cleaned, for
	// the frame's head. Much mail is styled by class from a <style> block
	// rather than inline, and looks broken without it.
	CSS string
}

var spacerImage = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="

// sanitizeHTML returns HTML that is safe to show in a sandboxed frame: no
// scripts, no event handlers, no forms, no frames, no remote content unless
// allowed, and links that open in a new tab without a referrer.
func sanitizeHTML(in string, opts sanitizeOptions) sanitizeResult {
	var blocked atomic.Int64
	css, cssBlocked := extractCSS(in, opts.AllowRemote)
	blocked.Add(int64(cssBlocked))
	in = wrapBody(in)
	p := bluemonday.UGCPolicy()
	p.AllowStyles(safeStyleProperties...).Globally()
	// The background shorthand carries a colour in most mail ("Confirm"
	// buttons are background:#1F4FA8;color:#fff). It's kept only when it
	// loads nothing; images come through img, where they can be blocked.
	p.AllowStyles("background").MatchingHandler(func(v string) bool {
		return !strings.Contains(strings.ToLower(v), "url(") && !strings.ContainsAny(v, "\\<>")
	}).Globally()
	// Classes and IDs, so the message's own stylesheet (above) applies.
	p.AllowAttrs("class").Matching(bluemonday.SpaceSeparatedTokens).Globally()
	p.AllowAttrs("id").Matching(regexp.MustCompile(`^[A-Za-z][\w-]{0,63}$`)).Globally()
	p.AllowAttrs("bgcolor", "align", "valign", "width", "height", "border", "cellpadding", "cellspacing").Globally()
	p.AllowElements("center", "font")
	p.AllowAttrs("color", "face", "size").OnElements("font")
	p.AllowURLSchemes("http", "https", "mailto", "cid", "data")
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.RequireParseableURLs(true)
	p.RewriteSrc(func(u *url.URL) {
		switch strings.ToLower(u.Scheme) {
		case "cid":
			target := ""
			if opts.CIDURL != nil {
				target = opts.CIDURL(u.Opaque)
			}
			replaceURL(u, target)
		case "data":
			// Only images may be inlined as data: URIs.
			if !strings.HasPrefix(strings.ToLower(u.Opaque), "image/") {
				replaceURL(u, spacerImage)
			}
		case "http", "https":
			if !opts.AllowRemote {
				blocked.Add(1)
				replaceURL(u, spacerImage)
			}
		default:
			replaceURL(u, spacerImage)
		}
	})
	// data: is allowed above only for <img src>; a data: link would be a
	// way to smuggle a document into a new tab.
	out := p.Sanitize(in)
	out = dataHrefRE.ReplaceAllString(out, `href="#"`)
	return sanitizeResult{HTML: out, BlockedImages: int(blocked.Load()), CSS: css}
}

var (
	styleBlockRE = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style\s*>`)
	cssCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssImportRE  = regexp.MustCompile(`(?i)@import[^;]*;?`)
	cssURLRE     = regexp.MustCompile(`(?i)url\(\s*(['"]?)([^'")]*)(['"]?)\s*\)`)
	cssDangerRE  = regexp.MustCompile(`(?i)(expression\s*\(|behavior\s*:|-moz-binding|javascript:|vbscript:)`)
	bodyTagRE    = regexp.MustCompile(`(?is)<body([^>]*)>`)
	bodyAttrRE   = regexp.MustCompile(`(?is)\b(style|bgcolor|text)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
)

// maxCSS caps the stylesheet carried into the frame.
const maxCSS = 256 << 10

// extractCSS collects a message's <style> blocks and makes them safe to put
// in the frame: no imports, no script-bearing constructs, nothing that can
// close the style element, and no remote url() unless remote content is
// allowed. The frame's CSP is the second line: it loads no remote style
// sheets or fonts in any case, and remote images only when allowed.
func extractCSS(in string, allowRemote bool) (string, int) {
	var b strings.Builder
	blocked := 0
	for _, m := range styleBlockRE.FindAllStringSubmatch(in, -1) {
		css := m[1]
		css = strings.NewReplacer("<!--", "", "-->", "").Replace(css)
		css = cssCommentRE.ReplaceAllString(css, "")
		css = cssImportRE.ReplaceAllString(css, "")
		css = cssDangerRE.ReplaceAllString(css, "")
		css = cssURLRE.ReplaceAllStringFunc(css, func(u string) string {
			target := strings.ToLower(strings.TrimSpace(cssURLRE.FindStringSubmatch(u)[2]))
			switch {
			case strings.HasPrefix(target, "data:image/"):
				return u
			case (strings.HasPrefix(target, "https:") || strings.HasPrefix(target, "http:")) && allowRemote:
				return u
			case strings.HasPrefix(target, "http"):
				blocked++
			}
			return "none"
		})
		// Nothing in CSS needs "<"; removing it means the text can never
		// end the <style> element it's placed in.
		css = strings.ReplaceAll(css, "<", "")
		b.WriteString(css)
		b.WriteString("\n")
		if b.Len() > maxCSS {
			break
		}
	}
	out := b.String()
	if len(out) > maxCSS {
		out = out[:maxCSS]
	}
	return out, blocked
}

// wrapBody keeps the <body> element's background and colours, which the
// sanitiser would drop with the body tag itself, by moving them onto a
// wrapper div around the content.
func wrapBody(in string) string {
	loc := bodyTagRE.FindStringSubmatchIndex(in)
	if loc == nil {
		return in
	}
	attrs := in[loc[2]:loc[3]]
	var styles []string
	bgcolor := ""
	for _, a := range bodyAttrRE.FindAllStringSubmatch(attrs, -1) {
		val := strings.Trim(a[2], `"'`)
		switch strings.ToLower(a[1]) {
		case "style":
			styles = append(styles, val)
		case "text":
			styles = append(styles, "color:"+val)
		case "bgcolor":
			bgcolor = val
		}
	}
	open := `<div class="elemta-body" style="` + html.EscapeString(strings.Join(styles, ";")) + `" bgcolor="` + html.EscapeString(bgcolor) + `">`
	rest := in[loc[1]:]
	if i := strings.LastIndex(strings.ToLower(rest), "</body"); i >= 0 {
		rest = rest[:i]
	}
	return in[:loc[0]] + open + rest + "</div>"
}

var dataHrefRE = regexp.MustCompile(`(?i)href="data:[^"]*"`)

// replaceURL overwrites u in place with target (or a spacer when target is
// empty or unparsable). RewriteSrc passes a pointer, so this is how a
// rewrite takes effect.
func replaceURL(u *url.URL, target string) {
	if target == "" {
		target = spacerImage
	}
	nu, err := url.Parse(target)
	if err != nil {
		nu, _ = url.Parse(spacerImage)
	}
	*u = *nu
}

var (
	blockBreakRE = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/li|/h[1-6])[^>]*>`)
	blankLinesRE = regexp.MustCompile(`\n{3,}`)
)

// htmlToText flattens an HTML body for quoting in a plain-text reply.
func htmlToText(in string) string {
	in = blockBreakRE.ReplaceAllString(in, "$0\n")
	out := html.UnescapeString(bluemonday.StrictPolicy().Sanitize(in))
	return strings.TrimSpace(blankLinesRE.ReplaceAllString(out, "\n\n"))
}

// composeStyles are the inline CSS properties the editor may produce:
// fonts, colours, alignment and indent. Bluemonday checks each value
// against the property's grammar, so nothing that loads a URL gets through.
var composeStyles = []string{
	"color", "background-color", "font-family", "font-size", "font-weight", "font-style",
	"text-decoration", "text-align", "margin-left", "padding-left",
}

// composePolicy is what the rich-text editor may send: formatting, fonts
// and colours, alignment, lists, quotes, tables, links and images that are
// part of the message (data: URIs, turned into inline attachments, or cid:
// references to them). No scripts, classes, forms or remote images.
var composePolicy = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "strike", "sub", "sup",
		"ul", "ol", "li", "blockquote", "pre", "code", "h1", "h2", "h3", "h4", "hr",
		"table", "thead", "tbody", "tr", "td", "th", "font")
	p.AllowAttrs("href").OnElements("a")
	p.AllowAttrs("align").OnElements("p", "div", "h1", "h2", "h3", "h4", "td", "th", "table")
	p.AllowAttrs("border", "cellpadding", "cellspacing", "width").OnElements("table")
	p.AllowAttrs("colspan", "rowspan", "width").OnElements("td", "th")
	p.AllowAttrs("color", "face", "size").OnElements("font")
	p.AllowStyles(composeStyles...).Globally()
	p.AllowImages()
	p.AllowDataURIImages()
	p.AllowAttrs("alt", "width", "height").OnElements("img")
	p.AllowURLSchemes("http", "https", "mailto", "cid", "data")
	p.RewriteSrc(func(u *url.URL) {
		// Images must travel with the message; a remote image would be a
		// tracking pixel in the user's own mail.
		switch strings.ToLower(u.Scheme) {
		case "cid":
		case "data":
			if !strings.HasPrefix(strings.ToLower(u.Opaque), "image/") {
				replaceURL(u, spacerImage)
			}
		default:
			replaceURL(u, spacerImage)
		}
	})
	p.RequireParseableURLs(true)
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	return p
}()

// sanitizeCompose cleans HTML from the editor.
func sanitizeCompose(in string) string {
	return strings.TrimSpace(composePolicy.Sanitize(in))
}

// dataImageRE matches an image the editor embedded as a data: URI.
var dataImageRE = regexp.MustCompile(`src="data:(image/(?:png|jpeg|gif|webp|bmp));base64,([A-Za-z0-9+/=\s]+)"`)

// extractInlineImages turns the data: images in composed HTML into inline
// attachments referenced by cid:, which is how mail clients expect
// pictures in a message body. budget caps their total size; what doesn't
// fit is dropped from the HTML and reported.
func extractInlineImages(html, domain string, budget int) (string, []Attachment, bool) {
	var parts []Attachment
	over := false
	n := 0
	out := dataImageRE.ReplaceAllStringFunc(html, func(m string) string {
		sub := dataImageRE.FindStringSubmatch(m)
		data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sub[2]), ""))
		if err != nil {
			return `src=""`
		}
		if len(data) > budget {
			over = true
			return `src=""`
		}
		budget -= len(data)
		n++
		id := newObjectID() + "@" + domain
		ext := strings.TrimPrefix(sub[1], "image/")
		if ext == "jpeg" {
			ext = "jpg"
		}
		parts = append(parts, Attachment{Filename: fmt.Sprintf("image%d.%s", n, ext), ContentType: sub[1], Data: data, ContentID: id})
		return `src="cid:` + id + `"`
	})
	return out, parts, over
}

var cidSrcRE = regexp.MustCompile(`src="cid:([^"]+)"`)

// inlineCIDs turns cid: images back into data: URIs, for reopening a
// draft or quoting a message in the editor.
func inlineCIDs(html string, raw []byte) string {
	return cidSrcRE.ReplaceAllStringFunc(html, func(m string) string {
		cid := cidSrcRE.FindStringSubmatch(m)[1]
		part, body, err := findPart(raw, 0, cid)
		if err != nil || len(body) > maxInlineImage || !strings.HasPrefix(part.ContentType, "image/") {
			return `src=""`
		}
		return `src="data:` + part.ContentType + ";base64," + base64.StdEncoding.EncodeToString(body) + `"`
	})
}

// textToHTML turns plain text into the editor's HTML: escaped, line
// breaks kept, and "> " quoted lines as blockquotes.
func textToHTML(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var b strings.Builder
	depth := 0
	for _, l := range lines {
		d := 0
		for strings.HasPrefix(l, ">") {
			d++
			l = strings.TrimPrefix(strings.TrimPrefix(l, ">"), " ")
		}
		for depth < d {
			b.WriteString("<blockquote>")
			depth++
		}
		for depth > d {
			b.WriteString("</blockquote>")
			depth--
		}
		b.WriteString(html.EscapeString(l))
		b.WriteString("<br>")
	}
	for ; depth > 0; depth-- {
		b.WriteString("</blockquote>")
	}
	return b.String()
}

// wrapHTMLBody gives a composed fragment the document shell and the light
// styling (quote bar, readable font) mail clients expect.
func wrapHTMLBody(fragment string) string {
	return `<!doctype html><html><head><meta charset="utf-8"><style>` +
		`body{font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5}` +
		`blockquote{margin:0 0 0 .8ex;border-left:2px solid #ccc;padding-left:1ex}` +
		`</style></head><body>` + fragment + `</body></html>`
}
