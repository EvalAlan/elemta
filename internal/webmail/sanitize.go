package webmail

import (
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
}

var spacerImage = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="

// sanitizeHTML returns HTML that is safe to show in a sandboxed frame: no
// scripts, no event handlers, no forms, no frames, no remote content unless
// allowed, and links that open in a new tab without a referrer.
func sanitizeHTML(in string, opts sanitizeOptions) sanitizeResult {
	var blocked atomic.Int64
	p := bluemonday.UGCPolicy()
	p.AllowStyles(safeStyleProperties...).Globally()
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
	return sanitizeResult{HTML: out, BlockedImages: int(blocked.Load())}
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
