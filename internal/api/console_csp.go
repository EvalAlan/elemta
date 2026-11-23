package api

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// previewStyleHash is the CSP hash of the campaign preview's own stylesheet
// (PREVIEW_CSS in web/static/campaigns.js). The preview is a srcdoc frame,
// and a srcdoc document inherits this page's policy, so its one <style>
// element is allowed by hash rather than by opening style-src to inline
// elements. TestConsoleCSPPreviewHash keeps the two in step.
const previewStyleHash = "'sha256-zeftC0s5dOjFxNiGwTDFtkC9FqbruSMjVb9ZiTxrtL0='"

// consoleCSP is the admin console's Content-Security-Policy.
//
// Scripts come only from this server's files: no inline script, no inline
// event handlers (web/static/actions.js wires the controls instead) and no
// eval. With that, text that slips past escaping can at worst become markup,
// never code, which is what makes the many innerHTML renderings tolerable.
//
// The exceptions, and why:
//   - style-src-attr 'unsafe-inline': the campaign editor is a contenteditable
//     whose content is mail, and mail is styled with style attributes. Without
//     this the editor would show a template unstyled. An attribute can only
//     restyle its own element; it can't run script or read the page.
//   - img-src https: and data:: a campaign shows its images, which live
//     wherever the sender hosts them, and the two-step QR code is a data: URL.
//   - form-action names the webmail: "Open mailbox" posts a one-time token to
//     it in a new tab.
func consoleCSP() string {
	formAction := "'self'"
	if u := webmailPublicURL(); u != "" {
		formAction += " " + u
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' " + previewStyleHash,
		"style-src-attr 'unsafe-inline'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action " + formAction,
		"frame-ancestors 'none'",
	}, "; ")
}

// setConsoleHeaders sets the security headers every console page carries.
func setConsoleHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", consoleCSP())
	h.Set("X-Content-Type-Options", "nosniff")
	// frame-ancestors says the same; this is for browsers that predate it.
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
}

// webmailPublicURL is the webmail's origin from ELEMTA_WEBMAIL_PUBLIC_URL,
// or "" when it is unset or not a bare origin. Plain http is accepted only
// for a local test stack, since the address carries a sign-in token.
func webmailPublicURL() string {
	publicURL := strings.TrimRight(os.Getenv("ELEMTA_WEBMAIL_PUBLIC_URL"), "/")
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return ""
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return ""
	}
	return publicURL
}
