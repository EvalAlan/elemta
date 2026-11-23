package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// consoleSources is every file the console's pages are made of.
func consoleSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("../../web/static/*.js")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	files = append(files, "../../web/static/index.html", "../../web/login.html", "../../web/login.js")
	out := map[string]string{}
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- the repository's own static files
		require.NoError(t, err)
		out[f] = string(src)
	}
	return out
}

// The browser tests prove the escaping and the CSP; they don't run in CI, so
// this keeps what the CSP would refuse from coming back unnoticed.
func TestConsoleHasNoInlineScript(t *testing.T) {
	sources := consoleSources(t)
	inlineHandler := regexp.MustCompile(`\bon[a-z]+\s*=\s*["'$]`)
	inlineScript := regexp.MustCompile(`<script(\s[^>]*)?>\s*[^<\s]`)
	scriptTag := regexp.MustCompile(`<script\b[^>]*>`)
	jsURL := regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["']?\s*javascript:`)
	for f, src := range sources {
		// Report the match, not the file: the files are long.
		require.Empty(t, inlineHandler.FindString(src), "%s: an inline handler; use data-click and friends (actions.js)", f)
		require.Empty(t, jsURL.FindString(src), "%s: a javascript: URL", f)
		if strings.HasSuffix(f, ".html") {
			require.Empty(t, inlineScript.FindString(src), "%s: inline script", f)
			require.False(t, strings.Contains(src, "<style"), "%s: inline style element", f)
			for _, tag := range scriptTag.FindAllString(src, -1) {
				require.Contains(t, tag, `src="/`, "%s: %s", f, tag)
			}
		}
	}
	require.Contains(t, sources["../../web/static/index.html"], `src="/static/actions.js`)
	app := sources["../../web/static/app.js"]
	_, body, found := strings.Cut(app, "function escapeHtml(")
	require.True(t, found)
	body, _, _ = strings.Cut(body, "\n}")
	for _, entity := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
		require.Contains(t, body, entity, "escapeHtml is used inside attributes")
	}
	require.NotContains(t, app, `sandbox="allow-same-origin"`)
}

// Every action the markup names is one actions.js will call, and exists.
func TestConsoleActionsAreAllowed(t *testing.T) {
	sources := consoleSources(t)
	actions := sources["../../web/static/actions.js"]
	_, list, found := strings.Cut(actions, "const allowed = new Set([")
	require.True(t, found)
	list, _, _ = strings.Cut(list, "]);")
	allowed := map[string]bool{"dismiss": true, "removeRow": true, "openFilePicker": true}
	for _, m := range regexp.MustCompile(`'([A-Za-z]+)'`).FindAllStringSubmatch(list, -1) {
		allowed[m[1]] = true
	}
	require.Greater(t, len(allowed), 50)

	used := regexp.MustCompile(`data-(?:click|change|input|submit)="([^"]*)"`)
	dynamicArgs := regexp.MustCompile(`data-args="\$\{\s*([A-Za-z]*)`)
	var all string
	for f, src := range sources {
		all += src
		for _, m := range used.FindAllStringSubmatch(src, -1) {
			require.True(t, allowed[m[1]], "%s: data action %q is not in actions.js's allowed list", f, m[1])
		}
		// Values from the server reach data-args only through actionArgs,
		// which escapes for the attribute.
		for _, m := range dynamicArgs.FindAllStringSubmatch(src, -1) {
			require.Equal(t, "actionArgs", m[1], "%s: data-args built without actionArgs", f)
		}
	}
	for name := range allowed {
		if slices.Contains([]string{"dismiss", "removeRow", "openFilePicker"}, name) {
			continue
		}
		require.True(t, strings.Contains(all, "function "+name+"(") || strings.Contains(all, "window."+name+" ="),
			"actions.js allows %q, but no script defines it", name)
	}
}

// The campaign preview's stylesheet is allowed by hash; a change to one must
// change the other.
func TestConsoleCSPPreviewHash(t *testing.T) {
	src, err := os.ReadFile("../../web/static/campaigns.js")
	require.NoError(t, err)
	m := regexp.MustCompile(`const PREVIEW_CSS = '([^'\\]*)';`).FindSubmatch(src)
	require.NotNil(t, m, "PREVIEW_CSS not found")
	sum := sha256.Sum256(m[1])
	require.Equal(t, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'", previewStyleHash,
		"PREVIEW_CSS changed: update previewStyleHash in console_csp.go")
}

func TestConsolePagesCarryCSP(t *testing.T) {
	t.Setenv("ELEMTA_WEBMAIL_PUBLIC_URL", "https://mail.example.com")
	webRoot, err := filepath.Abs("../../web/static")
	require.NoError(t, err)
	t.Chdir("../..")
	base, _ := startProvisionAPIWith(t, func(s *Server) { s.webRoot = webRoot })

	resp, err := http.Get(base + "/login")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self' https://mail.example.com"} {
		require.Contains(t, csp, want)
	}
	require.NotContains(t, strings.SplitN(strings.SplitN(csp, "script-src", 2)[1], ";", 2)[0], "unsafe")
	require.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	require.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

	// The sign-in page's script and style are public: the page needs them
	// before there is a session.
	for path, kind := range map[string]string{"/login.js": "javascript", "/login.css": "css"} {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Contains(t, resp.Header.Get("Content-Type"), kind, path)
		require.NotEmpty(t, b)
	}
}

func TestWebmailPublicURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                                       "",
		"https://mail.example.com":               "https://mail.example.com",
		"https://mail.example.com/":              "https://mail.example.com",
		"http://localhost:8080":                  "http://localhost:8080",
		"http://mail.example.com":                "",
		"https://mail.example.com/x":             "",
		"https://u@mail.example.com":             "",
		"https://mail.example.com?q=1":           "",
		"javascript:alert(1)":                    "",
		"https://mail.example.com; script-src *": "",
	} {
		t.Setenv("ELEMTA_WEBMAIL_PUBLIC_URL", in)
		require.Equal(t, want, webmailPublicURL(), in)
	}
}
