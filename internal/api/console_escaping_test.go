package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The browser test proves the escapers; it doesn't run in CI, so this keeps
// the two ways round them from coming back.
func TestConsoleEscaping(t *testing.T) {
	files, err := filepath.Glob("../../web/static/*.js")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	handler := regexp.MustCompile(`\bon[a-z]+="[^"]*\$\{\s*(encodeURI|escapeHtml\()`)
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- the repository's own static files
		require.NoError(t, err)
		require.NotRegexp(t, handler, string(src), "%s: an inline handler's argument needs escapeJsArg", f)
		if filepath.Base(f) != "app.js" {
			continue
		}
		_, body, found := strings.Cut(string(src), "function escapeHtml(")
		require.True(t, found)
		body, _, _ = strings.Cut(body, "\n}")
		for _, entity := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
			require.Contains(t, body, entity, "escapeHtml is used inside attributes")
		}
		require.NotContains(t, string(src), `sandbox="allow-same-origin"`)
	}
}
