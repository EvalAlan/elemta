package commands

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The shipped config used to say type = "elastic" with an Elasticsearch URL and
// none of it was consumed, so an operator reading their own configuration had
// every reason to believe logs were being shipped somewhere. The settings are
// still parsed, because deployments in the field carry them; the point of the
// warning is that the silence ends.

func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(previous)
	fn()
	return buf.String()
}

func TestUnimplementedLoggingSettingsAreCalledOut(t *testing.T) {
	out := captureLogs(t, func() {
		warnAboutUnusedLoggingSettings("elastic", "http://elemta-elasticsearch:9200", "/var/log/elemta.log")
	})

	for _, want := range []string{"type setting is not implemented", "output setting is not implemented", "file setting is not implemented"} {
		if !strings.Contains(out, want) {
			t.Errorf("no warning about %q:\n%s", want, out)
		}
	}
	// The warning has to say what to do instead, or it is just noise.
	if !strings.Contains(out, "elk-up") {
		t.Errorf("the warning does not point anywhere useful:\n%s", out)
	}
}

// TestTheDefaultConfigurationIsSilent. A warning that fires for everybody is one
// people learn to ignore, and the shipped config sets none of these.
func TestTheDefaultConfigurationIsSilent(t *testing.T) {
	for _, logType := range []string{"", "console", "stdout", "  Console  "} {
		out := captureLogs(t, func() {
			warnAboutUnusedLoggingSettings(logType, "", "")
		})
		if out != "" {
			t.Errorf("type %q warned when it should not have:\n%s", logType, out)
		}
	}
}
