package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactKeepsSecretsOutOfTheLog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, Options(slog.LevelDebug)))
	const pw = "hunter2-not-for-logs"
	b64 := "aHVudGVyMi1ub3QtZm9yLWxvZ3M=" // what a client sends after a refused AUTH

	log.Warn("Unknown command received", "command", b64)
	log.Info("auth", "command", "AUTH PLAIN "+b64, "password", pw, "has_password", true)
	log.Info("Valkey client initialized", "url", "redis://:"+pw+"@valkey.example:6379/0")
	log.Error("connect failed", "error", errors.New(`dial redis://user:`+pw+`@valkey.example:6379: refused`))
	log.Warn("Suspicious dot-prefixed line detected", "line", `".x`+pw+`"`, "sanitized_input", pw)
	log.Info("dial redis://u:" + pw + "@valkey.example failed")
	log.With("component", "c").WithGroup("db").Info("open", "dsn_password", pw, "api_key", pw)

	out := buf.String()
	if strings.Contains(out, pw) || strings.Contains(out, b64) {
		t.Fatalf("a secret reached the log:\n%s", out)
	}
	for _, want := range []string{
		`"command":"[redacted]"`,
		`"command":"AUTH [redacted]"`,
		`"has_password":true`,
		`"url":"redis://[redacted]@valkey.example:6379/0"`,
		`refused`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
}

func TestRedactKeepsWhatOperatorsNeed(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, Options(nil)))
	log.Info("delivered", "command", "MAIL FROM:<a@example.com> SIZE=10", "subject", "Lunch", "from", "a@example.com", "error", errors.New("550 no such user"))
	out := buf.String()
	for _, want := range []string{`"command":"MAIL FROM:<a@example.com> SIZE=10"`, `"subject":"Lunch"`, `"from":"a@example.com"`, `"error":"550 no such user"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
}

func TestSafeCommand(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"AUTH":                   "AUTH",
		"auth login dXNlcg==":    "AUTH [redacted]",
		"EHLO client.example":    "EHLO client.example",
		"cGFzc3dvcmQ=":           Redacted,
		"XCLIENT ADDR=192.0.2.1": "XCLIENT ADDR=192.0.2.1",
		"PASS hunter2":           Redacted,
		`QUIT\x0D\x0A`:           `QUIT\x0D\x0A`,
		`RSET\r\n`:               `RSET\r\n`,
		`cGFz\x0D\x0A`:           Redacted,
	} {
		if got := SafeCommand(in); got != want {
			t.Errorf("SafeCommand(%q) = %q, want %q", in, got, want)
		}
	}
}
