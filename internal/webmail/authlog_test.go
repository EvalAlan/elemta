package webmail

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// jsonLines decodes every JSON log line in buf whose msg is msg.
func jsonLines(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(buf.String(), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func wantFields(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v (line %v)", k, line[k], v, line)
		}
	}
}

// Sign-ins carry the MTA's authentication fields, so the console's Logs tab
// and a log cluster can count them with every other service's.
func TestSignInsAreLoggedAsAuthenticationEvents(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.server.log = slog.New(slog.NewJSONHandler(&logs, nil))

	_, body := h.get("/login")
	tok := hiddenRE("token").FindStringSubmatch(body)[1]
	if resp := h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"nope"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", resp.StatusCode)
	}
	csrf := h.login()
	if resp := h.post("/logout", url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d", resp.StatusCode)
	}

	refused := jsonLines(t, &logs, "webmail: login refused")
	if len(refused) != 1 {
		t.Fatalf("%d refusal lines, want 1:\n%s", len(refused), logs.String())
	}
	wantFields(t, refused[0], map[string]any{"level": "WARN", "event_type": "authentication", "protocol": "webmail",
		"auth_method": "password", "username": "dana", "ip": "127.0.0.1", "success": false, "failure_reason": "credentials"})

	ok := jsonLines(t, &logs, "webmail: login")
	if len(ok) != 1 {
		t.Fatalf("%d login lines, want 1:\n%s", len(ok), logs.String())
	}
	wantFields(t, ok[0], map[string]any{"level": "INFO", "event_type": "authentication", "protocol": "webmail",
		"auth_method": "password", "username": "dana", "ip": "127.0.0.1", "success": true})
	if _, has := ok[0]["failure_reason"]; has {
		t.Errorf("a successful sign-in has a failure reason: %v", ok[0])
	}

	out := jsonLines(t, &logs, "webmail: logout")
	if len(out) != 1 {
		t.Fatalf("%d logout lines, want 1:\n%s", len(out), logs.String())
	}
	wantFields(t, out[0], map[string]any{"event_type": "logout", "username": "dana", "ip": "127.0.0.1"})

	// The password is never in the log, whichever way the sign-in went.
	if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "nope") {
		t.Errorf("a password reached the log:\n%s", logs.String())
	}
}

// A throttled address was turned away without a line; a guessing run that
// reached the limit then went quiet in the log at exactly the point it
// mattered.
func TestThrottledSignInIsLogged(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxFailuresPerUser; i++ {
		_, body := h.get("/login")
		tok := hiddenRE("token").FindStringSubmatch(body)[1]
		h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"wrong"}})
	}
	var logs bytes.Buffer
	h.server.log = slog.New(slog.NewJSONHandler(&logs, nil))
	_, body := h.get("/login")
	tok := hiddenRE("token").FindStringSubmatch(body)[1]
	if resp := h.post("/login", url.Values{"token": {tok}, "user": {"dana"}, "password": {"secret"}}); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	refused := jsonLines(t, &logs, "webmail: login refused")
	if len(refused) != 1 {
		t.Fatalf("%d refusal lines, want 1:\n%s", len(refused), logs.String())
	}
	wantFields(t, refused[0], map[string]any{"failure_reason": "throttled", "username": "dana", "success": false})
}

func TestLoggedNameIsBounded(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.server.log = slog.New(slog.NewJSONHandler(&logs, nil))
	h.server.logSignInRefused(strings.Repeat("a", 5000), "192.0.2.1", "password", "credentials")
	refused := jsonLines(t, &logs, "webmail: login refused")
	if len(refused) != 1 || len(refused[0]["username"].(string)) != maxLoggedName {
		t.Fatalf("username not bounded: %v", refused)
	}
}
