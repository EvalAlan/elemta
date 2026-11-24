package logship

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/logging"
)

const (
	redacted      = logging.Redacted
	shortenTo     = 256
	maxEventDepth = 16
)

// prepare turns one logged line into what is put on the stream, or nil if it
// is below the level wanted. Secrets, and subjects unless wanted, are gone
// before the line leaves the process.
func prepare(line []byte, p policy, now time.Time) []byte {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	var e map[string]any
	d := json.NewDecoder(bytes.NewReader(line))
	d.UseNumber()
	if d.Decode(&e) != nil || e == nil {
		// A component with a text logger of its own.
		e = map[string]any{"msg": string(bytes.ToValidUTF8(line, nil))}
		for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
			if bytes.Contains(line, []byte("level="+l)) {
				e["level"] = l
			}
		}
	}
	level := slog.LevelInfo
	if s, ok := e["level"].(string); ok && level.UnmarshalText([]byte(s)) != nil {
		level = slog.LevelInfo
	}
	if level < levels[p.MinLevel] {
		return nil
	}
	e["level"] = level.String()
	if _, ok := e["time"].(string); !ok {
		e["time"] = now.UTC().Format(time.RFC3339Nano)
	}
	scrub(e, p.IncludeSubjects, 0)
	out, err := json.Marshal(e)
	if err != nil {
		return nil
	}
	if len(out) <= maxLineBytes {
		return out
	}
	for k, v := range e {
		if s, ok := v.(string); ok && len(s) > shortenTo {
			e[k] = strings.ToValidUTF8(s[:shortenTo], "")
		}
	}
	e["truncated"] = true
	if out, err = json.Marshal(e); err == nil && len(out) <= maxLineBytes {
		return out
	}
	small := map[string]any{"truncated": true}
	for _, k := range []string{"time", "level", "msg", "event_type", "component", "message_id"} {
		if s, ok := e[k].(string); ok {
			if len(s) > shortenTo {
				s = strings.ToValidUTF8(s[:shortenTo], "")
			}
			small[k] = s
		}
	}
	if out, err = json.Marshal(small); err == nil && len(out) <= maxLineBytes {
		return out
	}
	return nil
}

// scrub applies the process log's rules (internal/logging) to a line again,
// for components whose logger doesn't, then drops subjects unless wanted.
func scrub(m map[string]any, subjects bool, depth int) {
	for k, v := range m {
		name := strings.ReplaceAll(strings.ToLower(k), "-", "_")
		switch logging.FieldKind(k) {
		case "secret":
			// Whether there was one is useful, and no secret.
			if _, yesNo := v.(bool); !yesNo {
				m[k] = redacted
			}
		case "typed":
			m[k] = redacted
		case "command":
			if s, ok := v.(string); ok {
				m[k] = logging.SafeCommand(s)
			} else {
				m[k] = redacted
			}
		default:
			if !subjects && (name == "subject" || strings.HasSuffix(name, "_subject")) {
				delete(m, k)
				continue
			}
			m[k] = scrubValue(v, subjects, depth+1)
		}
	}
}

func scrubValue(v any, subjects bool, depth int) any {
	switch t := v.(type) {
	case string:
		return logging.ScrubText(t)
	case map[string]any:
		if depth >= maxEventDepth {
			return redacted
		}
		scrub(t, subjects, depth)
	case []any:
		if depth >= maxEventDepth {
			return redacted
		}
		for i := range t {
			t[i] = scrubValue(t[i], subjects, depth+1)
		}
	}
	return v
}

// clientKeys are the names the services log the other end's address under.
var clientKeys = []string{"client_ip", "remote_addr", "ip", "ip_address", "client", "remote"}

// document is a line as it is indexed. The fields everyone searches have ECS
// names and fixed types. The rest go under elemta, mapped as one flattened
// object: the same key is a string in one line and an object in another, and
// with a field each, the first type seen would have every later line of the
// other type refused.
func document(service, host string, line []byte, at time.Time) (map[string]any, time.Time) {
	var e map[string]any
	d := json.NewDecoder(bytes.NewReader(line))
	d.UseNumber()
	if d.Decode(&e) != nil || e == nil {
		e = map[string]any{"msg": strings.ToValidUTF8(string(line), "")}
	}
	if s, ok := e["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			at = t
		}
	}
	at = at.UTC()
	text := func(key string) string {
		s, _ := e[key].(string)
		return s
	}
	doc := map[string]any{
		"@timestamp": at.Format(time.RFC3339Nano),
		"message":    text("msg"),
		"service":    map[string]any{"name": service},
		"host":       map[string]any{"name": host},
	}
	if l := text("level"); l != "" {
		doc["log"] = map[string]any{"level": strings.ToLower(l)}
	}
	if a := text("event_type"); a != "" {
		doc["event"] = map[string]any{"action": a}
	}
	for _, key := range clientKeys {
		if ip, ok := addressOnly(text(key)); ok {
			doc["source"] = map[string]any{"ip": ip}
			break
		}
	}
	typed(doc, e)
	rest := map[string]any{}
	for k, v := range e {
		switch k {
		case "", "time", "msg", "level":
		default:
			if v != nil {
				rest[k] = v
			}
		}
	}
	doc["elemta"] = rest
	return doc, at
}

// typed copies the keys people chart and filter by into fields with types,
// so numbers can be summed and ranged and Kibana's field lists show them.
// They stay in elemta as well: saved searches and dashboards use those names.
// A value of the wrong type is skipped, not converted: the same key means
// different things on different lines, and a guess would be a wrong figure.
func typed(doc, e map[string]any) {
	put := func(path string, v any) {
		parts := strings.Split(path, ".")
		m := doc
		for _, p := range parts[:len(parts)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		m[parts[len(parts)-1]] = v
	}
	text := func(key, path string) {
		if s, ok := e[key].(string); ok && s != "" {
			put(path, s)
		}
	}
	number := func(key, path string, integer bool) {
		n, ok := e[key].(json.Number)
		if !ok {
			return
		}
		if i, err := n.Int64(); err == nil {
			put(path, i)
		} else if f, err := n.Float64(); err == nil && !integer {
			put(path, f)
		}
	}
	text("username", "user.name")
	text("failure_reason", "event.reason")
	text("client_hostname", "source.domain")
	text("message_id", "email.message_id")
	text("queue_id", "email.local_id")
	if s, ok := e["protocol"].(string); ok && s != "" {
		put("network.protocol", strings.ToLower(s))
	}
	if b, ok := e["success"].(bool); ok {
		put("event.outcome", map[bool]string{true: "success", false: "failure"}[b])
	}
	if b, ok := e["tls_active"].(bool); ok {
		put("tls.established", b)
	}
	// slog writes a time.Duration as nanoseconds, which is ECS's unit too.
	number("duration", "event.duration", true)
	number("size", "mail.size", true)
	number("spam_score", "mail.spam_score", false)
	number("recipient_count", "mail.recipient_count", true)
	// "550 5.7.1 Relay access denied": the code, and the enhanced status
	// when there is one.
	if s, ok := e["response"].(string); ok {
		f := strings.Fields(s)
		if len(f) > 0 && len(f[0]) == 3 && f[0][0] >= '2' && f[0][0] <= '5' && strings.Trim(f[0], "0123456789") == "" {
			code, _ := strconv.Atoi(f[0])
			put("mail.response_code", code)
			if len(f) > 1 && enhancedStatus.MatchString(f[1]) {
				put("mail.response_status", f[1])
			}
		}
	}
}

var enhancedStatus = regexp.MustCompile(`^[245]\.\d{1,3}\.\d{1,3}$`)

func addressOnly(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("").String(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("").String(), true
	}
	return "", false
}
