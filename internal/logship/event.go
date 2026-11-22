package logship

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// secretNames end the names of fields whose values never leave the process.
var secretNames = []string{"password", "passwd", "passphrase", "secret", "token", "authorization", "auth_header", "cookie", "csrf", "api_key", "apikey", "private_key", "credential", "credentials"}

// What a client typed can be anything, under any name. So a command is
// shipped only if SMTP or LMTP knows its verb, parameters never, and a line
// of a message never.
var (
	commandNames = []string{"command", "cmd", "original_line"}
	typedNames   = []string{"line", "args", "parameters"}
	commandVerbs = []string{"HELO", "EHLO", "LHLO", "MAIL", "RCPT", "DATA", "BDAT", "BURL", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELP", "STARTTLS"}

	// urlPassword finds the user and password of a URL, inside any text.
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s"<>]*@`)
)

const (
	redacted      = "[redacted]"
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

func scrub(m map[string]any, subjects bool, depth int) {
	for k, v := range m {
		name := strings.ReplaceAll(strings.ToLower(k), "-", "_")
		switch {
		case slices.ContainsFunc(secretNames, func(s string) bool { return strings.HasSuffix(name, s) }):
			// Whether there was one is useful, and no secret.
			if _, yesNo := v.(bool); !yesNo {
				m[k] = redacted
			}
		case slices.Contains(typedNames, name):
			m[k] = redacted
		case slices.Contains(commandNames, name):
			if s, ok := v.(string); ok {
				m[k] = safeCommand(s)
			} else {
				m[k] = redacted
			}
		case !subjects && (name == "subject" || strings.HasSuffix(name, "_subject")):
			delete(m, k)
		default:
			m[k] = scrubValue(v, subjects, depth+1)
		}
	}
}

func scrubValue(v any, subjects bool, depth int) any {
	switch t := v.(type) {
	case string:
		return urlPassword.ReplaceAllString(t, "${1}"+redacted+"@")
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

func safeCommand(s string) string {
	f := strings.Fields(s)
	switch {
	case len(f) == 0:
		return ""
	case strings.EqualFold(f[0], "AUTH"):
		if len(f) == 1 {
			return f[0]
		}
		return "AUTH " + redacted
	case slices.Contains(commandVerbs, strings.ToUpper(f[0])):
		return urlPassword.ReplaceAllString(s, "${1}"+redacted+"@")
	}
	return redacted
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

func addressOnly(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("").String(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("").String(), true
	}
	return "", false
}
