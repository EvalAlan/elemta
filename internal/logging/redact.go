package logging

// What the process's own log may hold.
//
// The log is read by more people and programs than the mail is: whoever can
// read the container's output or the log file, support bundles, and anything
// it is copied to. So a password, or what a client typed where a password
// may have gone, never reaches it, whatever the line's author passed in.
// Shipped logs (internal/logship) go through the same rules and then drop
// subjects too; the local log keeps subjects, which operators look for.

import (
	"log/slog"
	"regexp"
	"slices"
	"strings"
)

// Redacted stands in for a value the log may not hold.
const Redacted = "[redacted]"

var (
	// secretNames end the names of fields whose values never reach a log.
	secretNames = []string{"password", "passwd", "passphrase", "secret", "token", "authorization", "auth_header", "cookie", "csrf", "api_key", "apikey", "private_key", "credential", "credentials"}

	// What a client typed can be anything, under any name. A command is
	// kept only if SMTP or LMTP knows its verb (after a refused AUTH, a
	// client's next line is often the base64 password, which arrives as an
	// unknown command), and the parameters or a line of a message never.
	commandNames = []string{"command", "cmd", "original_line"}
	typedNames   = []string{"line", "args", "parameters", "sanitized_input"}
	commandVerbs = []string{"HELO", "EHLO", "LHLO", "MAIL", "RCPT", "DATA", "BDAT", "BURL", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELP", "STARTTLS", "ETRN", "XCLIENT", "XFORWARD", "XDEBUG"}

	// urlPassword finds the user and password of a URL, inside any text:
	// a Valkey or database URL carries them, and so do errors quoting it.
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s"<>]*@`)
)

// FieldKind says what becomes of a field named name: "secret" (its value goes),
// "typed" (it was typed by the other end, so it goes), "command" (only a
// known verb stays, see SafeCommand) or "" (kept, with URL passwords gone).
func FieldKind(name string) string {
	name = strings.ReplaceAll(strings.ToLower(name), "-", "_")
	switch {
	case slices.ContainsFunc(secretNames, func(s string) bool { return strings.HasSuffix(name, s) }):
		return "secret"
	case slices.Contains(typedNames, name):
		return "typed"
	case slices.Contains(commandNames, name):
		return "command"
	}
	return ""
}

// ScrubText takes the user and password out of any URL in s.
func ScrubText(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	return urlPassword.ReplaceAllString(s, "${1}"+Redacted+"@")
}

// SafeCommand is an SMTP or LMTP command line as a log may hold it.
func SafeCommand(s string) string {
	f := strings.Fields(s)
	switch {
	case len(f) == 0:
		return ""
	case strings.EqualFold(f[0], "AUTH"):
		if len(f) == 1 {
			return f[0]
		}
		return "AUTH " + Redacted
	case slices.Contains(commandVerbs, strings.ToUpper(commandVerb(f[0]))):
		return ScrubText(s)
	}
	return Redacted
}

// commandVerb is the verb of a command's first word. The SMTP server logs
// a command with its line ending escaped ("QUIT\x0D\x0A"), so the verb may
// run on into a backslash, which base64 never holds.
func commandVerb(word string) string {
	if i := strings.IndexByte(word, '\\'); i >= 0 {
		return word[:i]
	}
	return word
}

// Redact is a slog ReplaceAttr that applies the rules above to every field,
// the message included.
func Redact(_ []string, a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch FieldKind(a.Key) {
	case "secret":
		// Whether there was one is useful, and no secret.
		if v.Kind() != slog.KindBool {
			a.Value = slog.StringValue(Redacted)
		}
		return a
	case "typed":
		a.Value = slog.StringValue(Redacted)
		return a
	case "command":
		if v.Kind() == slog.KindString {
			a.Value = slog.StringValue(SafeCommand(v.String()))
		} else {
			a.Value = slog.StringValue(Redacted)
		}
		return a
	}
	switch v.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(ScrubText(v.String()))
	case slog.KindAny:
		// An error's text often quotes the address it failed to reach.
		if err, ok := v.Any().(error); ok && err != nil {
			if s := err.Error(); strings.Contains(s, "@") {
				a.Value = slog.StringValue(ScrubText(s))
			}
		}
	}
	return a
}

// Options are the handler options every logger in the process uses.
func Options(level slog.Leveler) *slog.HandlerOptions {
	return &slog.HandlerOptions{Level: level, ReplaceAttr: Redact}
}
