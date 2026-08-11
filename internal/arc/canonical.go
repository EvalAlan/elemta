package arc

import (
	"strings"
)

// Canonicalization is how a message is normalised before hashing, so that the
// incidental rewriting mail suffers in transit does not invalidate a signature.
// RFC 6376 §3.4 defines both forms; ARC reuses them unchanged.
type Canonicalization string

const (
	// CanonSimple tolerates almost nothing. Any change to a signed header, or
	// to anything but trailing empty lines in the body, breaks the signature.
	CanonSimple Canonicalization = "simple"
	// CanonRelaxed tolerates whitespace folding and header-name case changes,
	// which is what most relays actually do. It is the sane default.
	CanonRelaxed Canonicalization = "relaxed"
)

func (c Canonicalization) valid() bool {
	return c == CanonSimple || c == CanonRelaxed
}

// canonicalizeHeader normalises one header field.
//
// The field arrives without its trailing CRLF and with any folding still
// present, because "simple" is defined as the bytes exactly as they appeared —
// unfolding them first would corrupt it.
func canonicalizeHeader(field string, canon Canonicalization) string {
	if canon == CanonSimple {
		return field + "\r\n"
	}

	name, value, found := strings.Cut(field, ":")
	if !found {
		// Not a well-formed field. Hashing it verbatim is the safest thing;
		// the signature will simply not verify, which is the correct outcome.
		return strings.ToLower(strings.TrimSpace(field)) + "\r\n"
	}

	// Relaxed (RFC 6376 §3.4.2): lowercase the name, drop whitespace around the
	// colon, unfold, collapse runs of whitespace to one space, strip trailing
	// whitespace.
	name = strings.ToLower(strings.TrimSpace(name))
	value = unfold(value)
	value = collapseWSP(value)
	value = strings.TrimRight(value, " \t")
	// Leading whitespace belongs to the separator, not the value.
	value = strings.TrimLeft(value, " \t")
	return name + ":" + value + "\r\n"
}

// unfold joins continuation lines. A folded header is semantically one line;
// the fold is presentation only.
func unfold(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

// collapseWSP reduces every run of spaces and tabs to a single space.
func collapseWSP(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	inWSP := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' || c == '\t' {
			if !inWSP {
				out.WriteByte(' ')
				inWSP = true
			}
			continue
		}
		inWSP = false
		out.WriteByte(c)
	}
	return out.String()
}

// canonicalizeBody normalises the message body.
//
// Both forms delete trailing empty lines, because appending them is the one
// transformation essentially every mail system performs. Relaxed additionally
// forgives whitespace changes inside and at the end of lines.
func canonicalizeBody(body string, canon Canonicalization) string {
	// Work in terms of CRLF-terminated lines regardless of what arrived.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	lines := strings.Split(body, "\n")

	// A body ending in a line terminator produces a trailing empty element;
	// that is a terminator, not a line.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if canon == CanonRelaxed {
		for i, line := range lines {
			lines[i] = strings.TrimRight(collapseWSP(line), " \t")
		}
	}

	// Delete trailing empty lines (RFC 6376 §3.4.3 and §3.4.4).
	end := len(lines)
	for end > 0 && lines[end-1] == "" {
		end--
	}
	lines = lines[:end]

	if len(lines) == 0 {
		// An empty body canonicalises to a single CRLF, not to nothing. Hashing
		// the empty string here would make an empty body and a body of one blank
		// line produce the same hash.
		return "\r\n"
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
