package arc

import (
	"strconv"
	"strings"
)

// header is one field exactly as it appeared, minus its trailing CRLF. The raw
// bytes are kept because "simple" canonicalization is defined in terms of them:
// unfolding on parse would make simple signatures unverifiable.
type header struct {
	name string // lowercased field name, for matching
	raw  string // "Name: value" including any folding
}

// message is a parsed RFC 5322 message split at the header/body boundary.
type message struct {
	headers []header
	body    string
}

// parseMessage splits a message without altering either half.
func parseMessage(raw []byte) message {
	text := string(raw)

	// Accept bare LF as well as CRLF. Mail that reached us over SMTP is CRLF,
	// but messages read from disk or produced by tests often are not, and a
	// parser that only understood CRLF would silently treat the whole message
	// as one header block.
	sep := "\r\n\r\n"
	index := strings.Index(text, sep)
	if index < 0 {
		sep = "\n\n"
		index = strings.Index(text, sep)
	}

	headerBlock := text
	body := ""
	if index >= 0 {
		headerBlock = text[:index]
		body = text[index+len(sep):]
	}

	return message{headers: parseHeaderBlock(headerBlock), body: body}
}

// parseHeaderBlock splits a header block into fields, keeping folded
// continuation lines attached to the field they belong to.
func parseHeaderBlock(block string) []header {
	block = strings.ReplaceAll(block, "\r\n", "\n")
	if block == "" {
		return nil
	}

	var headers []header
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		field := current.String()
		name, _, _ := strings.Cut(field, ":")
		headers = append(headers, header{
			name: strings.ToLower(strings.TrimSpace(name)),
			raw:  field,
		})
		current.Reset()
	}

	for _, line := range strings.Split(block, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of the previous field. The CRLF is restored because
			// simple canonicalization must see the fold exactly as it arrived.
			if current.Len() > 0 {
				current.WriteString("\r\n")
				current.WriteString(line)
			}
			continue
		}
		flush()
		current.WriteString(line)
	}
	flush()
	return headers
}

// selectHeaders picks the fields named by an h= tag, in the order given.
//
// RFC 6376 §5.4.2: when a name appears more than once in h=, each occurrence
// refers to a different instance of that field, taken from the bottom of the
// header block upwards. A name listed more times than the field appears
// contributes nothing — that is how a signer protects against a header being
// added later.
func selectHeaders(headers []header, list string, canon Canonicalization) string {
	used := map[string]int{}
	var out strings.Builder
	for _, rawName := range strings.Split(list, ":") {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		seen := used[name]
		found := ""
		count := 0
		// Walk upwards so the first reference gets the bottom-most instance.
		for i := len(headers) - 1; i >= 0; i-- {
			if headers[i].name != name {
				continue
			}
			if count == seen {
				found = headers[i].raw
				break
			}
			count++
		}
		used[name] = seen + 1
		if found == "" {
			continue
		}
		out.WriteString(canonicalizeHeader(found, canon))
	}
	return out.String()
}

// parseTags splits a DKIM/ARC tag list ("v=1; a=rsa-sha256; ...").
//
// Whitespace inside a value is preserved apart from the edges, because the b=
// and bh= values arrive folded across lines and must be reassembled before
// being decoded.
func parseTags(value string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		name, val, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		tags[name] = strings.TrimSpace(val)
	}
	return tags
}

// stripWSP removes all whitespace, for base64 values that arrived folded.
func stripWSP(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, value)
}

// headerValue returns the part of a field after the colon.
func headerValue(raw string) string {
	_, value, found := strings.Cut(raw, ":")
	if !found {
		return ""
	}
	return value
}

// instanceOf reads the i= tag. Zero means absent or unusable; instance numbers
// are 1-based in RFC 8617, so zero is never valid.
func instanceOf(raw string) int {
	tags := parseTags(headerValue(raw))
	n, err := strconv.Atoi(strings.TrimSpace(tags["i"]))
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// withEmptyTag rewrites a tag's value to empty, keeping everything else byte
// for byte. Signing a signature header requires hashing it with its own b=
// value removed but its structure intact.
func withEmptyTag(field, tag string) string {
	lower := strings.ToLower(field)
	search := tag + "="
	from := 0
	for {
		index := strings.Index(lower[from:], search)
		if index < 0 {
			return field
		}
		index += from
		// Must be a tag boundary: start of value, or after ';' possibly with
		// whitespace. Otherwise "b=" would match inside "cb=" or a base64 blob.
		if !tagStartsAt(lower, index) {
			from = index + 1
			continue
		}
		end := strings.IndexByte(field[index:], ';')
		if end < 0 {
			return field[:index+len(search)]
		}
		return field[:index+len(search)] + field[index+end:]
	}
}

func tagStartsAt(lower string, index int) bool {
	for i := index - 1; i >= 0; i-- {
		switch lower[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case ';', ':':
			return true
		default:
			return false
		}
	}
	return false
}
