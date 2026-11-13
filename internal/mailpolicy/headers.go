package mailpolicy

import (
	"bytes"
	"net/mail"
	"strings"
)

// HeaderValues returns the values of every field called name in raw's header
// section, unfolded. It is deliberately lenient: a strict parser stops at the
// first malformed line, which would let a sender hide a From behind one from
// a check while the DKIM signer and the recipient's software still find it.
// Every line with a colon before the blank line is a field here.
func HeaderValues(raw []byte, name string) []string {
	if end := bytes.Index(raw, []byte("\r\n\r\n")); end >= 0 {
		raw = raw[:end]
	} else if end := bytes.Index(raw, []byte("\n\n")); end >= 0 {
		raw = raw[:end]
	}
	var out []string
	current := -1
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			if current >= 0 {
				out[current] += " " + strings.TrimSpace(line)
			}
			continue
		}
		current = -1
		field, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(field), name) {
			out = append(out, strings.TrimSpace(value))
			current = len(out) - 1
		}
	}
	return out
}

// FromAddresses returns every address in every From field of raw. ok is false
// when a From field can't be parsed, which callers must treat as not owned
// rather than as absent.
func FromAddresses(raw []byte) (addrs []string, ok bool) {
	for _, field := range HeaderValues(raw, "From") {
		list, err := mail.ParseAddressList(field)
		if err != nil || len(list) == 0 {
			return nil, false
		}
		for _, a := range list {
			addrs = append(addrs, a.Address)
		}
	}
	return addrs, true
}
