package campaign

import (
	"net/mail"
	"strings"
)

// SenderAllowed reports whether a campaign may go out From address.
//
// Campaign mail is signed on the way out for its From domain, so the From
// decides whose reputation a bulk send spends and whose name it carries.
// With no allowed list it may be any address in a domain this server hosts.
// The list widens or narrows that: an entry is an address ("news@example.com")
// or a domain ("example.com" or "@example.com"), and with a list set only
// what it names may send, hosted or not. That lets an operator send as a
// domain hosted elsewhere, or keep campaigns to one newsletter address.
// Recipients are not limited either way.
func SenderAllowed(from string, hosted, allowed []string) bool {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return false
	}
	address := strings.ToLower(addr.Address)
	at := strings.LastIndexByte(address, '@')
	if at < 1 || at == len(address)-1 {
		return false
	}
	domain := address[at+1:]
	if len(allowed) == 0 {
		for _, d := range hosted {
			if strings.EqualFold(strings.TrimSpace(d), domain) {
				return true
			}
		}
		return false
	}
	for _, entry := range allowed {
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch {
		case entry == "":
		case strings.Contains(strings.TrimPrefix(entry, "@"), "@"):
			if entry == address {
				return true
			}
		case strings.TrimPrefix(entry, "@") == domain:
			return true
		}
	}
	return false
}

// ValidSenderEntry checks one allowed_senders entry: an address, or a
// domain with or without a leading "@".
func ValidSenderEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	if strings.Contains(strings.TrimPrefix(entry, "@"), "@") {
		a, err := mail.ParseAddress(entry)
		return err == nil && a.Address == entry
	}
	d := strings.TrimPrefix(entry, "@")
	return d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, " \t<>,;")
}
