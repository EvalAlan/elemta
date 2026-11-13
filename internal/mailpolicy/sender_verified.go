package mailpolicy

import (
	"bytes"
	"strings"
)

// SenderVerifiedHeader carries the MTA's verdict on who sent a message, for
// the services behind it that act on mail (room booking, for one). A message
// says who it is from; this says what the MTA could confirm:
//
//	auth <address>   a signed-in user, whose From the MTA bound to the login
//	dmarc <domain>   passed DMARC for the From domain (the domain only)
//	none             nothing confirmed
//
// The MTA writes it among the trace headers it prepends to every message it
// accepts, so the first one in a message is always the MTA's. A sender can
// include their own, but it comes after, and SenderVerified reads only the
// first. Mail without one (queued before the MTA wrote it, or not from the
// MTA) reads as "none".
const SenderVerifiedHeader = "X-Elemta-Sender-Verified"

// SenderVerified returns the kind ("auth", "dmarc" or "none") and value of
// the first SenderVerifiedHeader in raw's header section.
func SenderVerified(raw []byte) (kind, value string) {
	if end := bytes.Index(raw, []byte("\r\n\r\n")); end >= 0 {
		raw = raw[:end]
	} else if end := bytes.Index(raw, []byte("\n\n")); end >= 0 {
		raw = raw[:end]
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		name, v, ok := strings.Cut(line, ":")
		if !ok || line == "" || line[0] == ' ' || line[0] == '\t' || !strings.EqualFold(strings.TrimSpace(name), SenderVerifiedHeader) {
			continue
		}
		kind, value, _ = strings.Cut(strings.TrimSpace(v), " ")
		kind, value = strings.ToLower(kind), strings.ToLower(strings.TrimSpace(value))
		if (kind == "auth" || kind == "dmarc") && value != "" {
			return kind, value
		}
		return "none", ""
	}
	return "none", ""
}
