package smtp

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// The header From is the identity recipients see and the one DMARC
// evaluates, and mail leaving through this server carries a DKIM signature
// for one of our domains. Binding only the envelope sender (sender_binding.go)
// left the header free: a signed-in user could send as anyone in their own
// domain with a signature that aligned with the forgery. So for a signed-in
// session every From address has to pass the same ownership rules as the
// envelope sender.

// headerValues returns the values of every field called name in head,
// unfolded. It is deliberately lenient: a strict parser stops at the first
// malformed line, which would let a sender hide a From behind one from this
// check while dkim.FromHeaderDomain and the recipient's software still find
// it. Every line with a colon before the blank line is a field here.
func headerValues(head []byte, name string) []string {
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	} else if end := bytes.Index(head, []byte("\n\n")); end >= 0 {
		head = head[:end]
	}
	var out []string
	current := -1
	for _, line := range strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n") {
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

// headerFromAddresses returns every address in every From field of head.
// ok is false when a From field can't be parsed, which callers must treat as
// not owned rather than as absent.
func headerFromAddresses(head []byte) (addrs []string, ok bool) {
	for _, field := range headerValues(head, "From") {
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

// checkHeaderFrom refuses a signed-in user's message whose From names an
// address the user may not send as. Sessions that aren't signed in are left
// alone: inbound mail is judged by SPF/DKIM/DMARC, and allowed relays are the
// operator's own systems.
func (dh *DataHandler) checkHeaderFrom(ctx context.Context, head []byte) error {
	if dh.state == nil || !dh.state.IsAuthenticated() || dh.session == nil || dh.session.commandHandler == nil {
		return nil
	}
	if auth := dh.config.Auth; auth != nil && auth.AllowAnySender {
		return nil
	}
	// The check reads the bounded head, but delivery finds From in the whole
	// message, so a header section running past the head could hide one.
	// No real mail has 256 KiB of headers.
	if len(head) >= DefaultHeadSize && !bytes.Contains(head, []byte("\r\n\r\n")) && !bytes.Contains(head, []byte("\n\n")) {
		return fmt.Errorf("552 5.6.0 Header section too large")
	}
	addrs, ok := headerFromAddresses(head)
	if !ok {
		return fmt.Errorf("550 5.7.1 From header could not be parsed")
	}
	for _, addr := range addrs {
		if err := dh.session.commandHandler.checkSenderBinding(ctx, addr); err != nil {
			if strings.HasPrefix(err.Error(), "4") {
				return err
			}
			dh.logger.WarnContext(ctx, "Message refused: From header not owned by authenticated user",
				"event_type", "rejection",
				"from_header", addr,
				"username", dh.state.GetUsername(),
			)
			return fmt.Errorf("550 5.7.1 From address <%s> is not one you may send as", sanitizeEmailForHeader(addr))
		}
	}
	return nil
}

// mayLaterSignFromHeader reports whether delivery may DKIM-sign this message
// for its header From domain when the envelope sender is empty. Delivery used
// to do that for every null-sender message, so anyone who could get one
// queued chose the signing domain by writing a From header.
//
// It is allowed for a signed-in user, whose From checkHeaderFrom has already
// bound to the login, and for the operator's own relays (the mailbox
// service's out-of-office replies) unless the message is a Sieve forward.
// A forward carries someone else's From, and the mailbox service marks every
// forward with sieveRedirectHeader, which a sender can add but never remove.
func (dh *DataHandler) mayLaterSignFromHeader(head []byte, mailFrom string) bool {
	if mailFrom != "" || dh.state == nil {
		return false
	}
	if dh.state.IsAuthenticated() {
		return true
	}
	if dh.session == nil || dh.session.commandHandler == nil || !dh.session.commandHandler.isRelayAllowed("") {
		return false
	}
	return len(headerValues(head, sieveRedirectHeader)) == 0
}

// sieveRedirectHeader marks a Sieve forward; see mailpolicy.SieveRedirectHeader.
const sieveRedirectHeader = mailpolicy.SieveRedirectHeader

// senderVerdict is the value of mailpolicy.SenderVerifiedHeader for this
// message. A signed-in user's From has been bound to the login by
// checkHeaderFrom, so its address is confirmed; otherwise DMARC confirms at
// most the From domain.
func (dh *DataHandler) senderVerdict(head []byte) string {
	if dh.state != nil && dh.state.IsAuthenticated() {
		if addrs, ok := headerFromAddresses(head); ok && len(addrs) == 1 && !strings.ContainsAny(addrs[0], " \t\r\n") {
			return "auth " + strings.ToLower(addrs[0])
		}
		return "none"
	}
	if dh.session != nil {
		if results, ok := dh.session.AuthResults(); ok && results.DMARC.Value == "pass" && results.DMARC.Domain != "" &&
			!strings.ContainsAny(results.DMARC.Domain, " \t\r\n") {
			return "dmarc " + strings.ToLower(results.DMARC.Domain)
		}
	}
	return "none"
}
