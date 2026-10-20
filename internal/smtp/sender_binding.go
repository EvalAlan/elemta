package smtp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Sender binding: an authenticated client may only use a MAIL FROM it owns.
//
// AUTH proves who is connected, not which address they may claim. Without
// this check a single phished password becomes the ability to send as any
// address at all, and because the message leaves through us it carries our
// DKIM signature and passes the recipient's SPF/DMARC checks for our domains,
// which is worse than an open relay: it is a trusted forgery service.
//
// What counts as owned:
//   - a login that is an address owns exactly that address;
//   - a bare login ("alice") owns that local part at each local domain, since
//     that is what the mailbox behind it receives;
//   - [auth.sender_aliases] adds addresses or whole domains ("@example.org")
//     per login, for shared mailboxes and role accounts.
//
// The null sender is allowed. It cannot claim to be anyone, and an
// authenticated client (a list manager, a vacation responder) may have a real
// reason to send a non-delivery or auto-reply with it.
//
// Clients on a trusted network that did not authenticate are not checked:
// there is no login to compare against, and allowed_relays is already the
// operator saying "these hosts may send anything".

// checkSenderBinding returns an SMTP error if the authenticated user may not
// send as mailFrom. It is a no-op for unauthenticated sessions.
func (ch *CommandHandler) checkSenderBinding(ctx context.Context, mailFrom string) error {
	if !ch.state.IsAuthenticated() || mailFrom == "" {
		return nil
	}
	auth := ch.config.Auth
	if auth != nil && auth.AllowAnySender {
		return nil
	}
	login := ch.state.GetUsername()
	if senderOwnedBy(login, mailFrom, ch.config.LocalDomains, auth) {
		return nil
	}
	if policies := ch.senderPolicies(); policies != nil {
		ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		allowed, err := policies.client.ShareAccess(ctx, mailFrom, login, true)
		if err == nil && allowed {
			return nil
		}
		if err != nil && !errors.Is(err, mailpolicy.ErrNotFound) {
			return fmt.Errorf("451 4.3.0 Shared sender authorization unavailable")
		}
	}
	return fmt.Errorf("553 5.7.1 Sender address rejected: not owned by authenticated user %s", login)
}

// senderOwnedBy reports whether login may use addr as its envelope sender.
func senderOwnedBy(login, addr string, localDomains []string, auth *AuthConfig) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	local, domain := addr[:at], addr[at+1:]
	lowerLogin := strings.ToLower(strings.TrimSpace(login))

	if strings.Contains(lowerLogin, "@") {
		if lowerLogin == addr {
			return true
		}
	} else if lowerLogin != "" && lowerLogin == local {
		for _, d := range localDomains {
			if strings.EqualFold(d, domain) {
				return true
			}
		}
	}

	if auth == nil {
		return false
	}
	// Alias keys are matched case-insensitively, the same way the login is.
	for key, aliases := range auth.SenderAliases {
		if !strings.EqualFold(strings.TrimSpace(key), lowerLogin) {
			continue
		}
		for _, a := range aliases {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == addr || (strings.HasPrefix(a, "@") && a[1:] == domain) {
				return true
			}
		}
	}
	return false
}
