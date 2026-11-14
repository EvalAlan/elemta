package smtp

import (
	"fmt"
	"strings"

	"github.com/EvalAlan/elemta/internal/authresult"
)

// Mail from outside that claims one of this server's own domains.
//
// DMARC enforcement is off by default, because enforcing it for everyone
// refuses mail that forwarders and mailing lists have legitimately changed.
// That left mail claiming this server's own domains, from anywhere,
// accepted: delivered to colleagues as if from the CEO, acted on by room
// booking, and sent on by forwarding with this server's signature.
//
// For its own domains the trade-off is different. The operator publishes
// those domains' DMARC records, and a record of p=reject is their statement
// that real mail from the domain always authenticates. So a message that
// fails DMARC for a local domain publishing p=reject is refused even when
// enforcement is off for everyone else. p=quarantine and p=none are left as
// they are: those owners have asked for less.
//
// The operator's own relays are exempt: the mailbox service's auto-replies,
// list copies and scheduled sends reach the MTA there unsigned (they're
// signed on the way out), and anything forged that they carry was checked
// when it first arrived.

// ownDomainDMARCRefusal returns the refusal for results, or nil.
func ownDomainDMARCRefusal(results authresult.Results, localDomains []string, ownRelay bool) error {
	if ownRelay || results.Disposition == "reject" || results.DMARC.Value != "fail" || results.Policy != "reject" {
		return nil
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(results.DMARC.Domain), "."))
	for _, d := range localDomains {
		if domain != "" && strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(d), "."), domain) {
			return fmt.Errorf("550 5.7.1 Message claims to be from %s, which this server hosts, and fails its DMARC check", domain)
		}
	}
	return nil
}
