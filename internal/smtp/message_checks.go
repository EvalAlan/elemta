package smtp

import "math"

// MessageChecksConfig ([message_checks]) sets how strictly the content of
// mail from outside is checked at DATA, beyond what the protocol requires.
//
// The defaults accept what real mail looks like. A load test with 5,000
// messages from public corpora (the Enron mailboxes and the SpamAssassin
// ham) found these checks refusing about one legitimate message in twelve:
// To and Cc headers with no @ ("undisclosed-recipients"), addresses with a
// leading dot, address lists tripping an SQL-injection heuristic, recipient
// lists longer than 998 characters once unfolded, and 8-bit text that isn't
// UTF-8. Other MTAs accept all of these, and the sender's MTA only learns
// its mail bounced. DMARC, spam scoring and the address checks on the SMTP
// envelope still apply either way.
type MessageChecksConfig struct {
	// StrictAddressHeaders refuses mail whose From, To, Cc, Bcc or Reply-To
	// isn't a valid address list, or names an address that fails the
	// envelope address checks. Default false.
	StrictAddressHeaders bool `toml:"strict_address_headers" json:"strict_address_headers"`
	// MaxHeaderLength refuses mail with a header field longer than this many
	// characters after unfolding. 0, the default, sets no limit. RFC 5322's
	// 998 applies to each line of a field, not to a folded field as a whole,
	// so 998 here is stricter than the standard.
	MaxHeaderLength int `toml:"max_header_length" json:"max_header_length"`
	// RejectInvalidUTF8 refuses mail containing bytes that aren't UTF-8.
	// Default false: 8-bit mail in other character sets is legal with
	// 8BITMIME, and older mail is full of it.
	RejectInvalidUTF8 bool `toml:"reject_invalid_utf8" json:"reject_invalid_utf8"`
}

func (c *Config) messageChecks() MessageChecksConfig {
	if c == nil || c.MessageChecks == nil {
		return MessageChecksConfig{}
	}
	return *c.MessageChecks
}

// applyMessageChecks sets the validator's header length limit from the
// configuration.
func (v *EnhancedValidator) applyMessageChecks(c MessageChecksConfig) {
	if c.MaxHeaderLength > 0 {
		v.limits.MaxHeaderLength = c.MaxHeaderLength
	} else {
		v.limits.MaxHeaderLength = math.MaxInt32
	}
}
