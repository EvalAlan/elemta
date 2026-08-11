package suppression

import "strings"

// Deciding what a failure means.
//
// The queue already separates permanent from transient failures to decide
// whether to retry. Suppression asks a narrower question: should we stop
// mailing this address entirely, from now on, across campaigns?
//
// Those are not the same question, and treating them as the same is the
// mistake worth avoiding in both directions:
//
//   - Suppressing on a transient failure silently stops mailing someone whose
//     server was down for an hour. They never hear from you again and nobody
//     finds out.
//   - Not suppressing on a permanent failure means every campaign re-mails
//     addresses that do not exist, which is the bounce rate receivers use to
//     decide whether to deliver any of your mail.

// ShouldSuppress reports whether a permanent failure means the address should
// never be mailed again, and why.
//
// Only called for failures the queue has already judged permanent. Even then it
// is not automatic: a 5xx can be about the message or about the sender rather
// than about the recipient, and suppressing the recipient for those would
// remove people from a list because of something we did.
func ShouldSuppress(code, diagnostic string) (Source, bool) {
	text := strings.ToLower(diagnostic)

	// A complaint outranks everything: the address works, and the person has
	// said they do not want the mail. Mailing them again is the fastest way to
	// be blocked outright.
	if containsAny(text, "abuse report", "complaint", "listed as spam by the recipient", "feedback loop") {
		return SourceComplaint, true
	}

	// Failures that are about us, not about the recipient. Suppressing here
	// would delete valid addresses from the list because our IP was blocked or
	// our message was too large — and once removed, nobody notices they stopped
	// receiving mail.
	if containsAny(text,
		"message too large", "size limit", "quota exceeded", "mailbox full", "over quota",
		"blocked", "blacklist", "blocklist", "spam", "policy", "rate limit", "too many",
		"greylist", "try again", "temporarily",
	) {
		return "", false
	}

	// What is left is the recipient not existing, which is the case suppression
	// is for. The enhanced status codes are the reliable signal; the text is a
	// fallback because plenty of servers do not send one.
	if strings.HasPrefix(code, "5.1.1") || // bad destination mailbox address
		strings.HasPrefix(code, "5.1.3") || // bad destination mailbox syntax
		strings.HasPrefix(code, "5.1.6") || // mailbox has moved
		strings.HasPrefix(code, "5.1.10") { // recipient address has null MX
		return SourceBounce, true
	}

	if containsAny(text,
		"user unknown", "unknown user", "no such user", "does not exist", "doesn't exist",
		"no such recipient", "recipient not found", "invalid recipient", "unrouteable address",
		"address rejected", "mailbox unavailable", "no mailbox",
	) {
		return SourceBounce, true
	}

	// Permanent, but for a reason this does not recognise. Not suppressing is
	// the safer default: an unrecognised 5xx recurring is visible in the failed
	// queue and in the message trace, whereas an address removed by a guess is
	// invisible.
	return "", false
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
