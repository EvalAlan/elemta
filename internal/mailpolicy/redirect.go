package mailpolicy

// SieveRedirectHeader is the field the mailbox service puts at the top of
// every message a Sieve rule forwards. The mailbox uses it to stop redirect
// loops, and the MTA uses it to recognise a forward: a forward carries
// someone else's From, so the MTA must never DKIM-sign it for that From's
// domain (internal/smtp/header_from.go). A sender can add the field but
// cannot remove the one the mailbox adds, so its presence is safe to rely on
// in that direction only.
const SieveRedirectHeader = "X-Elemta-Sieve-Redirected-By"
