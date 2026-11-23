package mailbox

import (
	"errors"
	"net"
	"time"
)

// Sign-in lines from mail apps. Until these, a refused IMAP or POP3 login
// left no line at all: the failure counted towards the limit in the database
// and nothing else, so neither the admin console's Logs tab nor a log cluster
// could show who was guessing at which account. The fields match the MTA's
// authentication lines (event_type "authentication", username, client_ip,
// success, failure_reason), so one query or dashboard panel counts sign-ins
// from every service.
//
// Only the public listeners log here. The webmail signs in over the internal
// listener for each user it serves and logs its own sign-ins with the user's
// real address; logging its IMAP connections too would count every webmail
// sign-in twice, from the webmail's own address. The credential recheck an
// open session makes every 30 seconds doesn't log either: it isn't a sign-in.

// maxLoggedName bounds a login name taken from a client, which can be
// anything it cares to send.
const maxLoggedName = 320

// remoteIP is the client's own address for a log line. clientKey isn't it:
// for IPv6 that is the /64 the failure limit counts.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// failureReason names why a sign-in was refused, for the log only; the client
// is told no more than before.
func failureReason(err error) string {
	switch {
	case errors.Is(err, ErrCredentials):
		return "credentials"
	case errors.Is(err, ErrProtocolDisabled):
		return "protocol_disabled"
	case errors.Is(err, errPOPInUse):
		return "in_use"
	default:
		return "unavailable"
	}
}

// logSignIn records one sign-in attempt by a mail app. name is what the client
// sent; a is the account it reached, when it reached one.
func (s *Service) logSignIn(protocol string, addr net.Addr, name string, a Account, err error) {
	if err == nil {
		s.log.Info("mailbox: signed in", "event_type", "authentication", "protocol", protocol,
			"username", a.Address, "client_ip", remoteIP(addr), "success", true)
		return
	}
	if len(name) > maxLoggedName {
		name = name[:maxLoggedName]
	}
	attrs := []any{"event_type", "authentication", "protocol", protocol, "username", name,
		"client_ip", remoteIP(addr), "success", false, "failure_reason", failureReason(err)}
	if failureReason(err) == "unavailable" {
		attrs = append(attrs, "error", err)
	}
	s.log.Warn("mailbox: sign-in refused", attrs...)
}

// logSessionEnd records the end of a signed-in mail app session, so a
// session's length and its end can be found next to its sign-in.
func (s *Service) logSessionEnd(protocol string, addr net.Addr, a Account, began time.Time) {
	s.log.Info("mailbox: session ended", "event_type", "session_end", "protocol", protocol,
		"username", a.Address, "client_ip", remoteIP(addr),
		"duration_ms", time.Since(began).Milliseconds())
}
