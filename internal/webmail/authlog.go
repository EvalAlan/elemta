package webmail

// Sign-in lines. The webmail logged a successful login and a wrong password,
// but as plain lines no query could tell apart from any other, and most ways a
// sign-in is refused (a throttled address, an app password, a wrong two-step
// code, a refused passkey, a class of service without webmail) logged nothing.
// These carry the MTA's authentication fields (event_type "authentication",
// username, success, failure_reason), so the admin console's Logs tab and a
// log cluster count the webmail's sign-ins with the mail apps' and the MTA's.
// "ip" is the client's own address, as on every other webmail line.
//
// method says how the person signed in:
//
//	password      the account password
//	two_step      the password and a code from an authenticator app
//	two_step_setup the password, while setting up a required second step
//	passkey       a passkey
//	admin_access  an administrator's short-lived access token
//	dav           a calendar or contacts app, with a password
//
// The reasons are for the log only; the person is told no more than before.

func (s *Server) logSignIn(user, ip, method string) {
	s.log.Info("webmail: login", "event_type", "authentication", "protocol", "webmail",
		"auth_method", method, "username", user, "ip", ip, "success", true)
}

func (s *Server) logSignInRefused(user, ip, method, reason string, extra ...any) {
	if len(user) > maxLoggedName {
		user = user[:maxLoggedName]
	}
	attrs := append([]any{"event_type", "authentication", "protocol", "webmail",
		"auth_method", method, "username", user, "ip", ip, "success", false,
		"failure_reason", reason}, extra...)
	s.log.Warn("webmail: login refused", attrs...)
}

// maxLoggedName bounds a name taken from a sign-in form, which can be
// anything someone cares to send.
const maxLoggedName = 320
