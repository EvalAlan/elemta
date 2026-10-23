package webmail

import (
	"context"
	"net"
)

type clientIPKey struct{}

// clientIPFrom is the address authed recorded for the request: the client
// itself, behind a trusted proxy.
func clientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

// stampOrigin puts the sender's address in d's X-Originating-IP when the
// operator turned that on. It is off by default: the header tells every
// recipient where the user was, which the large webmails stopped doing.
// logSent keeps the same fact on the server either way.
func (s *Server) stampOrigin(ctx context.Context, d *Draft) {
	if !s.cfg.OriginatingIPHeader {
		return
	}
	if ip := net.ParseIP(clientIPFrom(ctx)); ip != nil {
		d.OriginatingIP = ip.String()
	}
}

// logSent records a message the user sent. An abuse report quotes the
// Message-ID, which this line ties to the account and the address it was
// sent from.
func (s *Server) logSent(ctx context.Context, sess *Session, d *Draft, kind string) {
	s.log.Info("webmail: sent", "user", sess.User, "ip", clientIPFrom(ctx),
		"message_id", d.MessageID, "recipients", len(d.Recipients()), "kind", kind)
}
