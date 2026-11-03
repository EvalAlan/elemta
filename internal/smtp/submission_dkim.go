package smtp

// DKIM-signing what signed-in users send, as it arrives.
//
// Delivery signs mail as it leaves the server, which covers mail sent
// straight out. Mail to someone on this server was never signed, and when
// its recipient forwards it the copy goes out under its author's domain with
// no signature from that domain: SRS makes the envelope the forwarder's, so
// SPF can't align either, and the receiver's DMARC check fails. Gmail
// rejects it outright for a domain with p=reject. Signing at submission puts
// the author's signature in every copy, local ones included, and a forward
// carries it unchanged (headers are added above it, the body is kept).
//
// The domain is the envelope sender's, which the sender check has already
// bound to the signed-in user (sender_binding.go). The From header is only
// compared and logged, so signing for it would let a user sign as any
// domain this server holds a key for. When the two agree, as they do for
// ordinary mail, the signature aligns with From for DMARC.

import (
	"bytes"
	"context"
	"io"

	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/queue"
)

// signSubmission returns headerPrefix with a DKIM-Signature in front of it,
// and the domain signed for, when the session is a signed-in user and the
// sender's domain has a key. Otherwise it returns headerPrefix unchanged and
// "".
func (dh *DataHandler) signSubmission(ctx context.Context, headerPrefix []byte, body queue.ContentOpener, mailFrom string) ([]byte, string, error) {
	if dh.session == nil || dh.session.dkimSigner == nil || dh.state == nil || !dh.state.IsAuthenticated() {
		return headerPrefix, "", nil
	}
	domain := dkim.DomainFromAddress(mailFrom)
	if domain == "" || !dh.session.dkimSigner.HasKeyFor(domain) {
		return headerPrefix, "", nil
	}
	r, err := body()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = r.Close() }()
	sig, err := dh.session.dkimSigner.SignatureFor(io.MultiReader(bytes.NewReader(headerPrefix), r), domain)
	if err != nil || sig == "" {
		return nil, "", err
	}
	dh.logger.DebugContext(ctx, "Signed submission with DKIM", "domain", domain)
	return append([]byte(sig), headerPrefix...), domain, nil
}
