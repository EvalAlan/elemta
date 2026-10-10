package queue

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/EvalAlan/elemta/internal/dane"
	"github.com/EvalAlan/elemta/internal/tlsrpt"
)

// danePolicy is the usable TLSA records that apply to one MX host for one
// message. Nil means DANE does not apply.
type danePolicy struct {
	host    string
	records []dane.TLSA
}

// daneError is a connection refused because DANE could not be satisfied. It
// is temporary: RFC 7672 §2.2.2 has the sender try the next MX and then
// defer, since the fault may be a certificate rollover in progress.
type daneError struct {
	result string // TLS-RPT result type
	err    error
}

func (e *daneError) Error() string   { return e.err.Error() }
func (e *daneError) Unwrap() error   { return e.err }
func (e *daneError) Temporary() bool { return true }

// SetDANEResolver turns on DANE (RFC 7672) using r, which must validate
// DNSSEC. Nil turns it off.
func (h *SMTPDeliveryHandler) SetDANEResolver(r dane.Resolver) {
	h.dane = r
}

// danePolicyFor decides whether DANE applies to mxHost for domain. It
// applies only when the domain's MX RRset is signed (otherwise the MX host
// itself could be an attacker's) and the host publishes signed, usable TLSA
// records. Any lookup failure is returned as an error and defers delivery.
func (h *SMTPDeliveryHandler) danePolicyFor(ctx context.Context, domain, mxHost, address string) (*danePolicy, error) {
	if h.dane == nil {
		return nil, nil
	}
	secure, err := h.dane.MXSecure(ctx, domain)
	if err != nil {
		return nil, err
	}
	if !secure {
		return nil, nil
	}
	// The TLSA lookup uses the port actually dialled, which is 25 in
	// production; tests run the receiver elsewhere.
	port := 25
	if _, p, err := net.SplitHostPort(address); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	records, secure, err := h.dane.LookupTLSA(ctx, mxHost, port)
	if err != nil {
		return nil, err
	}
	usable := dane.Usable(records)
	if !secure || len(usable) == 0 {
		return nil, nil
	}
	return &danePolicy{host: strings.TrimSuffix(mxHost, "."), records: usable}, nil
}

// daneTLSConfig authenticates the server by TLSA instead of the web PKI.
func (h *SMTPDeliveryHandler) daneTLSConfig(host string, dp *danePolicy) *tls.Config {
	cfg := h.outboundTLSConfig(host)
	useTLSAVerification(cfg, dp)
	return cfg
}

// useTLSAVerification replaces web-PKI certificate verification on cfg with
// verification against the MX host's DNSSEC-signed TLSA records, as RFC 7672
// requires. DANE-EE certificates are commonly self-signed, so the PKI check
// would refuse hosts DANE says are authentic.
//
// Go only runs a custom verifier in place of its own when InsecureSkipVerify
// is set; VerifyConnection still runs on every handshake and fails it on a
// mismatch. Kept in one small function so the two settings cannot be
// separated.
func useTLSAVerification(cfg *tls.Config, dp *danePolicy) {
	// #nosec G402 -- verification is replaced, not skipped; see above.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return dane.Verify(cs, dp.records, dp.host)
	}
}

// reportPolicy is the TLS-RPT policy entry for these TLSA records.
func (dp *danePolicy) reportPolicy(domain string) tlsrpt.Policy {
	strs := make([]string, len(dp.records))
	for i, r := range dp.records {
		strs[i] = r.String()
	}
	return tlsrpt.Policy{Type: tlsrpt.PolicyTypeTLSA, Domain: domain, Strings: strs}
}

// reportDANEFailure records a session DANE refused. dp is nil when the
// failure was the DNSSEC lookup itself.
func (h *SMTPDeliveryHandler) reportDANEFailure(domain, mxHost string, dp *danePolicy, err error) {
	if h.tlsReports == nil {
		return
	}
	rec := tlsrpt.Session{
		ReceivingMX:   strings.TrimSuffix(mxHost, "."),
		FailureReason: err.Error(),
	}
	var de *daneError
	switch {
	case dp != nil && errors.As(err, &de):
		rec.Policy = dp.reportPolicy(domain)
		rec.ResultType = de.result
	default:
		rec.Policy = tlsrpt.Policy{Type: tlsrpt.PolicyTypeTLSA, Domain: domain}
		rec.ResultType = tlsrpt.ResultDNSSECInvalid
	}
	h.tlsReports.Record(rec)
}

func connLocal(c net.Conn) net.Addr {
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}

func connRemote(c net.Conn) net.Addr {
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}
