// Package dane implements DANE for SMTP (RFC 7672): authenticating an MX
// host's TLS certificate against TLSA records published in DNSSEC-signed DNS.
//
// MTA-STS authenticates MX hosts through the web PKI and a policy fetched over
// HTTPS; DANE does it through DNSSEC instead, and where both are published
// DANE takes precedence (RFC 8461 §2). Its advantage is that it is
// downgrade-resistant from the first message: an attacker who strips STARTTLS
// cannot also strip a signed TLSA record.
//
// Everything rests on the resolver's DNSSEC validation. Go's resolver does not
// validate, so lookups go to a configured validating resolver (unbound,
// systemd-resolved, a local BIND) and trust its AD bit. That resolver must be
// reachable over a path an attacker cannot tamper with, which in practice
// means loopback: an AD bit from a resolver across the network is only as
// trustworthy as the network.
package dane

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// TLSA usages, selectors and matching types (RFC 6698). SMTP uses only
// DANE-TA(2) and DANE-EE(3); PKIX-TA(0) and PKIX-EE(1) are unusable for SMTP
// (RFC 7672 §3.1.3), because an MX host's certificate need not chain to any
// particular public CA.
const (
	UsageDANETA = 2
	UsageDANEEE = 3

	SelectorCert = 0
	SelectorSPKI = 1

	MatchFull   = 0
	MatchSHA256 = 1
	MatchSHA512 = 2
)

// TLSA is one TLSA record.
type TLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         []byte
}

// String renders the record in presentation format, for logs and reports.
func (t TLSA) String() string {
	return fmt.Sprintf("%d %d %d %x", t.Usage, t.Selector, t.MatchingType, t.Data)
}

// Usable returns the records an SMTP client may use. If a host publishes
// TLSA records but none are usable, RFC 7672 §3.1.3 says to treat the host
// as having none: encrypt opportunistically, authenticate nothing.
func Usable(records []TLSA) []TLSA {
	var out []TLSA
	for _, r := range records {
		if r.Usage != UsageDANETA && r.Usage != UsageDANEEE {
			continue
		}
		if r.Selector != SelectorCert && r.Selector != SelectorSPKI {
			continue
		}
		switch r.MatchingType {
		case MatchFull, MatchSHA256, MatchSHA512:
			out = append(out, r)
		}
	}
	return out
}

// ErrNoMatch means the server's certificate matched none of the TLSA records.
var ErrNoMatch = errors.New("dane: certificate matches no TLSA record")

// Verify authenticates a TLS connection against usable TLSA records.
//
// DANE-EE(3) matches the leaf certificate or key alone. Name checks and
// expiry are deliberately skipped (RFC 7672 §3.1.1): the DNS binding is the
// authentication, and operators publishing "3 1 1" records commonly use
// self-signed certificates with any name.
//
// DANE-TA(2) matches a certificate in the chain the server sent; the leaf
// must chain to it and carry one of the names (RFC 7672 §3.2.2): the MX host
// name, or the TLSA base domain when they differ.
func Verify(cs tls.ConnectionState, records []TLSA, names ...string) error {
	chain := cs.PeerCertificates
	if len(chain) == 0 {
		return errors.New("dane: server sent no certificate")
	}
	for _, r := range records {
		switch r.Usage {
		case UsageDANEEE:
			if matches(r, chain[0]) {
				return nil
			}
		case UsageDANETA:
			for i, c := range chain {
				if !matches(r, c) {
					continue
				}
				if verifyTA(chain, i, names) == nil {
					return nil
				}
			}
		}
	}
	return ErrNoMatch
}

// verifyTA checks that the leaf chains to chain[ta] and is valid for one of names.
func verifyTA(chain []*x509.Certificate, ta int, names []string) error {
	roots := x509.NewCertPool()
	roots.AddCert(chain[ta])
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	var lastErr error
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			continue
		}
		_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name})
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("dane: no name to check")
	}
	return lastErr
}

func matches(r TLSA, c *x509.Certificate) bool {
	var data []byte
	switch r.Selector {
	case SelectorCert:
		data = c.Raw
	case SelectorSPKI:
		data = c.RawSubjectPublicKeyInfo
	default:
		return false
	}
	switch r.MatchingType {
	case MatchFull:
		return bytes.Equal(data, r.Data)
	case MatchSHA256:
		sum := sha256.Sum256(data)
		return bytes.Equal(sum[:], r.Data)
	case MatchSHA512:
		sum := sha512.Sum512(data)
		return bytes.Equal(sum[:], r.Data)
	}
	return false
}
