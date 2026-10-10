package dane

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ErrBogus means the validating resolver could not produce an answer: a
// DNSSEC validation failure, or a server failure that cannot be told apart
// from one. RFC 7672 §2.2 says delivery must wait rather than continue
// without DANE, because "the attacker made the lookup fail" is exactly the
// downgrade DANE exists to stop.
var ErrBogus = errors.New("dane: DNSSEC lookup failed")

// Resolver answers the two questions DANE needs.
type Resolver interface {
	// MXSecure reports whether domain's MX RRset is DNSSEC-signed. DANE applies
	// to an MX host only if the MX lookup that named it was secure; otherwise
	// an attacker could have substituted a host of their own.
	MXSecure(ctx context.Context, domain string) (bool, error)
	// LookupTLSA returns the TLSA records for host:port and whether they were
	// DNSSEC-validated. Insecure answers carry no records.
	LookupTLSA(ctx context.Context, host string, port int) ([]TLSA, bool, error)
}

// DNSResolver queries a validating resolver and trusts its AD bit.
type DNSResolver struct {
	// Server is host:port of the validating resolver, normally loopback.
	Server  string
	Timeout time.Duration
	client  *dns.Client
}

// NewDNSResolver returns a resolver that sends queries to server.
func NewDNSResolver(server string) *DNSResolver {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &DNSResolver{Server: server, Timeout: 5 * time.Second, client: &dns.Client{Timeout: 5 * time.Second}}
}

// query asks for name/qtype with the DO bit and returns the response when it
// is authenticated (AD set). An unauthenticated answer returns (nil, nil).
func (r *DNSResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true
	in, _, err := r.client.ExchangeContext(ctx, m, r.Server)
	if err == nil && in != nil && in.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: r.client.Timeout}
		in, _, err = tcp.ExchangeContext(ctx, m, r.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s: %v", ErrBogus, name, dns.TypeToString[qtype], err)
	}
	switch in.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("%w: %s %s: %s", ErrBogus, name, dns.TypeToString[qtype], dns.RcodeToString[in.Rcode])
	}
	if !in.AuthenticatedData {
		return nil, nil
	}
	return in, nil
}

// MXSecure implements Resolver.
func (r *DNSResolver) MXSecure(ctx context.Context, domain string) (bool, error) {
	in, err := r.query(ctx, domain, dns.TypeMX)
	if err != nil {
		return false, err
	}
	return in != nil, nil
}

// LookupTLSA implements Resolver.
func (r *DNSResolver) LookupTLSA(ctx context.Context, host string, port int) ([]TLSA, bool, error) {
	name := "_" + strconv.Itoa(port) + "._tcp." + strings.TrimSuffix(host, ".")
	in, err := r.query(ctx, name, dns.TypeTLSA)
	if err != nil || in == nil {
		return nil, false, err
	}
	var out []TLSA
	for _, rr := range in.Answer {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		data, err := hex.DecodeString(t.Certificate)
		if err != nil {
			continue
		}
		out = append(out, TLSA{Usage: t.Usage, Selector: t.Selector, MatchingType: t.MatchingType, Data: data})
	}
	return out, true, nil
}
