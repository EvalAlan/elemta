package tlsrpt

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type reportIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

var reportReserved = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func reportDestinationIPs(ctx context.Context, resolver reportIPResolver, host string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if parsed, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, parsed.Unmap())
	} else {
		resolved, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, value := range resolved {
			address, ok := netip.AddrFromSlice(value.IP)
			if !ok {
				return nil, errors.New("TLS report destination has an invalid address")
			}
			addresses = append(addresses, address.Unmap())
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("TLS report destination has no addresses")
	}
	for _, address := range addresses {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return nil, errors.New("TLS report destination resolves to a nonpublic address")
		}
		for _, prefix := range reportReserved {
			if prefix.Contains(address) {
				return nil, errors.New("TLS report destination resolves to a reserved address")
			}
		}
	}
	return addresses, nil
}

func reportTransport(resolver reportIPResolver) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := reportDestinationIPs(ctx, resolver, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range addresses {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
	}
}
