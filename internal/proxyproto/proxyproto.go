// Package proxyproto accepts the PROXY protocol (v1 and v2) from trusted
// load balancers, so a server behind one still sees each client's own
// address.
//
// Running the MTA or the mailbox service more than once puts a TCP load
// balancer in front of them (HAProxy in Compose, a Service or ingress in
// Kubernetes). Without the PROXY protocol every connection would appear to
// come from the balancer: spam and blocklist checks, rate limits, relay
// decisions, sign-in throttling and logs would all see one address.
//
// Only the addresses listed as trusted may send a header, and they must;
// a connection from anywhere else is taken as it is, and a header it sends
// is not read, so a client can't claim someone else's address.
package proxyproto

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	pp "github.com/pires/go-proxyproto"
)

// headerTimeout bounds how long a trusted connection may take to send its
// header. Balancers send it at once.
const headerTimeout = 5 * time.Second

// Wrap returns ln, accepting the PROXY protocol from the trusted addresses
// or networks (192.0.2.10, 10.0.0.0/8, 2001:db8::/32). With none, ln is
// returned as it is.
//
// A trusted connection is handed on only once its header has been read:
// SMTP, IMAP and POP3 servers speak first, so a header checked lazily, on
// the first read, would come after the greeting. Headers are read in their
// own goroutines, so one slow connection doesn't hold up the others.
func Wrap(ln net.Listener, trusted []string) (net.Listener, error) {
	nets, err := ParseTrusted(trusted)
	if err != nil || len(nets) == 0 {
		return ln, err
	}
	l := &listener{Listener: ln, nets: nets, ready: make(chan net.Conn), done: make(chan struct{})}
	go l.accept()
	return l, nil
}

type listener struct {
	net.Listener
	nets  []*net.IPNet
	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	err   error
}

func (l *listener) accept() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.mu.Lock()
			l.err = err
			l.mu.Unlock()
			l.once.Do(func() { close(l.done) })
			return
		}
		if !trustedAddr(c.RemoteAddr(), l.nets) {
			l.deliver(c)
			continue
		}
		go func() {
			pc := pp.NewConn(c, pp.WithPolicy(pp.REQUIRE), pp.SetReadHeaderTimeout(headerTimeout))
			if pc.ProxyHeader() == nil {
				_ = c.Close() // a balancer that sent no header
				return
			}
			l.deliver(pc)
		}()
	}
}

func (l *listener) deliver(c net.Conn) {
	select {
	case l.ready <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err == nil {
			return nil, net.ErrClosed
		}
		return nil, l.err
	}
}

func (l *listener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.done) })
	return err
}

// ParseTrusted reads the trusted list: addresses or CIDR networks.
func ParseTrusted(trusted []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.Contains(t, "/") {
			ip := net.ParseIP(t)
			if ip == nil {
				return nil, fmt.Errorf("proxy protocol: %q is not an address or network", t)
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return nil, fmt.Errorf("proxy protocol: %q is not an address or network", t)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func trustedAddr(a net.Addr, nets []*net.IPNet) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, n := range nets {
		if n.Contains(tcp.IP) {
			return true
		}
	}
	return false
}
