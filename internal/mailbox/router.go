package mailbox

// The cell router: one front door for mailboxes split across cells
// (cells.go explains cells).
//
// It listens where a mailbox service would (IMAP, IMAPS, POP3, ManageSieve,
// LMTP, HTTP), so nothing in front of it changes. A connection is held
// here until the client signs in; the router then finds the cell holding
// that mailbox, connects to one of the cell's mailbox servers, signs in
// there with the same credentials, and from then on only copies bytes both
// ways. The cell's server checks the password, applies its policy and
// sign-in limits, and does all the work, so the router keeps no state and
// any number of routers can run side by side.
//
// Toward the cells the router is a load balancer: it sends a PROXY
// protocol header with the client's own address first (list the routers
// in each cell's proxy_protocol_from), so a cell's sign-in limits, alerts
// and logs see the client, not the router, and it talks TLS to the cell's
// public listeners, so passwords never cross the network in the clear.
//
// LMTP is split by recipient instead: each recipient goes to its own cell,
// and their answers come back in order (router_lmtp.go). The HTTP APIs go
// by the account the request is for, and settings that every cell holds
// go to every cell (router_http.go).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/EvalAlan/elemta/internal/proxyproto"
	"github.com/EvalAlan/elemta/internal/tlssni"
	pp "github.com/pires/go-proxyproto"
)

// RouterConfig is the router's configuration file.
type RouterConfig struct {
	Router RouterServerConfig `toml:"router"`
	// Auth is the directory, read for placement (elemtaMailboxCell). The
	// router never checks a password itself.
	Auth  AuthConfig   `toml:"auth"`
	Cells []CellConfig `toml:"cell"`
}

// RouterServerConfig is where the router listens.
type RouterServerConfig struct {
	// IMAPListen is for internal clients (the webmail): plaintext
	// sign-in is allowed from internal_networks only.
	IMAPListen         string `toml:"imap_listen"`
	IMAPStartTLSListen string `toml:"imap_starttls_listen"`
	IMAPSListen        string `toml:"imaps_listen"`
	POP3Listen         string `toml:"pop3_listen"`
	SieveListen        string `toml:"sieve_listen"`
	LMTPListen         string `toml:"lmtp_listen"`
	HTTPListen         string `toml:"http_listen"`
	TLSCert            string `toml:"tls_cert"`
	TLSKey             string `toml:"tls_key"`
	TLSSNIDir          string `toml:"tls_sni_dir"`
	// ProxyProtocolFrom are the load balancers in front of the router's
	// public listeners (as a mailbox server's).
	ProxyProtocolFrom []string `toml:"proxy_protocol_from"`
	// InternalNetworks may use LMTP and HTTP, and sign in without TLS on
	// imap_listen and ManageSieve.
	InternalNetworks []string `toml:"internal_networks"`
	// DefaultCell holds every mailbox without a placement.
	DefaultCell string `toml:"default_cell"`
	// MaxConnections bounds client connections held at once.
	MaxConnections int `toml:"max_connections"`
	// MaxMessageMB bounds a message relayed over LMTP.
	MaxMessageMB int `toml:"max_message_mb"`
}

// CellConfig is one cell's mailbox servers, as the router reaches them:
// usually a Service in front of the cell's servers.
type CellConfig struct {
	Name string `toml:"name"`
	// IMAPS is the cell's implicit-TLS IMAP listener (imaps_listen).
	IMAPS string `toml:"imaps"`
	// POP3 and Sieve are its STARTTLS listeners.
	POP3  string `toml:"pop3"`
	Sieve string `toml:"sieve"`
	LMTP  string `toml:"lmtp"`
	// HTTP is the base URL of its HTTP APIs (http_listen).
	HTTP string `toml:"http"`
	// TLS toward the cell: the name its certificate carries, and a CA to
	// trust beyond the system's. Skipping verification is for development
	// only, and logged.
	TLSServerName         string `toml:"tls_server_name"`
	TLSCAFile             string `toml:"tls_ca_file"`
	TLSInsecureSkipVerify bool   `toml:"tls_insecure_skip_verify"`
}

// LoadRouterConfig reads and checks a router configuration file.
func LoadRouterConfig(path string) (RouterConfig, error) {
	var c RouterConfig
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return c, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return c, fmt.Errorf("unknown router setting %s", undecoded[0])
	}
	c = c.WithDefaults()
	return c, c.Validate()
}

func (c RouterConfig) WithDefaults() RouterConfig {
	if c.Router.MaxConnections == 0 {
		c.Router.MaxConnections = 10000
	}
	if c.Router.MaxMessageMB == 0 {
		c.Router.MaxMessageMB = 50
	}
	if c.Auth.CacheSeconds == 0 {
		c.Auth.CacheSeconds = 30
	}
	if c.Auth.BindDNEnv == "" {
		c.Auth.BindDNEnv = "ELEMTA_LDAP_BIND_DN"
	}
	if c.Auth.BindPasswordEnv == "" {
		c.Auth.BindPasswordEnv = "ELEMTA_LDAP_BIND_PASSWORD"
	}
	if c.Router.DefaultCell == "" && len(c.Cells) > 0 {
		c.Router.DefaultCell = c.Cells[0].Name
	}
	return c
}

func (c RouterConfig) Validate() error {
	if len(c.Cells) == 0 {
		return errors.New("router: no cells configured")
	}
	seen := map[string]bool{}
	for _, cell := range c.Cells {
		if cell.Name == "" || seen[cell.Name] {
			return fmt.Errorf("router: cell names must be set and different (%q)", cell.Name)
		}
		seen[cell.Name] = true
	}
	if !seen[c.Router.DefaultCell] {
		return fmt.Errorf("router: default_cell %q is not a configured cell", c.Router.DefaultCell)
	}
	if c.Auth.LDAPURL == "" || c.Auth.LDAPBase == "" {
		return errors.New("router: [auth] ldap_url and ldap_base are needed to find each mailbox's cell")
	}
	if _, err := proxyproto.ParseTrusted(c.Router.ProxyProtocolFrom); err != nil {
		return err
	}
	if _, err := proxyproto.ParseTrusted(c.Router.InternalNetworks); err != nil {
		return err
	}
	if (c.Router.IMAPSListen != "" || c.Router.IMAPStartTLSListen != "") && c.Router.TLSCert == "" {
		return errors.New("router: imaps_listen and imap_starttls_listen need tls_cert and tls_key")
	}
	return nil
}

// placer finds a mailbox's cell; LDAPAuth is one.
type placer interface {
	CellOf(ctx context.Context, address string) (string, error)
}

// Router is a running cell router.
type Router struct {
	cfg      RouterConfig
	log      *slog.Logger
	place    placer
	cells    map[string]*routerCell
	tls      *tls.Config
	internal []*net.IPNet
	slots    chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	// dialTimeout bounds connecting to a cell; tests shorten it.
	dialTimeout time.Duration
}

type routerCell struct {
	CellConfig
	tls *tls.Config
}

// NewRouter prepares a router; Run starts it.
func NewRouter(c RouterConfig, log *slog.Logger) (*Router, error) {
	c = c.WithDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return newRouter(c, NewLDAPAuth(c.Auth), log)
}

func newRouter(c RouterConfig, place placer, log *slog.Logger) (*Router, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &Router{cfg: c, log: log, place: place, cells: map[string]*routerCell{}, slots: make(chan struct{}, c.Router.MaxConnections), dialTimeout: 5 * time.Second}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	internal, _ := proxyproto.ParseTrusted(c.Router.InternalNetworks)
	r.internal = internal
	for _, cell := range c.Cells {
		rc := &routerCell{CellConfig: cell, tls: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cell.TLSServerName}}
		if cell.TLSCAFile != "" {
			pem, err := os.ReadFile(cell.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("router: cell %s: %w", cell.Name, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("router: cell %s: no certificates in %s", cell.Name, cell.TLSCAFile)
			}
			rc.tls.RootCAs = pool
		}
		if cell.TLSInsecureSkipVerify {
			log.Warn("router: not verifying the certificate of a cell's mailbox servers; for development only", "cell", cell.Name)
			rc.tls.InsecureSkipVerify = true // #nosec G402 -- opt-in for development, logged above
		}
		r.cells[cell.Name] = rc
	}
	if c.Router.TLSCert != "" {
		certs, err := newCertReloader(c.Router.TLSCert, c.Router.TLSKey)
		if err != nil {
			return nil, err
		}
		getCert := certs.GetCertificate
		if c.Router.TLSSNIDir != "" {
			getCert = tlssni.New(c.Router.TLSSNIDir, func(format string, args ...any) { log.Info(fmt.Sprintf(format, args...)) }).Wrap(getCert)
		}
		r.tls = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: getCert, CipherSuites: tls12Suites}
	}
	return r, nil
}

// cellFor finds the cell of address.
func (r *Router) cellFor(ctx context.Context, address string) (*routerCell, error) {
	name, err := r.place.CellOf(ctx, address)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = r.cfg.Router.DefaultCell
	}
	cell := r.cells[name]
	if cell == nil {
		r.log.Error("router: a mailbox is placed in a cell this router doesn't know", "address", address, "cell", name)
		return nil, errNoCell
	}
	return cell, nil
}

// isInternal says whether a client's address is on an internal network.
func (r *Router) isInternal(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, n := range r.internal {
		if n.Contains(tcp.IP) {
			return true
		}
	}
	return false
}

// dialCell connects to a cell's listener at addr, sending client's address
// in a PROXY protocol header first. implicitTLS wraps it in TLS at once.
func (r *Router) dialCell(ctx context.Context, cell *routerCell, addr string, client net.Conn, implicitTLS bool) (net.Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("cell %s has no listener for this protocol", cell.Name)
	}
	d := net.Dialer{Timeout: r.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if _, err := pp.HeaderProxyFromAddrs(2, client.RemoteAddr(), client.LocalAddr()).WriteTo(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !implicitTLS {
		return conn, nil
	}
	return r.startTLS(ctx, cell, conn)
}

func (r *Router) startTLS(ctx context.Context, cell *routerCell, conn net.Conn) (net.Conn, error) {
	cfg := cell.tls.Clone()
	if cfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		cfg.ServerName = host
	}
	t := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	defer cancel()
	if err := t.HandshakeContext(hctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return t, nil
}

// Run serves until ctx ends.
func (r *Router) Run(ctx context.Context) error {
	cfg := r.cfg.Router
	type endpoint struct {
		addr   string
		public bool
		serve  func(net.Conn)
		tls    bool
	}
	endpoints := []endpoint{
		{cfg.IMAPListen, false, func(c net.Conn) { r.serveIMAP(c, false) }, false},
		{cfg.IMAPStartTLSListen, true, func(c net.Conn) { r.serveIMAP(c, true) }, false},
		{cfg.IMAPSListen, true, func(c net.Conn) { r.serveIMAP(c, true) }, true},
		{cfg.POP3Listen, true, r.servePOP3, false},
		{cfg.SieveListen, true, r.serveSieve, false},
	}
	var listeners []net.Listener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	errs := make(chan error, len(endpoints)+2)
	for _, e := range endpoints {
		if e.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", e.addr)
		if err != nil {
			closeAll()
			return err
		}
		if e.public {
			if ln, err = proxyproto.Wrap(ln, cfg.ProxyProtocolFrom); err != nil {
				closeAll()
				return err
			}
		}
		if e.tls {
			if r.tls == nil {
				closeAll()
				return errors.New("router: imaps_listen needs tls_cert")
			}
			ln = tls.NewListener(ln, r.tls)
		}
		listeners = append(listeners, ln)
		go func(ln net.Listener, serve func(net.Conn)) { errs <- r.accept(ln, serve) }(ln, e.serve)
	}
	if cfg.LMTPListen != "" {
		ln, err := net.Listen("tcp", cfg.LMTPListen)
		if err != nil {
			closeAll()
			return err
		}
		listeners = append(listeners, ln)
		lmtp := r.lmtpServer()
		go func() { errs <- lmtp.Serve(&internalOnly{Listener: ln, r: r}) }()
		defer func() { _ = lmtp.Close() }()
	}
	if cfg.HTTPListen != "" {
		ln, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			closeAll()
			return err
		}
		listeners = append(listeners, ln)
		srv := r.httpServer()
		go func() { errs <- srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()
	}
	r.log.Info("mailbox router listening", "cells", len(r.cells), "default_cell", cfg.DefaultCell)
	select {
	case <-ctx.Done():
		r.cancel()
		closeAll()
		return nil
	case err := <-errs:
		r.cancel()
		closeAll()
		return err
	}
}

func (r *Router) accept(ln net.Listener, serve func(net.Conn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case r.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-r.slots }()
			serve(c)
		}()
	}
}

// internalOnly refuses LMTP from outside internal_networks.
type internalOnly struct {
	net.Listener
	r *Router
}

func (l *internalOnly) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.r.isInternal(c.RemoteAddr()) {
			return c, nil
		}
		_ = c.Close()
	}
}
