package mailbox

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/emersion/go-imap/v2"
	smtp "github.com/emersion/go-smtp"
)

type Service struct {
	receiveSlots chan struct{}
	cfg          Config
	engine       *Engine
	auth         Authenticator
	log          *slog.Logger
	imap         *imapserver.Server
	imapStartTLS *imapserver.Server
	// internalNets may use the account-security API (security_api.go).
	internalNets []*net.IPNet
	// adminToken guards the admin API (admin_api.go); empty turns it off.
	adminToken string
	lmtp       *smtp.Server
	sieve      sieveCache
	tlsConfig  *tls.Config
	http       *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
}

func Open(ctx context.Context, c Config, log *slog.Logger) (*Service, error) {
	c = c.WithDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if os.Getenv(c.Auth.BindDNEnv) == "" || os.Getenv(c.Auth.BindPasswordEnv) == "" {
		return nil, errors.New("mailbox LDAP service credentials are required")
	}
	db, err := sql.Open("postgres", os.Getenv(c.Metadata.DSNEnv))
	if err != nil {
		return nil, errors.New("invalid mailbox database configuration")
	}
	db.SetMaxOpenConns(c.Metadata.MaxConnections)
	db.SetMaxIdleConns(c.Metadata.MaxConnections / 2)
	db.SetConnMaxLifetime(30 * time.Minute)
	var bodies BodyStore
	switch c.Bodies.Driver {
	case "file":
		bodies, err = NewFileBodies(c.Bodies.Root)
	case "s3":
		bodies, err = NewS3Bodies(c.Bodies)
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	engine, err := NewEngine(ctx, db, bodies, c)
	if err != nil {
		_ = bodies.Close()
		_ = db.Close()
		return nil, fmt.Errorf("mailbox initialization: %w", err)
	}
	srv, err := newService(c, engine, LDAPAuth{Config: c.Auth}, log)
	if err != nil {
		_ = bodies.Close()
		_ = db.Close()
	}
	return srv, err
}
func newService(c Config, e *Engine, auth Authenticator, log *slog.Logger) (*Service, error) {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{receiveSlots: make(chan struct{}, c.Limits.MaxConcurrentBodies), cfg: c, engine: e, auth: auth, log: log, ctx: ctx, cancel: cancel, adminToken: os.Getenv(c.Admin.TokenEnv)}
	var tlsConfig *tls.Config
	if c.Server.TLSCert != "" {
		certs, err := newCertReloader(c.Server.TLSCert, c.Server.TLSKey)
		if err != nil {
			cancel()
			return nil, err
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}
	}
	s.tlsConfig = tlsConfig
	for _, cidr := range c.Server.LMTPAllowedNetworks {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			s.internalNets = append(s.internalNets, network)
		}
	}
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapNamespace: {}, imap.CapUIDPlus: {}, imap.CapMove: {}, imap.CapIdle: {}, imap.CapListExtended: {}, imap.CapListStatus: {}, imap.CapSpecialUse: {}, imap.CapESearch: {}, imap.CapStatusSize: {}, imap.CapUnselect: {}}
	// This server takes both the internal listener the webmail uses and
	// the implicit-TLS listener (993). Only the latter faces mail apps, and
	// it is the one whose connections are TLS from the first byte.
	s.imap = imapserver.New(&imapserver.Options{Caps: caps, TLSConfig: tlsConfig, InsecureAuth: c.Server.AllowPlaintextAuth, NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		_, public := conn.NetConn().(*tls.Conn)
		ctx, cancel := context.WithCancel(s.ctx)
		return &imapSession{service: s, ctx: ctx, cancel: cancel, public: public, conn: conn.NetConn()}, nil, nil
	}})
	s.imapStartTLS = imapserver.New(&imapserver.Options{Caps: caps, TLSConfig: tlsConfig, InsecureAuth: false, NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		ctx, cancel := context.WithCancel(s.ctx)
		return &imapSession{service: s, ctx: ctx, cancel: cancel, public: true, conn: conn.NetConn()}, nil, nil
	}})

	s.lmtp = smtp.NewServer(smtp.BackendFunc(func(conn *smtp.Conn) (smtp.Session, error) {
		host, _, err := net.SplitHostPort(conn.Conn().RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		allowed := false
		for _, cidr := range c.Server.LMTPAllowedNetworks {
			_, network, _ := net.ParseCIDR(cidr)
			if network != nil && network.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, &smtp.SMTPError{Code: 550, Message: "Untrusted delivery peer"}
		}
		return &lmtpSession{service: s, conn: conn}, nil
	}))
	s.lmtp.LMTP = true
	s.lmtp.Domain = "mailbox.elemta"
	s.lmtp.MaxMessageBytes = e.MaxBytes
	// RFC 5321 caps lines at 998 octets, but real mail breaks that (long
	// unwrapped HTML, careless senders) and the MTA has already accepted
	// it. Refusing it here would bounce mail permanently that other
	// mailbox servers deliver, so only the message size limit applies.
	s.lmtp.MaxLineLength = int(min(e.MaxBytes, 1<<30))
	s.lmtp.MaxRecipients = 100
	s.lmtp.ReadTimeout = time.Minute
	s.lmtp.WriteTimeout = time.Minute
	s.lmtp.TLSConfig = tlsConfig
	s.lmtp.EnableDSN = true
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.engine.Ready(ctx); err != nil {
			http.Error(w, "mailbox dependencies unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.securityAPI(mux)
	s.adminAPI(mux)
	// The write timeout allows for an admin purge of a large mailbox; the
	// other handlers bound their own work to a few seconds.
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second}
	return s, nil
}
func (s *Service) Run(ctx context.Context) error {
	var listeners []net.Listener
	for _, addr := range []string{s.cfg.Server.IMAPListen, s.cfg.Server.LMTPListen, s.cfg.Server.HTTPListen} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, old := range listeners {
				_ = old.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	slots := make(chan struct{}, s.cfg.Limits.MaxConnections)
	errs := make(chan error, 7)
	var wg sync.WaitGroup
	start := func(fn func() error) { wg.Add(1); go func() { defer wg.Done(); errs <- fn() }() }
	start(func() error { return s.imap.Serve(&limitedListener{Listener: listeners[0], slots: slots}) })
	start(func() error { return s.lmtp.Serve(&limitedListener{Listener: listeners[1], slots: slots}) })
	start(func() error { return s.http.Serve(listeners[2]) })
	for _, endpoint := range []struct {
		addr  string
		serve func(net.Listener) error
	}{
		{s.cfg.Server.IMAPStartTLSListen, s.imapStartTLS.Serve},
		{s.cfg.Server.POP3Listen, s.servePOP3},
	} {
		if endpoint.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", endpoint.addr)
		if err != nil {
			s.cancel()
			_ = s.imap.Close()
			_ = s.imapStartTLS.Close()
			_ = s.lmtp.Close()
			_ = s.http.Close()
			for _, l := range listeners {
				_ = l.Close()
			}
			wg.Wait()
			return err
		}
		listeners = append(listeners, ln)
		serve := endpoint.serve
		start(func() error { return serve(&limitedListener{Listener: ln, slots: slots}) })
	}

	if s.cfg.Server.IMAPSListen != "" && s.tlsConfig != nil {
		// Implicit TLS (port 993), which most clients default to. TLS wraps
		// the connection limiter, so the IMAP server sees a *tls.Conn and
		// knows the session is encrypted.
		ln, err := net.Listen("tcp", s.cfg.Server.IMAPSListen)
		if err != nil {
			s.cancel()
			for _, l := range listeners {
				_ = l.Close()
			}
			wg.Wait()
			return err
		}
		listeners = append(listeners, ln)
		start(func() error {
			return s.imap.Serve(tls.NewListener(&limitedListener{Listener: ln, slots: slots}, s.tlsConfig))
		})
	}
	if s.cfg.Sieve.Listen != "" {
		ln, err := net.Listen("tcp", s.cfg.Sieve.Listen)
		if err != nil {
			s.cancel()
			for _, l := range listeners {
				_ = l.Close()
			}
			wg.Wait()
			return err
		}
		listeners = append(listeners, ln)
		start(func() error { return s.serveManageSieve(&limitedListener{Listener: ln, slots: slots}, s.tlsConfig) })
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
				if _, err := s.collect(ctx); err != nil && ctx.Err() == nil {
					s.log.Warn("mailbox cleanup failed", "error", err)
				}
				_, _ = s.engine.DB.ExecContext(ctx, `DELETE FROM mailbox_auth_failures WHERE expires<now()`)
				if h := s.cfg.Maintenance.JournalRetentionHours; h > 0 {
					if _, err := s.engine.CompactChanges(ctx, time.Duration(h)*time.Hour); err != nil && ctx.Err() == nil {
						s.log.Warn("mailbox journal compaction failed", "error", err)
					}
				}
				// Every replica runs this; summaries are idempotent, so overlap
				// only costs a duplicate parse.
				if n := s.cfg.Maintenance.BackfillBatch; n > 0 {
					if done, err := s.engine.Backfill(ctx, n); err != nil && ctx.Err() == nil {
						s.log.Warn("mailbox summary backfill failed", "error", err)
					} else if done > 0 {
						s.log.Info("mailbox summaries backfilled", "count", done)
					}
				}
				cancel()
			}
		}
	}()
	s.log.Info("mailbox service listening", "imap", listeners[0].Addr(), "lmtp", listeners[1].Addr(), "health", listeners[2].Addr(), "bodies", s.cfg.Bodies.Driver)
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	s.cancel()
	_ = s.imap.Close()
	_ = s.imapStartTLS.Close()
	_ = s.lmtp.Close()
	_ = s.http.Close()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	wg.Wait()
	return err
}
func (s *Service) collect(ctx context.Context) (int, error) {
	if !s.cfg.Maintenance.GarbageCollection {
		return 0, nil
	}
	return s.engine.GC(ctx)
}
func (s *Service) Close() error {
	s.cancel()
	return errors.Join(s.engine.DB.Close(), s.engine.Bodies.Close())
}
func (s *Service) Engine() *Engine { return s.engine }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

func loginKey(user string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(user))))
	return hex.EncodeToString(sum[:])
}
func (s *Service) allowLogin(user string) (bool, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	var blocked bool
	err := s.engine.DB.QueryRowContext(ctx, `SELECT attempts>=20 AND expires>now() FROM mailbox_auth_failures WHERE key=$1`, loginKey(user)).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !blocked, nil
}
func (s *Service) failLogin(user string) {
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	_, _ = s.engine.DB.ExecContext(ctx, `INSERT INTO mailbox_auth_failures(key) VALUES($1) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN mailbox_auth_failures.expires<now() THEN 1 ELSE mailbox_auth_failures.attempts+1 END,expires=CASE WHEN mailbox_auth_failures.expires<now() THEN now()+interval '15 minutes' ELSE mailbox_auth_failures.expires END`, loginKey(user))
}

type lmtpSession struct {
	conn       *smtp.Conn
	service    *Service
	recipients []Account
	addresses  []string
	// lists holds, for each recipient, the list address it resolved to, or
	// "" for an account (routing.go).
	lists []string
	token string
	from  string
}

func (l *lmtpSession) Reset() {
	l.recipients, l.addresses, l.lists, l.token, l.from = nil, nil, nil, "", ""
}
func (l *lmtpSession) Logout() error { l.Reset(); return nil }
func (l *lmtpSession) Mail(from string, options *smtp.MailOptions) error {
	if !l.service.cfg.Server.AllowPlaintextAuth {
		if _, secure := l.conn.TLSConnectionState(); !secure {
			return &smtp.SMTPError{Code: 530, Message: "STARTTLS required"}
		}
	}
	l.Reset()
	l.token = options.EnvelopeID
	l.from = from
	return nil
}
func (l *lmtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	ctx, cancel := context.WithTimeout(l.service.ctx, 10*time.Second)
	defer cancel()
	r, err := l.service.resolveRecipient(ctx, to)
	if errors.Is(err, ErrCredentials) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Unknown recipient"}
	}
	if err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Directory unavailable"}
	}
	if r.list != "" {
		// Who may post is checked with the message (deliverList): the
		// MTA's recipient check asks with a null sender, so the real one
		// isn't known yet.
		l.recipients = append(l.recipients, Account{})
		l.addresses = append(l.addresses, to)
		l.lists = append(l.lists, r.list)
		return nil
	}
	a := r.account
	if err = l.service.applyPolicy(ctx, &a); err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Mailbox unavailable"}
	}
	if err = l.service.engine.EnsureAccount(ctx, a); err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Mailbox unavailable"}
	}
	l.recipients = append(l.recipients, a)
	l.addresses = append(l.addresses, to)
	l.lists = append(l.lists, "")
	return nil
}
func (l *lmtpSession) Data(_ io.Reader) error {
	return &smtp.SMTPError{Code: 451, Message: "LMTP delivery required"}
}
func (l *lmtpSession) LMTPData(r io.Reader, status smtp.StatusCollector) error {
	release, err := l.service.receiveSlot(l.service.ctx)
	if err != nil {
		return err
	}
	defer release()

	raw, err := readBounded(r, l.service.engine.MaxBytes)
	if errors.Is(err, ErrTooLarge) {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message exceeds limit"}
	}
	if err != nil {
		// A broken read is the connection's fault, not the message's.
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Message not received completely; try again"}
	}
	largestAttachment := int64(-1) // measured once, if a recipient limits it
	for i, a := range l.recipients {
		if l.lists[i] != "" {
			ctx, cancel := context.WithTimeout(l.service.ctx, 2*time.Minute)
			token := l.token
			if token != "" {
				digest := sha256.Sum256([]byte(token + "\x00" + strings.ToLower(l.addresses[i])))
				token = hex.EncodeToString(digest[:])
			}
			err := l.service.deliverList(ctx, l.lists[i], l.from, raw, token)
			cancel()
			status.SetStatus(l.addresses[i], lmtpResult(l.service, l.lists[i], err))
			continue
		}
		if refused := sizeRefusal(a.Policy, raw, &largestAttachment); refused != nil {
			status.SetStatus(l.addresses[i], refused)
			continue
		}
		ctx, cancel := context.WithTimeout(l.service.ctx, 45*time.Second)
		token := l.token
		if token != "" {
			digest := sha256.Sum256([]byte(token + "\x00" + strings.ToLower(l.addresses[i])))
			token = hex.EncodeToString(digest[:])
		}
		err := l.service.deliver(ctx, delivery{account: a, from: l.from, rcpt: l.addresses[i], raw: raw, token: token})
		cancel()
		var result error
		var smtpErr *smtp.SMTPError
		if errors.As(err, &smtpErr) {
			result = smtpErr // a Sieve reject, or a deliberate temporary failure
		} else if err != nil {
			result = &smtp.SMTPError{Code: 451, Message: "Delivery temporarily unavailable"}
			if errors.Is(err, ErrQuota) {
				result = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2}, Message: "Mailbox quota exceeded"}
			}
			l.service.log.Warn("mailbox delivery failed", "account", a.ID, "error", err)
		}
		status.SetStatus(l.addresses[i], result)
	}
	return nil
}

func (s *Service) receiveSlot(ctx context.Context) (func(), error) {
	select {
	case s.receiveSlots <- struct{}{}:
		return func() { <-s.receiveSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// applyPolicy works out the account's class of service and applies its
// quota, so a quota a class sets reaches EnsureAccount like one the
// directory holds.
func (s *Service) applyPolicy(ctx context.Context, a *Account) error {
	eff, err := s.engine.EffectivePolicy(ctx, a.Address, a.Quota)
	if err != nil {
		return err
	}
	a.Quota = eff.QuotaBytes
	a.Policy = &eff
	return nil
}

// sizeRefusal applies a recipient's class-of-service limits on the size of
// mail received. Each recipient gets their own answer, so one with a small
// limit doesn't bounce the message for the others.
func sizeRefusal(p *mailpolicy.Effective, raw []byte, largest *int64) error {
	if p == nil {
		return nil
	}
	if p.MaxMessageBytes > 0 && int64(len(raw)) > p.MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message is larger than this recipient accepts"}
	}
	if p.MaxAttachmentBytes > 0 {
		if *largest < 0 {
			*largest = mailpolicy.LargestAttachment(raw)
		}
		if *largest > p.MaxAttachmentBytes {
			return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "An attachment is larger than this recipient accepts"}
		}
	}
	return nil
}

// lmtpResult turns a delivery error into the recipient's LMTP status: a
// deliberate SMTP answer as is, anything else as a temporary failure.
func lmtpResult(s *Service, what string, err error) error {
	if err == nil {
		return nil
	}
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr
	}
	s.log.Warn("mailbox delivery failed", "recipient", what, "error", err)
	return &smtp.SMTPError{Code: 451, Message: "Delivery temporarily unavailable"}
}
