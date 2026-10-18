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
	lmtp         *smtp.Server
	sieve        sieveCache
	tlsConfig    *tls.Config
	http         *http.Server
	ctx          context.Context
	cancel       context.CancelFunc
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
	s := &Service{receiveSlots: make(chan struct{}, c.Limits.MaxConcurrentBodies), cfg: c, engine: e, auth: auth, log: log, ctx: ctx, cancel: cancel}
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
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapNamespace: {}, imap.CapUIDPlus: {}, imap.CapMove: {}, imap.CapIdle: {}, imap.CapListExtended: {}, imap.CapListStatus: {}, imap.CapSpecialUse: {}, imap.CapESearch: {}, imap.CapStatusSize: {}, imap.CapUnselect: {}}
	s.imap = imapserver.New(&imapserver.Options{Caps: caps, TLSConfig: tlsConfig, InsecureAuth: c.Server.AllowPlaintextAuth, NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		ctx, cancel := context.WithCancel(s.ctx)
		return &imapSession{service: s, ctx: ctx, cancel: cancel}, nil, nil
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
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
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
	errs := make(chan error, 5)
	var wg sync.WaitGroup
	start := func(fn func() error) { wg.Add(1); go func() { defer wg.Done(); errs <- fn() }() }
	start(func() error { return s.imap.Serve(&limitedListener{Listener: listeners[0], slots: slots}) })
	start(func() error { return s.lmtp.Serve(&limitedListener{Listener: listeners[1], slots: slots}) })
	start(func() error { return s.http.Serve(listeners[2]) })
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
	token      string
	from       string
}

func (l *lmtpSession) Reset()        { l.recipients = nil; l.addresses = nil; l.token = ""; l.from = "" }
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
	a, err := l.service.auth.Resolve(ctx, to)
	if errors.Is(err, ErrCredentials) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Unknown recipient"}
	}
	if err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Directory unavailable"}
	}
	if err = l.service.engine.EnsureAccount(ctx, a); err != nil {
		return &smtp.SMTPError{Code: 451, Message: "Mailbox unavailable"}
	}
	l.recipients = append(l.recipients, a)
	l.addresses = append(l.addresses, to)
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
	for i, a := range l.recipients {
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
