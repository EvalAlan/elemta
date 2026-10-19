package tlsrpt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config controls report generation and delivery.
type Config struct {
	// OrganizationName and ContactInfo go into every report.
	OrganizationName string
	ContactInfo      string
	// Hostname names this submitter in report IDs and filenames.
	Hostname string
	// From is the envelope and header sender of emailed reports. It must be a
	// domain we DKIM-sign: RFC 8460 §5.3 requires signed reports, and
	// receivers discard unsigned ones.
	From string
	// StateFile persists counts across restarts. Empty keeps them in memory.
	StateFile string
}

// Enqueuer hands an emailed report to the local queue for delivery. id is
// stable for a given report, so a retry after a crash is idempotent.
type Enqueuer func(id, from string, to []string, subject string, content []byte) error

// txtResolver is the part of net.Resolver discovery needs.
type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Reporter counts sessions and sends the daily reports.
type Reporter struct {
	*Counter
	cfg      Config
	enqueue  Enqueuer
	resolver txtResolver
	http     *http.Client
	logger   *slog.Logger

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	// retries tracks failed sends per domain-day. A failed send waits
	// retryDelay before the next try, and after maxAttempts the report is
	// dropped rather than retried forever.
	retries map[string]retry
}

type retry struct {
	attempts int
	next     time.Time
}

const (
	flushInterval = time.Minute
	maxAttempts   = 6
	retryDelay    = time.Hour
)

// NewReporter returns a reporter, loading any saved counts from cfg.StateFile.
func NewReporter(cfg Config, enqueue Enqueuer, logger *slog.Logger) (*Reporter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.From == "" {
		return nil, errors.New("tls reporting needs a report sender address (report_from)")
	}
	if cfg.OrganizationName == "" {
		cfg.OrganizationName = cfg.Hostname
	}
	if cfg.ContactInfo == "" {
		cfg.ContactInfo = cfg.From
	}
	r := &Reporter{
		Counter:  NewCounter(),
		cfg:      cfg,
		enqueue:  enqueue,
		resolver: net.DefaultResolver,
		http: &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     reportTransport(net.DefaultResolver)},
		logger:  logger.With("component", "tls-rpt"),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		retries: make(map[string]retry),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// Start runs the flush/send loop until Stop.
func (r *Reporter) Start() {
	go func() {
		defer close(r.done)
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		r.SendDue(context.Background())
		for {
			select {
			case <-r.stop:
				if err := r.save(); err != nil {
					r.logger.Warn("Failed to save TLS report counts", "error", err)
				}
				return
			case <-t.C:
				r.SendDue(context.Background())
				if err := r.save(); err != nil {
					r.logger.Warn("Failed to save TLS report counts", "error", err)
				}
			}
		}
	}()
}

// Stop ends the loop and saves the counts.
func (r *Reporter) Stop() {
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

// SendDue sends a report for every domain with counts from a finished day.
func (r *Reporter) SendDue(ctx context.Context) {
	for _, day := range r.completedDays() {
		for _, domain := range r.domainsFor(day) {
			key := day + "/" + domain
			rt := r.retries[key]
			if r.now().Before(rt.next) {
				continue
			}
			dc := r.take(day, domain)
			if dc == nil {
				continue
			}
			err := r.send(ctx, day, domain, dc)
			if err == nil {
				delete(r.retries, key)
				continue
			}
			rt.attempts++
			if rt.attempts >= maxAttempts {
				r.logger.Warn("Giving up on TLS report", "domain", domain, "day", day, "error", err)
				delete(r.retries, key)
				continue
			}
			rt.next = r.now().Add(retryDelay)
			r.retries[key] = rt
			r.logger.Info("TLS report not sent; will retry", "domain", domain, "day", day, "error", err)
			r.restore(day, domain, dc)
		}
	}
}

// errNoPolicy means the domain does not ask for reports, which is the normal
// case and not an error worth retrying.
var errNoPolicy = errors.New("no TLSRPT record")

func (r *Reporter) send(ctx context.Context, day, domain string, dc *dayCounts) error {
	rua, err := r.discover(ctx, domain)
	if errors.Is(err, errNoPolicy) {
		return nil
	}
	if err != nil {
		return err
	}
	report, err := buildReport(day, domain, dc, r.cfg.OrganizationName, r.cfg.ContactInfo, r.cfg.Hostname)
	if err != nil {
		return err
	}
	gz, err := gzipJSON(report)
	if err != nil {
		return err
	}

	// Every rua destination gets the report; any one succeeding is enough to
	// call it sent, because re-sending would duplicate it at the others.
	var mailto []string
	var errs []error
	sent := false
	for _, u := range rua {
		switch {
		case strings.HasPrefix(u, "mailto:"):
			mailto = append(mailto, strings.TrimPrefix(u, "mailto:"))
		case strings.HasPrefix(u, "https://"):
			if err := r.post(ctx, u, gz); err != nil {
				errs = append(errs, err)
			} else {
				sent = true
			}
		}
	}
	if len(mailto) > 0 && r.enqueue != nil {
		subject := fmt.Sprintf("Report Domain: %s Submitter: %s Report-ID: <%s>", domain, r.cfg.Hostname, report.ReportID)
		msg := buildEmail(report, gz, domain, r.cfg.From, mailto)
		id := "tlsrpt-" + strings.NewReplacer("@", "-", ".", "-", "_", "-").Replace(report.ReportID)
		if err := r.enqueue(id, r.cfg.From, mailto, subject, msg); err != nil {
			errs = append(errs, fmt.Errorf("enqueue: %w", err))
		} else {
			sent = true
		}
	}
	if sent || len(errs) == 0 {
		r.logger.Info("TLS report sent", "domain", domain, "day", day, "destinations", len(rua))
		return nil
	}
	return errors.Join(errs...)
}

// discover reads _smtp._tls.<domain> (RFC 8460 §3).
func (r *Reporter) discover(ctx context.Context, domain string) ([]string, error) {
	txts, err := r.resolver.LookupTXT(ctx, "_smtp._tls."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, errNoPolicy
		}
		return nil, err
	}
	var found []string
	records := 0
	for _, txt := range txts {
		rua, ok := parseRecord(txt)
		if !ok {
			continue
		}
		records++
		found = rua
	}
	// More than one valid record is a misconfiguration; RFC 8460 says to
	// treat it as no record.
	if records != 1 || len(found) == 0 {
		return nil, errNoPolicy
	}
	return found, nil
}

// parseRecord parses "v=TLSRPTv1; rua=mailto:a@b,https://c/d".
func parseRecord(txt string) ([]string, bool) {
	fields := strings.Split(txt, ";")
	if len(fields) == 0 || strings.TrimSpace(fields[0]) != "v=TLSRPTv1" {
		return nil, false
	}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(f), "=")
		if !ok || strings.TrimSpace(k) != "rua" {
			continue
		}
		var out []string
		for _, u := range strings.Split(v, ",") {
			u = strings.TrimSpace(u)
			lower := strings.ToLower(u)
			switch {
			case strings.HasPrefix(lower, "mailto:"):
				addr, err := url.PathUnescape(u[len("mailto:"):])
				if err == nil && strings.Contains(addr, "@") && !strings.ContainsAny(addr, "\r\n<>") {
					out = append(out, "mailto:"+addr)
				}
			case strings.HasPrefix(lower, "https://"):
				if _, err := url.Parse(u); err == nil {
					out = append(out, u)
				}
			}
		}
		return out, true
	}
	return nil, false
}

// post delivers a report over HTTPS (RFC 8460 §5.4).
func (r *Reporter) post(ctx context.Context, endpoint string, gz []byte) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("TLS report endpoint must be HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(gz))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/tlsrpt+gzip")
	// #nosec G107 -- the endpoint is the report URI the receiving domain
	// published for exactly this purpose, restricted to https:// by parseRecord.
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: %s", endpoint, resp.Status)
	}
	return nil
}

// state is the on-disk form of the counter.
type state struct {
	Days map[string]map[string]*dayCounts `json:"days"`
}

func (r *Reporter) save() error {
	if r.cfg.StateFile == "" {
		return nil
	}
	r.mu.Lock()
	data, err := json.Marshal(state{Days: r.days})
	r.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := r.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.cfg.StateFile)
}

func (r *Reporter) load() error {
	if r.cfg.StateFile == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(r.cfg.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read TLS report state: %w", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		// A corrupt state file costs a day of counts, not the server.
		r.logger.Warn("Ignoring unreadable TLS report state", "file", r.cfg.StateFile, "error", err)
		return nil
	}
	if st.Days != nil {
		r.days = st.Days
	}
	return nil
}
