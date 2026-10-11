package dmarcrpt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Config controls report generation and delivery.
type Config struct {
	// OrganizationName and ContactEmail go into every report.
	OrganizationName string
	ContactEmail     string
	// Hostname names this receiver in report IDs and filenames.
	Hostname string
	// From is the envelope and header sender of reports. Receivers of
	// reports commonly drop unauthenticated ones, so it should be in a
	// domain this server DKIM-signs.
	From string
	// StateFile persists counts across restarts. Empty keeps them in memory.
	StateFile string
}

// Enqueuer hands a report to the local queue for delivery. id is stable for
// a given report, so a retry after a crash is idempotent.
type Enqueuer func(id, from string, to []string, subject string, content []byte) error

// txtResolver is the part of net.Resolver destination verification needs.
type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Reporter counts evaluations and sends the daily reports.
type Reporter struct {
	*Counter
	cfg      Config
	enqueue  Enqueuer
	resolver txtResolver
	logger   *slog.Logger

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	// retries tracks failed sends per domain-day, so a failure waits
	// retryDelay and gives up after maxAttempts instead of retrying forever.
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
		return nil, errors.New("dmarc reporting needs a report sender address (report_from)")
	}
	if cfg.OrganizationName == "" {
		cfg.OrganizationName = cfg.Hostname
	}
	if cfg.ContactEmail == "" {
		cfg.ContactEmail = cfg.From
	}
	r := &Reporter{
		Counter:  NewCounter(),
		cfg:      cfg,
		enqueue:  enqueue,
		resolver: net.DefaultResolver,
		logger:   logger.With("component", "dmarc-reports"),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		retries:  make(map[string]retry),
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
					r.logger.Warn("Failed to save DMARC report counts", "error", err)
				}
				return
			case <-t.C:
				r.SendDue(context.Background())
				if err := r.save(); err != nil {
					r.logger.Warn("Failed to save DMARC report counts", "error", err)
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
	if n := r.takeDroppedDomains(); n > 0 {
		r.logger.Warn("DMARC evaluations not counted: too many policy domains in one day",
			"dropped", n, "limit", maxDomains)
	}
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
				r.logger.Warn("Giving up on DMARC report", "domain", domain, "day", day, "error", err)
				delete(r.retries, key)
				continue
			}
			rt.next = r.now().Add(retryDelay)
			r.retries[key] = rt
			r.logger.Info("DMARC report not sent; will retry", "domain", domain, "day", day, "error", err)
			r.restore(day, domain, dc)
		}
	}
}

func (r *Reporter) send(ctx context.Context, day, domain string, dc *dayCounts) error {
	report, err := buildReport(day, domain, dc, r.cfg.OrganizationName, r.cfg.ContactEmail, r.cfg.Hostname)
	if err != nil {
		return err
	}
	gz, err := gzipXML(report)
	if err != nil {
		return err
	}

	var dests []destination
	var errs []error
	for _, d := range parseRUA(dc.Policy.RUA) {
		ok, err := r.authorized(ctx, domain, d.Domain)
		switch {
		case err != nil:
			errs = append(errs, err)
		case !ok:
			r.logger.Info("DMARC report destination has not authorised reports for this domain",
				"domain", domain, "destination", d.Domain)
		default:
			dests = append(dests, d)
		}
	}
	if len(dests) == 0 {
		// A lookup that failed is worth retrying; a destination that refused
		// is not.
		return errors.Join(errs...)
	}

	// The size limit applies to what each destination receives. The message
	// names every recipient, so check each address against the message it
	// would get, dropping those that are too small and rebuilding.
	var to []string
	for _, d := range dests {
		to = append(to, d.Addr)
	}
	msg := buildEmail(report, gz, r.cfg.Hostname, r.cfg.From, to)
	var fits []string
	for _, d := range dests {
		if d.Limit > 0 && int64(len(msg)) > d.Limit {
			r.logger.Info("DMARC report exceeds the destination's size limit; not sent there",
				"domain", domain, "destination", d.Addr, "size", len(msg), "limit", d.Limit)
			continue
		}
		fits = append(fits, d.Addr)
	}
	if len(fits) == 0 {
		return errors.Join(errs...)
	}
	if len(fits) != len(to) {
		msg = buildEmail(report, gz, r.cfg.Hostname, r.cfg.From, fits)
	}
	if r.enqueue == nil {
		return nil
	}
	id := "dmarcrpt-" + strings.NewReplacer("@", "-", ".", "-", "_", "-").Replace(report.ReportMetadata.ReportID)
	if err := r.enqueue(id, r.cfg.From, fits, reportSubject(report, r.cfg.Hostname), msg); err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	// A destination whose verification lookup failed misses this report; the
	// others have it, and re-sending would duplicate it for them.
	r.logger.Info("DMARC report sent", "domain", domain, "day", day,
		"records", len(report.Records), "destinations", len(fits), "skipped_errors", len(errs))
	return nil
}

// authorized applies RFC 7489 §7.1: a destination outside the policy
// domain's organisational domain must publish
// <policy-domain>._report._dmarc.<destination-domain> before it is sent
// reports. Otherwise anyone could publish a rua pointing at a victim and
// have receivers mail them daily.
func (r *Reporter) authorized(ctx context.Context, policyDomain, destDomain string) (bool, error) {
	if orgDomain(policyDomain) == orgDomain(destDomain) {
		return true, nil
	}
	name := policyDomain + "._report._dmarc." + destDomain
	txts, err := r.resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, fmt.Errorf("verify report destination %s: %w", name, err)
	}
	for _, txt := range txts {
		v, _, _ := strings.Cut(txt, ";")
		if strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(v), " ", ""), "v=DMARC1") {
			return true, nil
		}
	}
	return false, nil
}

func orgDomain(d string) string {
	d = normDomain(d)
	if org, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return org
	}
	return d
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
		return fmt.Errorf("read DMARC report state: %w", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		// A corrupt state file costs a day of counts, not the server.
		r.logger.Warn("Ignoring unreadable DMARC report state", "file", r.cfg.StateFile, "error", err)
		return nil
	}
	if st.Days != nil {
		for _, domains := range st.Days {
			for domain, dc := range domains {
				switch {
				case dc == nil:
					delete(domains, domain)
				case dc.Rows == nil:
					dc.Rows = make(map[string]*row)
				}
			}
		}
		r.days = st.Days
	}
	return nil
}
