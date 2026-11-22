package mailbox

// Reading the DMARC aggregate reports mailed to hosted domains.
//
// Mail to a registered report address is copied to a bounded queue as it
// arrives, before lists, forwarding and filters, and is delivered exactly as
// it would be otherwise: the worker reading the queue can be slow, full or
// failing without delivery noticing. What it misses, a backfill reads from
// the mailbox later.
//
// A report is verified when the MTA confirmed who sent it, which proves the
// sender owns that domain and nothing about whether they are an honest
// reporter. So every count keeps the sender's domain beside it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/dmarcrpt"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

const (
	dmarcQueueItems = 64
	dmarcQueueBytes = 32 << 20
	// dmarcMessageMax is a full-sized attachment in base64, and its headers.
	dmarcMessageMax = dmarcrpt.MaxReportCompressed*3/2 + 1<<20
	// dmarcRefresh is how long another replica's change takes to be seen.
	dmarcRefresh      = 30 * time.Second
	dmarcBackfillTime = 30 * time.Minute
	dmarcDefaultDays  = 30
	dmarcMaxDays      = 400
)

type dmarcReport struct {
	domain   string // the registered one
	sender   string
	verified bool
	received time.Time
	feedback *dmarcrpt.Feedback
}

type dmarcMail struct {
	rcpt     string
	raw      []byte
	received time.Time
}

type dmarcIngest struct {
	engine *Engine
	log    *slog.Logger
	queue  chan dmarcMail
	parse  func([]byte, time.Time) (*dmarcrpt.Feedback, error)

	mu        sync.RWMutex
	addresses map[string][]string // address -> the domains reporting to it
	pending   int
}

func newDMARCIngest(e *Engine, log *slog.Logger) *dmarcIngest {
	return &dmarcIngest{engine: e, log: log, queue: make(chan dmarcMail, dmarcQueueItems),
		parse: dmarcrpt.ParseMessage, addresses: map[string][]string{}}
}

func (in *dmarcIngest) refresh(ctx context.Context) error {
	list, err := in.engine.DMARCAddresses(ctx)
	if err != nil {
		return err
	}
	m := map[string][]string{}
	for _, a := range list {
		m[a.Address] = append(m[a.Address], a.Domain)
	}
	in.mu.Lock()
	in.addresses = m
	in.mu.Unlock()
	return nil
}

func (in *dmarcIngest) domains(address string) []string {
	in.mu.RLock()
	defer in.mu.RUnlock()
	return in.addresses[address]
}

// observe queues a message if it went to a report address. It never waits.
func (in *dmarcIngest) observe(rcpt string, raw []byte) {
	if in == nil {
		return
	}
	rcpt = strings.ToLower(strings.Trim(strings.TrimSpace(rcpt), "<>"))
	if len(in.domains(rcpt)) == 0 {
		return
	}
	if len(raw) > dmarcMessageMax {
		in.log.Info("DMARC report not read: too large", "bytes", len(raw))
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pending+len(raw) > dmarcQueueBytes {
		in.log.Warn("DMARC report not read: the queue is full; a backfill will pick it up")
		return
	}
	select {
	case in.queue <- dmarcMail{rcpt: rcpt, raw: raw, received: time.Now()}:
		in.pending += len(raw)
	default:
		in.log.Warn("DMARC report not read: the queue is full; a backfill will pick it up")
	}
}

func (in *dmarcIngest) run(ctx context.Context) {
	refresh := func() {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := in.refresh(c); err != nil && ctx.Err() == nil {
			in.log.Warn("DMARC report addresses could not be read", "error", err)
		}
	}
	refresh()
	ticker := time.NewTicker(dmarcRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		case m := <-in.queue:
			c, cancel := context.WithTimeout(ctx, time.Minute)
			if _, err := in.ingest(c, m, in.domains(m.rcpt), time.Now()); err != nil && ctx.Err() == nil {
				in.log.Warn("DMARC report not stored", "error", err)
			}
			cancel()
			in.mu.Lock()
			in.pending -= len(m.raw)
			in.mu.Unlock()
		}
	}
}

// ingest reads one message and stores the report in it, if it is about one
// of domains. The error is storage's: a message that isn't a usable report
// is not one.
func (in *dmarcIngest) ingest(ctx context.Context, m dmarcMail, domains []string, now time.Time) (stored bool, err error) {
	defer func() {
		// The parsers are fed whatever a stranger mails.
		if p := recover(); p != nil {
			stored, err = false, fmt.Errorf("reading a report panicked: %v", p)
		}
	}()
	f, parseErr := in.parse(m.raw, now)
	if parseErr != nil {
		if errors.Is(parseErr, dmarcrpt.ErrBadReport) {
			in.log.Info("DMARC report refused", "reason", parseErr)
		}
		return false, nil
	}
	domain := ""
	for _, d := range domains {
		// A receiver may report a subdomain under its own name.
		if (f.PolicyPublished.Domain == d || strings.HasSuffix(f.PolicyPublished.Domain, "."+d)) && len(d) > len(domain) {
			domain = d
		}
	}
	if domain == "" {
		return false, nil
	}
	sender, verified := reportSender(m.raw)
	return in.engine.storeDMARCReport(ctx, dmarcReport{domain: domain, sender: sender, verified: verified, received: m.received, feedback: f}, now)
}

// reportSender is the domain that sent a report and whether the MTA vouched
// for it. The MTA's verdict header must agree with the first
// Authentication-Results: both are prepended by this server on arrival, but
// mail stored before the verdict header existed has only the latter, and
// there a sender could have written the former.
func reportSender(raw []byte) (string, bool) {
	if kind, domain := mailpolicy.SenderVerified(raw); kind == "dmarc" {
		if results := headerLines(headerBlock(raw), "Authentication-Results"); len(results) > 0 && dmarcPassedFor(results[0], domain) {
			return clipDomain(domain), true
		}
	}
	if msg, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil {
		if from, err := mail.ParseAddress(msg.Header.Get("From")); err == nil {
			if i := strings.LastIndexByte(from.Address, '@'); i >= 0 {
				return clipDomain(from.Address[i+1:]), false
			}
		}
	}
	return "", false
}

func dmarcPassedFor(value, domain string) bool {
	for _, part := range strings.Split(value, ";") {
		f := strings.Fields(strings.ToLower(part))
		if len(f) > 0 && f[0] == "dmarc=pass" && slices.Contains(f, "header.from="+domain) {
			return true
		}
	}
	return false
}

func clipDomain(s string) string {
	s = strings.ToLower(strings.ToValidUTF8(s, ""))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 253 {
		s = strings.ToValidUTF8(s[:253], "")
	}
	return s
}

type backfillResult struct{ read, stored, unindexed int64 }

// dmarcBackfill reads the reports already delivered to address. It reads
// only messages addressed to it and changes none, flags included. Reports
// that came by Bcc don't show the address and aren't found.
func (s *Service) dmarcBackfill(ctx context.Context, domain, address string) (backfillResult, error) {
	var res backfillResult
	account, err := s.auth.Resolve(ctx, address)
	if errors.Is(err, ErrCredentials) {
		return res, errBackfillNotAccount
	}
	if err != nil {
		return res, err
	}
	db := s.engine.DB
	const inMail = ` FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder
WHERE f.account=$1 AND lower(f.name) NOT IN ('calendar','contacts','tasks','settings')`
	if err := db.QueryRowContext(ctx, `SELECT count(*)`+inMail+`
AND NOT EXISTS (SELECT 1 FROM mailbox_summaries s WHERE s.body=m.body AND s.version=$2)`, account.ID, summaryVersion).Scan(&res.unindexed); err != nil {
		return res, err
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ON (m.body) m.body, m.internal_date, s.hdr_to||','||s.hdr_cc||','||s.hdr_bcc
FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder
JOIN mailbox_summaries s ON s.body=m.body AND s.version=$2
WHERE f.account=$1 AND lower(f.name) NOT IN ('calendar','contacts','tasks','settings')
AND m.internal_date>=$3 AND (s.hdr_to ILIKE $4 OR s.hdr_cc ILIKE $4 OR s.hdr_bcc ILIKE $4)
ORDER BY m.body, m.internal_date`, account.ID, summaryVersion, time.Now().Add(-dmarcKeep), likePattern(address))
	if err != nil {
		return res, err
	}
	type candidate struct {
		body string
		date time.Time
	}
	var found []candidate
	err = func() error {
		defer rows.Close()
		for rows.Next() {
			var c candidate
			var to string
			if err := rows.Scan(&c.body, &c.date, &to); err != nil {
				return err
			}
			if addressedTo(to, address) {
				found = append(found, c)
			}
		}
		return rows.Err()
	}()
	if err != nil {
		return res, err
	}
	// Attributed as at delivery: a subdomain registered to the same address
	// gets its own reports, whichever domain's backfill finds them.
	domains := []string{domain}
	registered, err := s.engine.DMARCAddresses(ctx)
	if err != nil {
		return res, err
	}
	for _, a := range registered {
		if a.Address == address && a.Domain != domain {
			domains = append(domains, a.Domain)
		}
	}
	for _, c := range found {
		raw, err := s.engine.Bodies.Get(ctx, c.body, s.engine.MaxBytes+1)
		if err != nil {
			if ctx.Err() != nil {
				return res, err
			}
			s.log.Warn("DMARC backfill skipped an unreadable message", "error", err)
			continue
		}
		res.read++
		if len(raw) > dmarcMessageMax {
			continue
		}
		ok, err := s.dmarc.ingest(ctx, dmarcMail{raw: raw, received: c.date}, domains, time.Now())
		if err != nil {
			return res, err
		}
		if ok {
			res.stored++
		}
	}
	return res, nil
}

var errBackfillNotAccount = errors.New("the address isn't an account or an account's alias, so there is no mailbox to read")

// addressedTo reports whether address appears whole in decoded header text.
func addressedTo(headers, address string) bool {
	return slices.Contains(strings.FieldsFunc(strings.ToLower(headers), func(r rune) bool {
		return strings.ContainsRune(" \t\r\n,;<>()[]\":", r)
	}), address)
}

func dmarcDomainParam(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if d == "" || len(d) > 253 || strings.ContainsAny(d, "@/ \t\r\n<>\"") {
		return "", errors.Join(mailpolicy.ErrInvalid, errors.New("name a domain"))
	}
	return d, nil
}

func dmarcWindow(r *http.Request) (time.Time, error) {
	days := dmarcDefaultDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > dmarcMaxDays {
			return time.Time{}, errors.Join(mailpolicy.ErrInvalid, fmt.Errorf("days is 1 to %d", dmarcMaxDays))
		}
		days = n
	}
	return time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 1-days), nil
}

func (s *Service) dmarcAPI(handle func(string, func(*http.Request) (any, error)), decode func(*http.Request, any) error) {
	handle("GET /v1/admin/dmarc/addresses", func(r *http.Request) (any, error) {
		return s.engine.DMARCAddresses(r.Context())
	})
	handle("PUT /v1/admin/dmarc/addresses/{domain}", func(r *http.Request) (any, error) {
		domain, err := dmarcDomainParam(r.PathValue("domain"))
		if err != nil {
			return nil, err
		}
		var in struct {
			Address string `json:"address"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		address := strings.ToLower(strings.TrimSpace(in.Address))
		if p, err := mail.ParseAddress(address); err != nil || p.Address != address || len(address) > 320 {
			return nil, errors.Join(mailpolicy.ErrInvalid, errors.New("enter the address reports are sent to"))
		}
		out, err := s.engine.SetDMARCAddress(r.Context(), domain, address)
		if err != nil {
			return nil, err
		}
		return out, s.dmarc.refresh(r.Context())
	})
	handle("DELETE /v1/admin/dmarc/addresses/{domain}", func(r *http.Request) (any, error) {
		domain, err := dmarcDomainParam(r.PathValue("domain"))
		if err != nil {
			return nil, err
		}
		if err := s.engine.DeleteDMARCAddress(r.Context(), domain); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.dmarc.refresh(r.Context())
	})
	handle("POST /v1/admin/dmarc/addresses/{domain}/backfill", func(r *http.Request) (any, error) {
		domain, err := dmarcDomainParam(r.PathValue("domain"))
		if err != nil {
			return nil, err
		}
		address, err := s.engine.startDMARCBackfill(r.Context(), domain, time.Now())
		if err != nil {
			return nil, err
		}
		// Years of reports take longer than a request may.
		go func() {
			ctx, cancel := context.WithTimeout(s.ctx, dmarcBackfillTime)
			defer cancel()
			res, err := s.dmarcBackfill(ctx, domain, address)
			problem := ""
			switch {
			case errors.Is(err, errBackfillNotAccount):
				problem = err.Error()
			case err != nil:
				problem = "stopped before the end; start it again"
				s.log.Warn("DMARC backfill stopped", "domain", domain, "error", err)
			}
			done, cancelDone := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancelDone()
			if err := s.engine.finishDMARCBackfill(done, domain, address, res, problem); err != nil {
				s.log.Warn("DMARC backfill result not saved", "domain", domain, "error", err)
			}
			s.log.Info("DMARC backfill finished", "domain", domain, "read", res.read, "stored", res.stored)
		}()
		return map[string]bool{"started": true}, nil
	})
	handle("GET /v1/admin/dmarc/summary", func(r *http.Request) (any, error) {
		since, err := dmarcWindow(r)
		if err != nil {
			return nil, err
		}
		return s.engine.DMARCSummary(r.Context(), r.URL.Query()["domain"], since)
	})
	handle("GET /v1/admin/dmarc/sources", func(r *http.Request) (any, error) {
		since, err := dmarcWindow(r)
		if err != nil {
			return nil, err
		}
		return s.engine.DMARCSources(r.Context(), r.URL.Query()["domain"], since)
	})
}
