// Package dmarcrpt implements the sending side of DMARC aggregate reporting
// (RFC 7489 §7.2).
//
// A domain that publishes a DMARC record with a rua= tag is asking receivers
// to tell it, once a day, which hosts sent mail in its name and whether that
// mail authenticated. That is how a domain owner finds the third-party
// sender they forgot to authorise before moving to p=reject, and how they
// spot someone forging them. Without reports from receivers, DMARC
// deployment is guesswork.
//
// Evaluations are counted in memory per UTC day and policy domain, and
// persisted to a state file, so a restart loses at most one flush interval
// of counts rather than the whole day.
package dmarcrpt

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Policy is the DMARC record published by the policy domain.
type Policy struct {
	Domain string `json:"domain"`
	P      string `json:"p"`
	SP     string `json:"sp"`
	Pct    int    `json:"pct"`
	ADKIM  string `json:"adkim"`
	ASPF   string `json:"aspf"`
	// RUA is the aggregate report URIs as published.
	RUA []string `json:"rua"`
}

// DKIMAuth is one DKIM signature's outcome.
type DKIMAuth struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector,omitempty"`
	Result   string `json:"result"`
}

// SPFAuth is the SPF outcome for the MAIL FROM identity.
type SPFAuth struct {
	Domain string `json:"domain"`
	Result string `json:"result"`
}

// Evaluation is one message's DMARC evaluation.
type Evaluation struct {
	SourceIP     string
	HeaderFrom   string
	EnvelopeFrom string
	Policy       Policy
	// Disposition is what was applied: none, quarantine or reject.
	Disposition string
	DKIMAligned bool
	SPFAligned  bool
	// OverrideReason explains a disposition that differs from the policy,
	// using the RFC 7489 PolicyOverrideType values (local_policy, ...).
	OverrideReason string
	DKIM           []DKIMAuth
	SPF            SPFAuth
}

// row is one <record> of a report: evaluations that agree on everything a
// report shows, counted together.
type row struct {
	SourceIP     string     `json:"source_ip"`
	Disposition  string     `json:"disposition"`
	DKIM         string     `json:"dkim"`
	SPF          string     `json:"spf"`
	Reason       string     `json:"reason,omitempty"`
	HeaderFrom   string     `json:"header_from"`
	EnvelopeFrom string     `json:"envelope_from,omitempty"`
	DKIMAuth     []DKIMAuth `json:"dkim_auth,omitempty"`
	SPFAuth      SPFAuth    `json:"spf_auth"`
	Count        int64      `json:"count"`
}

func (r *row) key() string {
	var b strings.Builder
	for _, f := range []string{r.SourceIP, r.Disposition, r.DKIM, r.SPF, r.Reason, r.HeaderFrom, r.EnvelopeFrom, r.SPFAuth.Domain, r.SPFAuth.Result} {
		b.WriteString(f)
		b.WriteByte(0)
	}
	for _, d := range r.DKIMAuth {
		b.WriteString(d.Domain + "/" + d.Selector + "/" + d.Result)
		b.WriteByte(0)
	}
	return b.String()
}

// dayCounts is everything recorded for one policy domain on one UTC day.
type dayCounts struct {
	// Policy is the most recently seen record: a domain that changes its
	// policy mid-day gets one report under the newer one.
	Policy Policy          `json:"policy"`
	Rows   map[string]*row `json:"rows"`
	// Overflow counts messages not given a row because Rows was full.
	Overflow int64 `json:"overflow,omitempty"`
}

// maxRows bounds the distinct rows kept per domain per day, so a domain
// forged from a botnet cannot grow memory and the state file without limit.
// Messages past it are counted, and the report says how many were left out.
const maxRows = 10000

// maxDomains bounds the policy domains tracked per day for the same reason:
// every spam run can name a fresh From domain.
const maxDomains = 10000

// Counter aggregates evaluations by UTC day and policy domain.
type Counter struct {
	mu   sync.Mutex
	days map[string]map[string]*dayCounts // day (YYYY-MM-DD) -> domain -> counts
	// droppedDomains counts evaluations refused because maxDomains was hit,
	// for the log; it is not persisted.
	droppedDomains int64
	now            func() time.Time
}

// NewCounter returns an empty counter.
func NewCounter() *Counter {
	return &Counter{days: make(map[string]map[string]*dayCounts), now: time.Now}
}

func dayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

func normDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

func passFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

// Record counts one evaluation. Evaluations for domains that do not ask for
// aggregate reports by email are ignored, since nothing could be done with
// them.
func (c *Counter) Record(e Evaluation) {
	domain := normDomain(e.Policy.Domain)
	if domain == "" || len(parseRUA(e.Policy.RUA)) == 0 {
		return
	}
	e.Policy.Domain = domain
	r := &row{
		SourceIP:     e.SourceIP,
		Disposition:  e.Disposition,
		DKIM:         passFail(e.DKIMAligned),
		SPF:          passFail(e.SPFAligned),
		Reason:       e.OverrideReason,
		HeaderFrom:   normDomain(e.HeaderFrom),
		EnvelopeFrom: normDomain(e.EnvelopeFrom),
		DKIMAuth:     append([]DKIMAuth(nil), e.DKIM...),
		SPFAuth:      e.SPF,
	}
	if r.Disposition == "" {
		r.Disposition = "none"
	}
	k := r.key()

	c.mu.Lock()
	defer c.mu.Unlock()
	day := dayOf(c.now())
	domains := c.days[day]
	if domains == nil {
		domains = make(map[string]*dayCounts)
		c.days[day] = domains
	}
	dc := domains[domain]
	if dc == nil {
		if len(domains) >= maxDomains {
			c.droppedDomains++
			return
		}
		dc = &dayCounts{Rows: make(map[string]*row)}
		domains[domain] = dc
	}
	dc.Policy = e.Policy
	if existing := dc.Rows[k]; existing != nil {
		existing.Count++
		return
	}
	if len(dc.Rows) >= maxRows {
		dc.Overflow++
		return
	}
	r.Count = 1
	dc.Rows[k] = r
}

// takeDroppedDomains returns and resets the count of evaluations refused
// for want of room.
func (c *Counter) takeDroppedDomains() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.droppedDomains
	c.droppedDomains = 0
	return n
}

// completedDays returns recorded days that have ended, oldest first.
func (c *Counter) completedDays() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	today := dayOf(c.now())
	var out []string
	for d := range c.days {
		if d < today {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// domainsFor returns the domains recorded on day, sorted.
func (c *Counter) domainsFor(day string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for d := range c.days[day] {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// take returns and removes the counts for one domain and day.
func (c *Counter) take(day, domain string) *dayCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	domains := c.days[day]
	dc := domains[domain]
	delete(domains, domain)
	if len(domains) == 0 {
		delete(c.days, day)
	}
	return dc
}

// restore puts counts back after a failed send. The day is over, so nothing
// can have been recorded for it meanwhile.
func (c *Counter) restore(day, domain string, dc *dayCounts) {
	c.mu.Lock()
	defer c.mu.Unlock()
	domains := c.days[day]
	if domains == nil {
		domains = make(map[string]*dayCounts)
		c.days[day] = domains
	}
	if domains[domain] == nil {
		domains[domain] = dc
	}
}
