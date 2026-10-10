// Package tlsrpt implements the sending side of SMTP TLS Reporting (RFC 8460).
//
// Receivers publish a TXT record at _smtp._tls.<domain> naming where they
// want reports. Senders count, per recipient domain and UTC day, how many
// SMTP sessions negotiated TLS as that domain's policy required and how many
// did not (and why), then send one aggregate JSON report per domain per day.
//
// The point is for receivers to learn that their MTA-STS policy or
// certificates are broken from the senders who hit the breakage, instead of
// from missing mail. Without reports, a receiver with an expired certificate
// sees nothing: opportunistic senders fall back to unverified TLS or plaintext
// and the mail still arrives.
//
// Counting is in memory and persisted to a state file, so a restart loses at
// most one flush interval of counts rather than the whole day.
package tlsrpt

import (
	"crypto/x509"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Policy types (RFC 8460 §4.4).
const (
	PolicyTypeSTS      = "sts"
	PolicyTypeTLSA     = "tlsa"
	PolicyTypeNoPolicy = "no-policy-found"
)

// Result types (RFC 8460 §4.3).
const (
	ResultStartTLSNotSupported    = "starttls-not-supported"
	ResultCertificateHostMismatch = "certificate-host-mismatch"
	ResultCertificateExpired      = "certificate-expired"
	ResultCertificateNotTrusted   = "certificate-not-trusted"
	ResultValidationFailure       = "validation-failure"
	ResultTLSAInvalid             = "tlsa-invalid"
	ResultDNSSECInvalid           = "dnssec-invalid"
	ResultDANERequired            = "dane-required"
)

// Policy identifies the policy a session was evaluated against.
type Policy struct {
	Type string `json:"policy-type"`
	// Strings is the policy as published: MTA-STS policy lines, or TLSA
	// records in presentation format. Empty for no-policy-found.
	Strings []string `json:"policy-string,omitempty"`
	Domain  string   `json:"policy-domain"`
	// MXHosts is the MX patterns an MTA-STS policy lists.
	MXHosts []string `json:"mx-host,omitempty"`
}

func (p Policy) key() string {
	return p.Type + "\x00" + strings.Join(p.Strings, "\n") + "\x00" + strings.Join(p.MXHosts, ",")
}

// Session is the outcome of one SMTP session's TLS negotiation.
type Session struct {
	Policy Policy
	// Success means TLS was negotiated as the policy required.
	Success bool
	// ResultType classifies a failure; ignored on success.
	ResultType    string
	SendingIP     string
	ReceivingMX   string
	ReceivingIP   string
	FailureReason string
}

// ClassifyCertError maps a certificate verification error to a result type.
func ClassifyCertError(err error) string {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return ResultCertificateHostMismatch
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return ResultCertificateExpired
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return ResultCertificateNotTrusted
	}
	return ResultValidationFailure
}

// failureKey groups failures the way a report lists them.
type failureKey struct {
	ResultType  string `json:"result-type"`
	SendingIP   string `json:"sending-mta-ip,omitempty"`
	ReceivingMX string `json:"receiving-mx-hostname,omitempty"`
	ReceivingIP string `json:"receiving-ip,omitempty"`
}

type failureCount struct {
	failureKey
	Count  int64  `json:"failed-session-count"`
	Reason string `json:"failure-reason-code,omitempty"`
}

type policyCounts struct {
	Policy   Policy                   `json:"policy"`
	Success  int64                    `json:"success"`
	Failures map[string]*failureCount `json:"failures,omitempty"`
}

// dayCounts is everything recorded for one recipient domain on one UTC day.
type dayCounts struct {
	Policies map[string]*policyCounts `json:"policies"`
}

// maxFailureRows bounds the distinct failure rows kept per policy, so a
// domain with thousands of MX addresses cannot grow the state without limit.
// Further distinct failures are folded into a row with no receiving details.
const maxFailureRows = 100

// Counter aggregates sessions by UTC day and recipient domain.
type Counter struct {
	mu   sync.Mutex
	days map[string]map[string]*dayCounts // day (YYYY-MM-DD) -> domain -> counts
	now  func() time.Time
}

// NewCounter returns an empty counter.
func NewCounter() *Counter {
	return &Counter{days: make(map[string]map[string]*dayCounts), now: time.Now}
}

func dayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Record counts one session.
func (c *Counter) Record(s Session) {
	domain := strings.ToLower(strings.TrimSuffix(s.Policy.Domain, "."))
	if domain == "" {
		return
	}
	s.Policy.Domain = domain
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
		dc = &dayCounts{Policies: make(map[string]*policyCounts)}
		domains[domain] = dc
	}
	pk := s.Policy.key()
	pc := dc.Policies[pk]
	if pc == nil {
		pc = &policyCounts{Policy: s.Policy}
		dc.Policies[pk] = pc
	}
	if s.Success {
		pc.Success++
		return
	}
	if pc.Failures == nil {
		pc.Failures = make(map[string]*failureCount)
	}
	fk := failureKey{ResultType: s.ResultType, SendingIP: s.SendingIP, ReceivingMX: s.ReceivingMX, ReceivingIP: s.ReceivingIP}
	k := fk.ResultType + "|" + fk.SendingIP + "|" + fk.ReceivingMX + "|" + fk.ReceivingIP
	fc := pc.Failures[k]
	if fc == nil {
		if len(pc.Failures) >= maxFailureRows {
			fk = failureKey{ResultType: s.ResultType}
			k = fk.ResultType + "|||"
			fc = pc.Failures[k]
		}
		if fc == nil {
			fc = &failureCount{failureKey: fk, Reason: s.FailureReason}
			pc.Failures[k] = fc
		}
	}
	fc.Count++
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

// restore puts counts back after a failed send, merging with anything
// recorded meanwhile (nothing can be: the day is over, but be safe).
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
