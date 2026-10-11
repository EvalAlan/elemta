package dmarcrpt

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Feedback is the RFC 7489 Appendix C aggregate report.
type Feedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []Record        `xml:"record"`
}

// ReportMetadata identifies the reporter and the window.
type ReportMetadata struct {
	OrgName   string    `xml:"org_name"`
	Email     string    `xml:"email"`
	ReportID  string    `xml:"report_id"`
	DateRange DateRange `xml:"date_range"`
	Errors    []string  `xml:"error,omitempty"`
}

// DateRange is the reporting window in Unix seconds.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished is the record the report was produced under.
type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    int    `xml:"pct"`
}

// Record is one group of messages.
type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row is the source and what DMARC made of its messages.
type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int64           `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

// PolicyEvaluated is the applied disposition and aligned results.
type PolicyEvaluated struct {
	Disposition string   `xml:"disposition"`
	DKIM        string   `xml:"dkim"`
	SPF         string   `xml:"spf"`
	Reasons     []Reason `xml:"reason,omitempty"`
}

// Reason explains a disposition that departs from the published policy.
type Reason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment,omitempty"`
}

// Identifiers are the domains the message presented.
type Identifiers struct {
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
}

// AuthResults are the underlying, unaligned DKIM and SPF results.
type AuthResults struct {
	DKIM []DKIMResult `xml:"dkim,omitempty"`
	SPF  []SPFResult  `xml:"spf"`
}

// DKIMResult is one signature.
type DKIMResult struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector,omitempty"`
	Result   string `xml:"result"`
}

// SPFResult is the MAIL FROM check.
type SPFResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// The schema enumerates these; anything else a library reports is "none"
// rather than an invalid document receivers would reject.
var (
	dkimResults = map[string]bool{"none": true, "pass": true, "fail": true, "policy": true, "neutral": true, "temperror": true, "permerror": true}
	spfResults  = map[string]bool{"none": true, "neutral": true, "pass": true, "fail": true, "softfail": true, "temperror": true, "permerror": true}
)

func enumOr(v string, allowed map[string]bool) string {
	v = strings.ToLower(v)
	if allowed[v] {
		return v
	}
	return "none"
}

// buildReport turns one domain-day of counts into a report. Output is
// deterministic for the same counts, so a report re-sent after a crash is
// byte-identical to the first attempt.
func buildReport(day, domain string, dc *dayCounts, org, contact, hostname string) (*Feedback, error) {
	start, err := time.Parse("2006-01-02", day)
	if err != nil {
		return nil, fmt.Errorf("bad report day %q: %w", day, err)
	}
	start = start.UTC()
	p := dc.Policy
	f := &Feedback{
		Version: "1.0",
		ReportMetadata: ReportMetadata{
			OrgName:   org,
			Email:     contact,
			ReportID:  fmt.Sprintf("%s_%s@%s", day, domain, hostname),
			DateRange: DateRange{Begin: start.Unix(), End: start.Add(24*time.Hour - time.Second).Unix()},
		},
		PolicyPublished: PolicyPublished{Domain: domain, ADKIM: p.ADKIM, ASPF: p.ASPF, P: p.P, SP: p.SP, Pct: p.Pct},
	}
	if dc.Overflow > 0 {
		f.ReportMetadata.Errors = append(f.ReportMetadata.Errors,
			fmt.Sprintf("%d messages not itemised: limit of %d records per day reached", dc.Overflow, maxRows))
	}
	keys := make([]string, 0, len(dc.Rows))
	for k := range dc.Rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := dc.Rows[k]
		rec := Record{
			Row: Row{
				SourceIP: r.SourceIP,
				Count:    r.Count,
				PolicyEvaluated: PolicyEvaluated{
					Disposition: r.Disposition,
					DKIM:        r.DKIM,
					SPF:         r.SPF,
				},
			},
			Identifiers: Identifiers{EnvelopeFrom: r.EnvelopeFrom, HeaderFrom: r.HeaderFrom},
			AuthResults: AuthResults{SPF: []SPFResult{{
				Domain: r.SPFAuth.Domain, Scope: "mfrom", Result: enumOr(r.SPFAuth.Result, spfResults),
			}}},
		}
		if r.Reason != "" {
			rec.Row.PolicyEvaluated.Reasons = []Reason{{Type: r.Reason}}
		}
		for _, d := range r.DKIMAuth {
			rec.AuthResults.DKIM = append(rec.AuthResults.DKIM, DKIMResult{
				Domain: d.Domain, Selector: d.Selector, Result: enumOr(d.Result, dkimResults),
			})
		}
		f.Records = append(f.Records, rec)
	}
	return f, nil
}

// marshalXML renders the report document.
func marshalXML(f *Feedback) ([]byte, error) {
	body, err := xml.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	out := append([]byte(xml.Header), body...)
	return append(out, '\n'), nil
}

// gzipXML is the report as sent.
func gzipXML(f *Feedback) ([]byte, error) {
	raw, err := marshalXML(f)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	// No name and zero mtime in the header keep the bytes deterministic.
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// reportFilename follows RFC 7489 §7.2.1.1:
// receiver!policy-domain!begin-timestamp!end-timestamp.xml.gz
func reportFilename(f *Feedback, hostname string) string {
	return fmt.Sprintf("%s!%s!%d!%d.xml.gz", hostname, f.PolicyPublished.Domain,
		f.ReportMetadata.DateRange.Begin, f.ReportMetadata.DateRange.End)
}

func reportSubject(f *Feedback, hostname string) string {
	return fmt.Sprintf("Report Domain: %s Submitter: %s Report-ID: <%s>",
		f.PolicyPublished.Domain, hostname, f.ReportMetadata.ReportID)
}

// buildEmail renders the report as a message with the gzipped XML attached
// (RFC 7489 §7.2.1.1).
func buildEmail(f *Feedback, gz []byte, hostname, from string, to []string) []byte {
	boundary := "dmarc-" + strings.NewReplacer("@", ".", "_", ".").Replace(f.ReportMetadata.ReportID)
	// The Date is the end of the window, not the send time, so the message is
	// byte-identical if it has to be re-enqueued after a crash.
	date := time.Unix(f.ReportMetadata.DateRange.End+1, 0).UTC().Format(time.RFC1123Z)
	var b strings.Builder
	fmt.Fprintf(&b, "From: <%s>\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", angleList(to))
	fmt.Fprintf(&b, "Date: %s\r\n", date)
	fmt.Fprintf(&b, "Subject: %s\r\n", reportSubject(f, hostname))
	fmt.Fprintf(&b, "Message-ID: <%s>\r\n", f.ReportMetadata.ReportID)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	fmt.Fprintf(&b, "This is a DMARC aggregate report from %s for %s, %s.\r\n\r\n",
		f.ReportMetadata.OrgName, f.PolicyPublished.Domain,
		time.Unix(f.ReportMetadata.DateRange.Begin, 0).UTC().Format("2006-01-02"))
	name := reportFilename(f, hostname)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: application/gzip; name=\"%s\"\r\n", boundary, name)
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", name)
	enc := base64.StdEncoding.EncodeToString(gz)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

func angleList(addrs []string) string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = "<" + a + ">"
	}
	return strings.Join(out, ", ")
}

// destination is one mailto: rua target.
type destination struct {
	Addr   string
	Domain string
	// Limit is the largest report the destination accepts, in bytes; zero
	// means no limit.
	Limit int64
}

// parseRUA keeps the mailto: URIs of a rua tag. Other schemes are not
// defined for DMARC aggregate reports and are skipped.
func parseRUA(uris []string) []destination {
	var out []destination
	for _, u := range uris {
		u = strings.TrimSpace(u)
		if len(u) < len("mailto:") || !strings.EqualFold(u[:len("mailto:")], "mailto:") {
			continue
		}
		u = u[len("mailto:"):]
		var limit int64
		if i := strings.LastIndexByte(u, '!'); i >= 0 {
			n, ok := parseSize(u[i+1:])
			if !ok {
				continue
			}
			limit = n
			u = u[:i]
		}
		// Header fields in a mailto: URI are not ours to honour.
		if i := strings.IndexByte(u, '?'); i >= 0 {
			u = u[:i]
		}
		addr, err := url.PathUnescape(u)
		if err != nil || strings.ContainsAny(addr, "\r\n<>,; \t") {
			continue
		}
		at := strings.LastIndexByte(addr, '@')
		if at <= 0 || at == len(addr)-1 {
			continue
		}
		out = append(out, destination{Addr: addr, Domain: normDomain(addr[at+1:]), Limit: limit})
	}
	return out
}

// parseSize reads the RFC 7489 §6.2 size suffix: digits with an optional
// k, m, g or t unit, each a power of 2^10.
func parseSize(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	shift := 0
	switch s[len(s)-1] {
	case 'k', 'K':
		shift = 10
	case 'm', 'M':
		shift = 20
	case 'g', 'G':
		shift = 30
	case 't', 'T':
		shift = 40
	}
	if shift > 0 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)>>shift {
		return 0, false
	}
	return n << shift, true
}
