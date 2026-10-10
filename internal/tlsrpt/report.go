package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Report is the RFC 8460 §4.4 JSON report.
type Report struct {
	OrganizationName string         `json:"organization-name"`
	DateRange        DateRange      `json:"date-range"`
	ContactInfo      string         `json:"contact-info"`
	ReportID         string         `json:"report-id"`
	Policies         []PolicyResult `json:"policies"`
}

// DateRange is the reporting window.
type DateRange struct {
	Start time.Time `json:"start-datetime"`
	End   time.Time `json:"end-datetime"`
}

// PolicyResult is one policy's counts within a report.
type PolicyResult struct {
	Policy         Policy          `json:"policy"`
	Summary        Summary         `json:"summary"`
	FailureDetails []FailureDetail `json:"failure-details,omitempty"`
}

// Summary holds the session totals for a policy.
type Summary struct {
	Successful int64 `json:"total-successful-session-count"`
	Failed     int64 `json:"total-failure-session-count"`
}

// FailureDetail is one row of grouped failures.
type FailureDetail struct {
	ResultType  string `json:"result-type"`
	SendingIP   string `json:"sending-mta-ip,omitempty"`
	ReceivingMX string `json:"receiving-mx-hostname,omitempty"`
	ReceivingIP string `json:"receiving-ip,omitempty"`
	Count       int64  `json:"failed-session-count"`
	Reason      string `json:"failure-reason-code,omitempty"`
}

// buildReport turns one domain-day of counts into a report. Output is
// deterministic for the same counts, so a report re-sent after a crash is
// byte-identical to the first attempt.
func buildReport(day, domain string, dc *dayCounts, org, contact, hostname string) (*Report, error) {
	start, err := time.Parse("2006-01-02", day)
	if err != nil {
		return nil, fmt.Errorf("bad report day %q: %w", day, err)
	}
	r := &Report{
		OrganizationName: org,
		DateRange:        DateRange{Start: start.UTC(), End: start.UTC().Add(24*time.Hour - time.Second)},
		ContactInfo:      contact,
		ReportID:         fmt.Sprintf("%s_%s@%s", day, domain, hostname),
	}
	keys := make([]string, 0, len(dc.Policies))
	for k := range dc.Policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pc := dc.Policies[k]
		pr := PolicyResult{Policy: pc.Policy, Summary: Summary{Successful: pc.Success}}
		fkeys := make([]string, 0, len(pc.Failures))
		for fk := range pc.Failures {
			fkeys = append(fkeys, fk)
		}
		sort.Strings(fkeys)
		for _, fk := range fkeys {
			f := pc.Failures[fk]
			pr.Summary.Failed += f.Count
			pr.FailureDetails = append(pr.FailureDetails, FailureDetail{
				ResultType: f.ResultType, SendingIP: f.SendingIP, ReceivingMX: f.ReceivingMX,
				ReceivingIP: f.ReceivingIP, Count: f.Count, Reason: f.Reason,
			})
		}
		r.Policies = append(r.Policies, pr)
	}
	return r, nil
}

// gzipJSON is the report as sent: gzip-compressed JSON.
func gzipJSON(r *Report) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// A fixed header (no name, zero mtime) keeps the bytes deterministic.
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// reportFilename follows RFC 8460 §5.3: submitter!policy-domain!begin!end.json.gz
func reportFilename(r *Report, domain string) string {
	return fmt.Sprintf("%s!%s!%d!%d.json.gz", hostOnly(r.ReportID), domain,
		r.DateRange.Start.Unix(), r.DateRange.End.Unix())
}

func hostOnly(reportID string) string {
	if i := strings.LastIndexByte(reportID, '@'); i >= 0 {
		return reportID[i+1:]
	}
	return reportID
}

// buildEmail renders the report as an RFC 8460 §5.3 multipart/report message.
func buildEmail(r *Report, gz []byte, domain, from string, to []string) []byte {
	boundary := "tlsrpt-" + strings.NewReplacer("@", ".", "_", ".").Replace(r.ReportID)
	// The Date is the end of the reporting window, not the send time, so the
	// message is byte-identical if it has to be re-enqueued after a crash.
	date := r.DateRange.End.Add(time.Second).Format(time.RFC1123Z)
	var b strings.Builder
	fmt.Fprintf(&b, "From: <%s>\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", angleList(to))
	fmt.Fprintf(&b, "Date: %s\r\n", date)
	fmt.Fprintf(&b, "Subject: Report Domain: %s Submitter: %s Report-ID: <%s>\r\n", domain, hostOnly(r.ReportID), r.ReportID)
	fmt.Fprintf(&b, "Message-ID: <%s>\r\n", r.ReportID)
	fmt.Fprintf(&b, "TLS-Report-Domain: %s\r\n", domain)
	fmt.Fprintf(&b, "TLS-Report-Submitter: %s\r\n", hostOnly(r.ReportID))
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/report; report-type=\"tlsrpt\"; boundary=\"%s\"\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	fmt.Fprintf(&b, "This is an aggregate TLS report from %s for %s, %s.\r\n\r\n",
		r.OrganizationName, domain, r.DateRange.Start.Format("2006-01-02"))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: application/tlsrpt+gzip\r\n", boundary)
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", reportFilename(r, domain))
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
