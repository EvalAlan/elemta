package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var stsPolicy = Policy{
	Type:    PolicyTypeSTS,
	Domain:  "example.com",
	Strings: []string{"version: STSv1", "mode: enforce", "mx: mx.example.com", "max_age: 86400"},
	MXHosts: []string{"mx.example.com"},
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestCounterAggregatesByDayDomainAndFailure(t *testing.T) {
	c := NewCounter()
	day1 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	c.now = fixedClock(day1)

	for i := 0; i < 3; i++ {
		c.Record(Session{Policy: stsPolicy, Success: true})
	}
	fail := Session{Policy: stsPolicy, ResultType: ResultCertificateExpired, ReceivingMX: "mx.example.com", ReceivingIP: "192.0.2.1"}
	c.Record(fail)
	c.Record(fail)
	c.Record(Session{Policy: Policy{Type: PolicyTypeNoPolicy, Domain: "EXAMPLE.com."}, Success: true})

	c.now = fixedClock(day1.Add(24 * time.Hour))
	days := c.completedDays()
	if len(days) != 1 || days[0] != "2026-10-09" {
		t.Fatalf("completed days = %v", days)
	}
	if got := c.domainsFor("2026-10-09"); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("domains = %v, want example.com folded together", got)
	}

	r, err := buildReport("2026-10-09", "example.com", c.take("2026-10-09", "example.com"), "Org", "ops@example.net", "mx.sender.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policies) != 2 {
		t.Fatalf("policies = %d, want sts and no-policy-found", len(r.Policies))
	}
	var sts *PolicyResult
	for i := range r.Policies {
		if r.Policies[i].Policy.Type == PolicyTypeSTS {
			sts = &r.Policies[i]
		}
	}
	if sts == nil || sts.Summary.Successful != 3 || sts.Summary.Failed != 2 {
		t.Fatalf("sts summary = %+v", sts)
	}
	if len(sts.FailureDetails) != 1 || sts.FailureDetails[0].Count != 2 || sts.FailureDetails[0].ResultType != ResultCertificateExpired {
		t.Fatalf("failure details = %+v", sts.FailureDetails)
	}
	if !r.DateRange.Start.Equal(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)) ||
		!r.DateRange.End.Equal(time.Date(2026, 10, 9, 23, 59, 59, 0, time.UTC)) {
		t.Errorf("date range = %+v", r.DateRange)
	}
	if len(c.completedDays()) != 0 {
		t.Error("take left the day behind")
	}
}

// The JSON uses RFC 8460's field names; receivers parse it strictly.
func TestReportJSONFieldNames(t *testing.T) {
	c := NewCounter()
	c.Record(Session{Policy: stsPolicy, ResultType: ResultStartTLSNotSupported, SendingIP: "198.51.100.1", ReceivingMX: "mx.example.com"})
	r, err := buildReport(dayOf(time.Now()), "example.com", c.take(dayOf(time.Now()), "example.com"), "Org", "c", "h")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	for _, want := range []string{
		`"organization-name"`, `"date-range"`, `"start-datetime"`, `"end-datetime"`, `"contact-info"`, `"report-id"`,
		`"policy-type":"sts"`, `"policy-string"`, `"policy-domain"`, `"mx-host"`,
		`"total-successful-session-count"`, `"total-failure-session-count"`,
		`"result-type":"starttls-not-supported"`, `"sending-mta-ip"`, `"receiving-mx-hostname"`, `"failed-session-count"`,
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("report JSON lacks %s: %s", want, raw)
		}
	}
}

func TestFailureRowsAreBounded(t *testing.T) {
	c := NewCounter()
	for i := 0; i < maxFailureRows+50; i++ {
		c.Record(Session{Policy: stsPolicy, ResultType: ResultValidationFailure, ReceivingIP: net.IPv4(10, 0, byte(i>>8), byte(i)).String()})
	}
	dc := c.take(dayOf(time.Now()), "example.com")
	for _, pc := range dc.Policies {
		if len(pc.Failures) > maxFailureRows+1 {
			t.Errorf("%d failure rows, want at most %d", len(pc.Failures), maxFailureRows+1)
		}
		var total int64
		for _, f := range pc.Failures {
			total += f.Count
		}
		if total != maxFailureRows+50 {
			t.Errorf("folding lost sessions: total %d", total)
		}
	}
}

func TestClassifyCertError(t *testing.T) {
	cases := map[string]error{
		ResultCertificateHostMismatch: x509.HostnameError{Host: "mx.example.com", Certificate: &x509.Certificate{}},
		ResultCertificateExpired:      x509.CertificateInvalidError{Reason: x509.Expired, Cert: &x509.Certificate{}},
		ResultCertificateNotTrusted:   x509.UnknownAuthorityError{},
		ResultValidationFailure:       errors.New("handshake failure"),
	}
	for want, err := range cases {
		if got := ClassifyCertError(err); got != want {
			t.Errorf("ClassifyCertError(%T) = %s, want %s", err, got, want)
		}
		// The TLS stack wraps verification errors; classification sees through it.
		if got := ClassifyCertError(&wrapped{err}); got != want {
			t.Errorf("wrapped %T = %s, want %s", err, got, want)
		}
	}
}

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "tls: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }

func TestParseRecord(t *testing.T) {
	cases := []struct {
		txt  string
		ok   bool
		want []string
	}{
		{"v=TLSRPTv1; rua=mailto:tls@example.com", true, []string{"mailto:tls@example.com"}},
		{"v=TLSRPTv1;rua=mailto:a@example.com,https://r.example.com/tls", true, []string{"mailto:a@example.com", "https://r.example.com/tls"}},
		{"v=TLSRPTv1; rua=http://insecure.example.com/x", true, nil},
		{"v=TLSRPTv1; rua=mailto:tls%40example.com", true, []string{"mailto:tls@example.com"}},
		{"v=TLSRPTv1; rua=mailto:x@example.com%0d%0aBcc:y@z", true, nil},
		{"v=spf1 -all", false, nil},
		{"v=TLSRPTv1", false, nil},
	}
	for _, c := range cases {
		got, ok := parseRecord(c.txt)
		if ok != c.ok || strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("parseRecord(%q) = %v %v, want %v %v", c.txt, got, ok, c.want, c.ok)
		}
	}
}

type fakeTXT map[string][]string

func (f fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type enqueued struct {
	id, from string
	to       []string
	content  []byte
}

func newTestReporter(t *testing.T, txt fakeTXT, state string) (*Reporter, *[]enqueued) {
	t.Helper()
	var mu sync.Mutex
	var got []enqueued
	r, err := NewReporter(Config{OrganizationName: "Sender Org", Hostname: "mx.sender.test", From: "tlsrpt@sender.test", StateFile: state},
		func(id, from string, to []string, _ string, content []byte) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, enqueued{id, from, to, content})
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.resolver = txt
	return r, &got
}

func TestSendDueEmailsReportOnlyToDomainsThatAsk(t *testing.T) {
	r, got := newTestReporter(t, fakeTXT{"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:tls-reports@example.com"}}, "")
	yesterday := time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)
	r.now = fixedClock(yesterday)
	r.Record(Session{Policy: stsPolicy, Success: true})
	r.Record(Session{Policy: Policy{Type: PolicyTypeNoPolicy, Domain: "quiet.test"}, Success: true})

	// Nothing is sent for a day that is still running.
	r.SendDue(context.Background())
	if len(*got) != 0 {
		t.Fatal("report sent before the day ended")
	}

	r.now = fixedClock(yesterday.Add(12 * time.Hour))
	r.SendDue(context.Background())
	if len(*got) != 1 {
		t.Fatalf("reports enqueued = %d, want 1 (quiet.test publishes no record)", len(*got))
	}
	m := (*got)[0]
	if m.from != "tlsrpt@sender.test" || len(m.to) != 1 || m.to[0] != "tls-reports@example.com" {
		t.Errorf("envelope = %s -> %v", m.from, m.to)
	}
	msg := string(m.content)
	for _, want := range []string{
		"TLS-Report-Domain: example.com\r\n",
		"TLS-Report-Submitter: mx.sender.test\r\n",
		`Content-Type: multipart/report; report-type="tlsrpt"`,
		"Content-Type: application/tlsrpt+gzip\r\n",
		`filename="mx.sender.test!example.com!1791504000!1791590399.json.gz"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("report email lacks %q", want)
		}
	}
	report := decodeAttachment(t, msg)
	if report.Policies[0].Summary.Successful != 1 || report.OrganizationName != "Sender Org" {
		t.Errorf("attached report = %+v", report)
	}
	if len(r.completedDays()) != 0 {
		t.Error("sent and skipped domains were not cleared")
	}
}

func decodeAttachment(t *testing.T, msg string) Report {
	t.Helper()
	i := strings.Index(msg, "filename=")
	body := msg[strings.Index(msg[i:], "\r\n\r\n")+i+4:]
	body = body[:strings.Index(body, "--")]
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	js, _ := io.ReadAll(zr)
	var r Report
	if err := json.Unmarshal(js, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// The same counts produce the same bytes and queue ID, so a report
// re-enqueued after a crash is recognised as the one already queued.
func TestReportEmailIsDeterministic(t *testing.T) {
	build := func() enqueued {
		r, got := newTestReporter(t, fakeTXT{"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:t@example.com"}}, "")
		r.now = fixedClock(time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC))
		r.Record(Session{Policy: stsPolicy, Success: true})
		r.now = fixedClock(time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC))
		r.SendDue(context.Background())
		return (*got)[0]
	}
	a, b := build(), build()
	if a.id != b.id || !bytes.Equal(a.content, b.content) {
		t.Error("report email differs between identical runs")
	}
}

func TestSendDuePostsHTTPS(t *testing.T) {
	var gotType string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotType = req.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(req.Body)
	}))
	defer srv.Close()

	r, got := newTestReporter(t, fakeTXT{"_smtp._tls.example.com": {"v=TLSRPTv1; rua=" + srv.URL + "/report"}}, "")
	r.http = srv.Client()
	r.now = fixedClock(time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC))
	r.Record(Session{Policy: stsPolicy, Success: true})
	r.now = fixedClock(time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC))
	r.SendDue(context.Background())

	if gotType != "application/tlsrpt+gzip" {
		t.Errorf("Content-Type = %q", gotType)
	}
	if _, err := gzip.NewReader(bytes.NewReader(gotBody)); err != nil {
		t.Errorf("body is not gzip: %v", err)
	}
	if len(*got) != 0 {
		t.Error("https-only record also produced an email")
	}
}

// A failed send keeps the counts and waits before trying again.
func TestSendDueRetriesLater(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	r, _ := newTestReporter(t, fakeTXT{"_smtp._tls.example.com": {"v=TLSRPTv1; rua=" + srv.URL}}, "")
	r.http = srv.Client()
	start := time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC)
	r.now = fixedClock(start)
	r.Record(Session{Policy: stsPolicy, Success: true})

	now := start.Add(24 * time.Hour)
	r.now = fixedClock(now)
	r.SendDue(context.Background())
	if len(r.completedDays()) != 1 {
		t.Fatal("counts dropped after one failed send")
	}
	if rt := r.retries["2026-10-09/example.com"]; rt.attempts != 1 || !rt.next.Equal(now.Add(retryDelay)) {
		t.Errorf("retry state = %+v", rt)
	}
	for i := 1; i < maxAttempts; i++ {
		now = now.Add(retryDelay)
		r.now = fixedClock(now)
		r.SendDue(context.Background())
	}
	if len(r.completedDays()) != 0 {
		t.Error("report retried past the attempt limit")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "tlsrpt.json")
	r, _ := newTestReporter(t, fakeTXT{}, state)
	r.Record(Session{Policy: stsPolicy, Success: true})
	r.Record(Session{Policy: stsPolicy, ResultType: ResultCertificateExpired})
	if err := r.save(); err != nil {
		t.Fatal(err)
	}

	r2, _ := newTestReporter(t, fakeTXT{}, state)
	dc := r2.take(dayOf(time.Now()), "example.com")
	if dc == nil {
		t.Fatal("counts not restored")
	}
	for _, pc := range dc.Policies {
		if pc.Success != 1 || len(pc.Failures) != 1 {
			t.Errorf("restored counts = %+v", pc)
		}
	}
}

func TestReporterNeedsSender(t *testing.T) {
	if _, err := NewReporter(Config{Hostname: "h"}, nil, nil); err == nil {
		t.Error("reporter started without report_from")
	}
}
