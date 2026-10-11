package dmarcrpt

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var examplePolicy = Policy{
	Domain: "example.com", P: "reject", SP: "quarantine", Pct: 100, ADKIM: "r", ASPF: "s",
	RUA: []string{"mailto:dmarc-rua@example.com"},
}

func eval(ip string, dkimOK, spfOK bool, disposition string) Evaluation {
	e := Evaluation{
		SourceIP:     ip,
		HeaderFrom:   "example.com",
		EnvelopeFrom: "example.com",
		Policy:       examplePolicy,
		Disposition:  disposition,
		DKIMAligned:  dkimOK,
		SPFAligned:   spfOK,
		DKIM:         []DKIMAuth{{Domain: "example.com", Selector: "s1", Result: passFail(dkimOK)}},
		SPF:          SPFAuth{Domain: "example.com", Result: passFail(spfOK)},
	}
	if disposition == "none" && !dkimOK && !spfOK {
		e.OverrideReason = "local_policy"
	}
	return e
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

var day1 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// The report is what receivers' parsers see, so its exact shape is pinned.
func TestReportXMLGolden(t *testing.T) {
	c := NewCounter()
	c.now = fixedClock(day1)
	for i := 0; i < 3; i++ {
		c.Record(eval("192.0.2.1", true, true, "none"))
	}
	c.Record(eval("198.51.100.7", false, false, "none"))
	unsigned := eval("2001:db8::25", false, true, "none")
	unsigned.DKIM = nil
	c.Record(unsigned)

	f, err := buildReport("2026-10-09", "example.com", c.take("2026-10-09", "example.com"), "Receiver Org", "dmarc@receiver.test", "mx.receiver.test")
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalXML(f)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "report.golden.xml")
	if *update {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("report XML differs from %s (run with -update to accept):\n%s", golden, got)
	}
	var back Feedback
	if err := xml.Unmarshal(got, &back); err != nil {
		t.Fatalf("report does not parse back: %v", err)
	}
}

func TestRecordGroupsBySourceDispositionAndResults(t *testing.T) {
	c := NewCounter()
	c.now = fixedClock(day1)
	c.Record(eval("192.0.2.1", true, true, "none"))
	c.Record(eval("192.0.2.1", true, true, "none"))
	c.Record(eval("192.0.2.1", true, false, "none"))    // different SPF result
	c.Record(eval("192.0.2.1", false, false, "reject")) // different disposition
	c.Record(eval("192.0.2.2", true, true, "none"))     // different source
	upper := eval("192.0.2.1", true, true, "none")      // same row, spelled differently
	upper.Policy.Domain = "EXAMPLE.com."
	c.Record(upper)

	noRUA := eval("192.0.2.1", true, true, "none")
	noRUA.Policy.Domain, noRUA.Policy.RUA = "quiet.test", nil
	c.Record(noRUA)
	httpsOnly := eval("192.0.2.1", true, true, "none")
	httpsOnly.Policy.Domain, httpsOnly.Policy.RUA = "web.test", []string{"https://r.web.test/"}
	c.Record(httpsOnly)

	if got := c.domainsFor("2026-10-09"); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("domains = %v, want only example.com (others ask for no mailto reports)", got)
	}
	dc := c.take("2026-10-09", "example.com")
	if len(dc.Rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(dc.Rows))
	}
	f, err := buildReport("2026-10-09", "example.com", dc, "o", "c", "h")
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, r := range f.Records {
		total += r.Row.Count
		if r.Row.SourceIP == "192.0.2.1" && r.Row.PolicyEvaluated.DKIM == "pass" && r.Row.PolicyEvaluated.SPF == "pass" && r.Row.Count != 3 {
			t.Errorf("matching evaluations were not counted together: %+v", r.Row)
		}
	}
	if total != 6 {
		t.Errorf("total count = %d, want 6", total)
	}
}

func TestRowsAreBounded(t *testing.T) {
	c := NewCounter()
	c.now = fixedClock(day1)
	for i := 0; i < maxRows+25; i++ {
		c.Record(eval(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String(), true, true, "none"))
	}
	c.Record(eval("10.0.0.0", true, true, "none")) // an existing row still counts
	dc := c.take("2026-10-09", "example.com")
	if len(dc.Rows) != maxRows || dc.Overflow != 25 {
		t.Fatalf("rows = %d overflow = %d, want %d and 25", len(dc.Rows), dc.Overflow, maxRows)
	}
	if dc.Rows[eval("10.0.0.0", true, true, "none").row().key()].Count != 2 {
		t.Error("an existing row stopped counting once the limit was hit")
	}
	f, _ := buildReport("2026-10-09", "example.com", dc, "o", "c", "h")
	if len(f.ReportMetadata.Errors) != 1 || !strings.HasPrefix(f.ReportMetadata.Errors[0], "25 messages not itemised") {
		t.Errorf("report does not say what was left out: %v", f.ReportMetadata.Errors)
	}
}

// row builds the row an evaluation would land in, for looking it up.
func (e Evaluation) row() *row {
	return &row{
		SourceIP: e.SourceIP, Disposition: e.Disposition, DKIM: passFail(e.DKIMAligned), SPF: passFail(e.SPFAligned),
		Reason: e.OverrideReason, HeaderFrom: e.HeaderFrom, EnvelopeFrom: e.EnvelopeFrom, DKIMAuth: e.DKIM, SPFAuth: e.SPF,
	}
}

func TestParseRUA(t *testing.T) {
	got := parseRUA([]string{
		"mailto:a@example.com",
		"MAILTO:b@reports.test!10m",
		"mailto:c@example.com!50k",
		"mailto:d%40example.com",
		"mailto:e@example.com!bogus",
		"mailto:f@example.com%0d%0aBcc:x@y",
		"https://example.com/rua",
		"mailto:nobody",
	})
	want := []destination{
		{"a@example.com", "example.com", 0},
		{"b@reports.test", "reports.test", 10 << 20},
		{"c@example.com", "example.com", 50 << 10},
		{"d@example.com", "example.com", 0},
	}
	if len(got) != len(want) {
		t.Fatalf("parseRUA = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

type fakeTXT struct {
	zone    map[string][]string
	failing map[string]bool
	queries []string
}

func (f *fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.queries = append(f.queries, name)
	if f.failing[name] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	if v, ok := f.zone[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type enqueued struct {
	id, from, subject string
	to                []string
	content           []byte
}

func newTestReporter(t *testing.T, txt *fakeTXT, stateFile string) (*Reporter, *[]enqueued) {
	t.Helper()
	var mu sync.Mutex
	var got []enqueued
	r, err := NewReporter(Config{OrganizationName: "Receiver Org", Hostname: "mx.receiver.test", From: "dmarc@receiver.test", StateFile: stateFile},
		func(id, from string, to []string, subject string, content []byte) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, enqueued{id, from, subject, to, content})
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if txt == nil {
		txt = &fakeTXT{}
	}
	r.resolver = txt
	return r, &got
}

func TestSendDueMailsReportAfterDayRollover(t *testing.T) {
	r, got := newTestReporter(t, nil, "")
	r.now = fixedClock(day1)
	r.Record(eval("192.0.2.1", true, true, "none"))
	r.Record(eval("192.0.2.1", true, true, "none"))

	r.SendDue(context.Background())
	if len(*got) != 0 {
		t.Fatal("report sent before the day ended")
	}

	r.now = fixedClock(day1.Add(12 * time.Hour))
	r.SendDue(context.Background())
	if len(*got) != 1 {
		t.Fatalf("reports enqueued = %d, want 1", len(*got))
	}
	m := (*got)[0]
	if m.from != "dmarc@receiver.test" || len(m.to) != 1 || m.to[0] != "dmarc-rua@example.com" {
		t.Errorf("envelope = %s -> %v", m.from, m.to)
	}
	if m.subject != "Report Domain: example.com Submitter: mx.receiver.test Report-ID: <2026-10-09_example.com@mx.receiver.test>" {
		t.Errorf("subject = %q", m.subject)
	}
	msg := string(m.content)
	for _, want := range []string{
		"Subject: " + m.subject + "\r\n",
		"Content-Type: application/gzip",
		`filename="mx.receiver.test!example.com!1791504000!1791590399.xml.gz"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("report email lacks %q", want)
		}
	}
	f := decodeAttachment(t, msg)
	if len(f.Records) != 1 || f.Records[0].Row.Count != 2 || f.ReportMetadata.OrgName != "Receiver Org" {
		t.Errorf("attached report = %+v", f)
	}
	if f.ReportMetadata.Email != "dmarc@receiver.test" {
		t.Errorf("contact email = %q, want report_from by default", f.ReportMetadata.Email)
	}
	if len(r.completedDays()) != 0 {
		t.Error("the sent day was not cleared")
	}

	// The next day's mail is a separate report.
	r.Record(eval("192.0.2.9", true, true, "none"))
	r.SendDue(context.Background())
	if len(*got) != 1 {
		t.Error("the current day was reported before it ended")
	}
}

func decodeAttachment(t *testing.T, msg string) Feedback {
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
	doc, _ := io.ReadAll(zr)
	var f Feedback
	if err := xml.Unmarshal(doc, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// RFC 7489 §7.1: a rua outside the policy domain's organisation is used only
// once that destination has published consent.
func TestExternalDestinationVerification(t *testing.T) {
	policy := examplePolicy
	policy.RUA = []string{
		"mailto:in-house@reports.example.com", // same organisational domain
		"mailto:dmarc@vendor.test",            // external, consents
		"mailto:dmarc@victim.test",            // external, never asked
	}
	txt := &fakeTXT{zone: map[string][]string{
		"example.com._report._dmarc.vendor.test": {"v=DMARC1"},
		"example.com._report._dmarc.victim.test": {"v=spf1 -all"},
	}}
	r, got := newTestReporter(t, txt, "")
	r.now = fixedClock(day1)
	e := eval("192.0.2.1", true, true, "none")
	e.Policy = policy
	r.Record(e)
	r.now = fixedClock(day1.Add(24 * time.Hour))
	r.SendDue(context.Background())

	if len(*got) != 1 {
		t.Fatalf("reports enqueued = %d", len(*got))
	}
	if to := strings.Join((*got)[0].to, ","); to != "in-house@reports.example.com,dmarc@vendor.test" {
		t.Errorf("recipients = %s", to)
	}
	for _, q := range txt.queries {
		if strings.HasSuffix(q, "reports.example.com") {
			t.Errorf("looked up %s for a destination inside the policy domain's organisation", q)
		}
	}
}

// A destination nobody has authorised gets nothing, and that is final.
func TestUnverifiedOnlyDestinationIsDropped(t *testing.T) {
	r, got := newTestReporter(t, &fakeTXT{}, "")
	r.now = fixedClock(day1)
	e := eval("192.0.2.1", true, true, "none")
	e.Policy.RUA = []string{"mailto:dmarc@victim.test"}
	r.Record(e)
	r.now = fixedClock(day1.Add(24 * time.Hour))
	r.SendDue(context.Background())
	if len(*got) != 0 {
		t.Error("report sent to an unverified external destination")
	}
	if len(r.completedDays()) != 0 || len(r.retries) != 0 {
		t.Error("a refused destination was queued for retry")
	}
}

// A verification lookup that fails is retried rather than taken as refusal.
func TestVerificationLookupFailureRetries(t *testing.T) {
	txt := &fakeTXT{failing: map[string]bool{"example.com._report._dmarc.vendor.test": true}}
	r, got := newTestReporter(t, txt, "")
	r.now = fixedClock(day1)
	e := eval("192.0.2.1", true, true, "none")
	e.Policy.RUA = []string{"mailto:dmarc@vendor.test"}
	r.Record(e)
	now := day1.Add(24 * time.Hour)
	r.now = fixedClock(now)
	r.SendDue(context.Background())
	if len(*got) != 0 || len(r.completedDays()) != 1 {
		t.Fatal("counts dropped after a failed lookup")
	}
	txt.failing = nil
	txt.zone = map[string][]string{"example.com._report._dmarc.vendor.test": {"v=DMARC1;"}}
	r.now = fixedClock(now.Add(retryDelay))
	r.SendDue(context.Background())
	if len(*got) != 1 {
		t.Error("report not sent once the lookup recovered")
	}
}

func TestSizeLimitIsHonoured(t *testing.T) {
	r, got := newTestReporter(t, nil, "")
	r.now = fixedClock(day1)
	e := eval("192.0.2.1", true, true, "none")
	e.Policy.RUA = []string{"mailto:tiny@example.com!100", "mailto:big@example.com!1m"}
	r.Record(e)
	r.now = fixedClock(day1.Add(24 * time.Hour))
	r.SendDue(context.Background())
	if len(*got) != 1 || strings.Join((*got)[0].to, ",") != "big@example.com" {
		t.Fatalf("enqueued = %+v, want only the destination whose limit fits", *got)
	}
	if strings.Contains(string((*got)[0].content), "tiny@example.com") {
		t.Error("the message still names the destination it was not sent to")
	}
}

// The same counts produce the same bytes and queue ID, so a report
// re-enqueued after a crash is recognised as the one already queued.
func TestReportEmailIsDeterministic(t *testing.T) {
	build := func() enqueued {
		r, got := newTestReporter(t, nil, "")
		r.now = fixedClock(day1)
		r.Record(eval("192.0.2.1", true, true, "none"))
		r.Record(eval("192.0.2.2", false, true, "none"))
		r.now = fixedClock(day1.Add(24 * time.Hour))
		r.SendDue(context.Background())
		return (*got)[0]
	}
	a, b := build(), build()
	if a.id != b.id || !bytes.Equal(a.content, b.content) {
		t.Error("report email differs between identical runs")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "dmarc.json")
	r, _ := newTestReporter(t, nil, state)
	r.now = fixedClock(day1)
	r.Record(eval("192.0.2.1", true, true, "none"))
	r.Record(eval("192.0.2.1", true, true, "none"))
	if err := r.save(); err != nil {
		t.Fatal(err)
	}

	r2, got := newTestReporter(t, nil, state)
	r2.now = fixedClock(day1.Add(24 * time.Hour))
	r2.SendDue(context.Background())
	if len(*got) != 1 {
		t.Fatal("restored counts were not reported")
	}
	if f := decodeAttachment(t, string((*got)[0].content)); f.Records[0].Row.Count != 2 {
		t.Errorf("restored count = %d, want 2", f.Records[0].Row.Count)
	}
}

func TestCorruptStateIsIgnored(t *testing.T) {
	state := filepath.Join(t.TempDir(), "dmarc.json")
	if err := os.WriteFile(state, []byte(`{"days":{"2026-10-09":{"example.com":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReporter(Config{From: "d@r.test", StateFile: state}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte(`{"days":{"2026-10-09":{"example.com":null}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewReporter(Config{From: "d@r.test", StateFile: state}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.resolver = &fakeTXT{}
	r.SendDue(context.Background()) // must not panic on the null entry
}

func TestReporterNeedsSender(t *testing.T) {
	if _, err := NewReporter(Config{Hostname: "h"}, nil, nil); err == nil {
		t.Error("reporter started without report_from")
	}
}

func TestEnqueueFailureRetries(t *testing.T) {
	r, err := NewReporter(Config{Hostname: "h", From: "d@h"}, func(string, string, []string, string, []byte) error {
		return errors.New("queue full")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.resolver = &fakeTXT{}
	r.now = fixedClock(day1)
	r.Record(eval("192.0.2.1", true, true, "none"))
	r.now = fixedClock(day1.Add(24 * time.Hour))
	r.SendDue(context.Background())
	if len(r.completedDays()) != 1 || r.retries["2026-10-09/example.com"].attempts != 1 {
		t.Error("a failed enqueue lost the counts")
	}
}
