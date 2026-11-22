package mailbox

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/authresult"
	"github.com/EvalAlan/elemta/internal/dmarcrpt"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func testReportXML(domain, id string, count int) []byte {
	begin := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1).Unix()
	return fmt.Appendf(nil, `<?xml version="1.0"?><feedback><report_metadata><org_name>Receiver</org_name><report_id>%s</report_id><date_range><begin>%d</begin><end>%d</end></date_range></report_metadata><policy_published><domain>%s</domain><p>reject</p><pct>100</pct></policy_published><record><row><source_ip>192.0.2.7</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>%s</header_from></identifiers><auth_results><dkim><domain>%s</domain><result>pass</result></dkim><spf><domain>esp.example</domain><result>pass</result></spf></auth_results></record></feedback>`,
		id, begin, begin+86399, domain, count, domain, domain)
}

// testVouched is what the MTA prepends for a sender that passed DMARC.
func testVouched(sender string) string {
	res := authresult.Results{Policy: "reject"}
	res.DMARC.Value, res.DMARC.Domain = "pass", sender
	return "Authentication-Results: " + res.Header("mx.example.net") + "\r\n" + mailpolicy.SenderVerifiedHeader + ": dmarc " + sender + "\r\n"
}

func testReportMail(to, trace string, attachment []byte) string {
	return trace + "From: Reports <reports@receiver.example>\r\nTo: " + to + "\r\nSubject: Report domain\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(attachment) + "\r\n"
}

func testGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testZip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestReportSender(t *testing.T) {
	const from = "From: x@claimed.example\r\n\r\nbody"
	pass := testVouched("receiver.example")
	fail := "Authentication-Results: mx.example.net; dmarc=fail header.from=receiver.example\r\n"
	forged := mailpolicy.SenderVerifiedHeader + ": dmarc receiver.example\r\n"
	for _, c := range []struct {
		name, raw, sender string
		verified          bool
	}{
		{"vouched", pass + from, "receiver.example", true},
		{"nothing", from, "claimed.example", false},
		{"verdict alone", forged + from, "claimed.example", false},
		{"older mail with a forged verdict", fail + forged + from, "claimed.example", false},
		{"forged after the MTA's none", fail + mailpolicy.SenderVerifiedHeader + ": none\r\n" + pass + from, "claimed.example", false},
		{"pass for another domain", "Authentication-Results: mx; dmarc=pass header.from=other.example\r\n" + forged + from, "claimed.example", false},
		{"signed-in user", mailpolicy.SenderVerifiedHeader + ": auth x@claimed.example\r\n" + from, "claimed.example", false},
	} {
		if sender, verified := reportSender([]byte(c.raw)); sender != c.sender || verified != c.verified {
			t.Errorf("%s: %q %v", c.name, sender, verified)
		}
	}
}

func TestDMARCObserveNeverWaits(t *testing.T) {
	in := newDMARCIngest(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	in.addresses["rua@example.com"] = []string{"example.com"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range dmarcQueueItems * 3 {
			in.observe("RUA@example.com", make([]byte, 1<<20)) // nobody is reading
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observe waited for the worker")
	}
	if in.pending > dmarcQueueBytes || len(in.queue) == 0 {
		t.Fatalf("queued %d bytes in %d", in.pending, len(in.queue))
	}
	before := len(in.queue)
	in.observe("someone@example.com", []byte("x"))
	if len(in.queue) != before {
		t.Fatal("queued mail for an unregistered address")
	}
}

type dmarcRig struct {
	*addressingRig
	address string
}

func newDMARCRig(t *testing.T, run bool) *dmarcRig {
	t.Helper()
	r := &dmarcRig{addressingRig: newAddressingRig(t)}
	r.address = r.addr("benny") // an alias, as report addresses often are
	ctx := context.Background()
	if _, err := r.e.SetDMARCAddress(ctx, r.domain, r.address); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.e.DB.Exec(`DELETE FROM mailbox_dmarc_reports WHERE domain=$1`, r.domain)
		_, _ = r.e.DB.Exec(`DELETE FROM mailbox_dmarc_addresses WHERE domain=$1`, r.domain)
	})
	if err := r.svc.dmarc.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if run {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); r.svc.dmarc.run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
	}
	return r
}

func (r *dmarcRig) deliver(id, raw string) {
	r.t.Helper()
	for rcpt, err := range r.send("reports@receiver.example", id, []string{r.address}, raw) {
		if err != nil {
			r.t.Fatalf("%s: %v", rcpt, err)
		}
	}
}

func (r *dmarcRig) totals() (verified, unverified int64) {
	r.t.Helper()
	days, err := r.e.DMARCSummary(context.Background(), []string{r.domain}, time.Now().AddDate(0, 0, -5))
	if err != nil {
		r.t.Fatal(err)
	}
	for _, d := range days {
		if d.Verified {
			verified += d.Messages
		} else {
			unverified += d.Messages
		}
	}
	return
}

func TestDMARCIngestAtDelivery(t *testing.T) {
	r := newDMARCRig(t, true)
	pass := testVouched("receiver.example")
	forged := "Authentication-Results: mx.example.net; dmarc=fail header.from=receiver.example\r\n" + mailpolicy.SenderVerifiedHeader + ": dmarc receiver.example\r\n"
	mails := []string{
		testReportMail(r.address, pass, testReportXML(r.domain, "plain", 1)),
		testReportMail(r.address, pass, testGzip(t, testReportXML(r.domain, "gz", 10))),
		testReportMail(r.address, pass, testZip(t, testReportXML(r.domain, "zip", 100))),
		testReportMail(r.address, pass, testReportXML(r.domain, "plain", 1)), // sent again
		testReportMail(r.address, forged, testReportXML(r.domain, "forged", 1000)),
		// The forgery can't take a real report's place by using its id.
		testReportMail(r.address, forged, testReportXML(r.domain, "after", 2000)),
		testReportMail(r.address, pass, testReportXML(r.domain, "after", 10000)),
		testReportMail(r.address, pass, testGzip(t, bytes.Repeat([]byte(" "), dmarcrpt.MaxReportExpanded+1))),
		testReportMail(r.address, pass, testReportXML("someone-else.example", "foreign", 7)),
		testReportMail(r.address, pass, testReportXML("sub."+r.domain, "sub", 100000)),
	}
	for i, raw := range mails {
		r.deliver(fmt.Sprint("m", i), raw)
	}
	waitFor(t, "the reports to be read", func() bool {
		v, u := r.totals()
		return v == 110111 && u == 3000
	})
	if got := r.inbox("ben"); len(got) != len(mails) {
		t.Fatalf("delivered %d of %d", len(got), len(mails))
	}
	sources, err := r.e.DMARCSources(context.Background(), []string{r.domain}, time.Now().AddDate(0, 0, -5))
	if err != nil || len(sources) == 0 || !sources[0].Verified || sources[0].SourceIP != "192.0.2.7" || sources[0].SPFDomain != "esp.example" || sources[0].DKIMDomain == "" {
		t.Fatalf("sources %+v %v", sources, err)
	}
}

func TestDMARCBrokenParserLeavesDeliveryAlone(t *testing.T) {
	r := newDMARCRig(t, false)
	r.svc.dmarc.parse = func([]byte, time.Time) (*dmarcrpt.Feedback, error) { panic("broken parser") }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.svc.dmarc.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	raw := testReportMail(r.address, testVouched("receiver.example"), testReportXML(r.domain, "x", 1))
	r.deliver("broken", raw)
	if got := r.inbox("ben"); len(got) != 1 || !strings.Contains(got[0], raw[strings.Index(raw, "From: "):]) {
		t.Fatalf("delivery changed: %q", got)
	}
	waitFor(t, "the worker to take it", func() bool {
		r.svc.dmarc.mu.RLock()
		defer r.svc.dmarc.mu.RUnlock()
		return r.svc.dmarc.pending == 0
	})
	if v, u := r.totals(); v+u != 0 {
		t.Fatalf("stored %d %d", v, u)
	}
}

func TestDMARCBackfill(t *testing.T) {
	r := newDMARCRig(t, false)
	ctx := context.Background()
	if err := r.e.DeleteDMARCAddress(ctx, r.domain); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.dmarc.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pass := testVouched("receiver.example")
	r.deliver("old", testReportMail(r.address, pass, testReportXML(r.domain, "old", 5)))
	// Addressed to the account itself, or to a longer name ending the same.
	r.deliver("own", testReportMail(r.addr("ben"), pass, testReportXML(r.domain, "own", 50)))
	r.deliver("longer", testReportMail("x"+r.address, pass, testReportXML(r.domain, "longer", 500)))

	r.svc.adminToken = "test-token"
	call := func(method, path, body string, out any) int {
		t.Helper()
		req := httptest.NewRequest(method, "/v1/admin/dmarc/"+path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		r.svc.http.Handler.ServeHTTP(w, req)
		if out != nil && w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
		return w.Code
	}
	if code := call("POST", "addresses/"+r.domain+"/backfill", "", nil); code != http.StatusNotFound {
		t.Fatalf("backfill of an unregistered domain = %d", code)
	}
	if code := call("PUT", "addresses/"+r.domain, `{"address":"`+strings.ToUpper(r.address)+`"}`, nil); code != http.StatusOK {
		t.Fatalf("register = %d", code)
	}
	run := func() mailpolicy.DMARCAddress {
		t.Helper()
		if code := call("POST", "addresses/"+r.domain+"/backfill", "", nil); code != http.StatusOK {
			t.Fatalf("backfill = %d", code)
		}
		var mine mailpolicy.DMARCAddress
		waitFor(t, "the backfill", func() bool {
			var all []mailpolicy.DMARCAddress
			if call("GET", "addresses", "", &all) != http.StatusOK {
				return false
			}
			for _, a := range all {
				if a.Domain == r.domain {
					mine = a
				}
			}
			return mine.BackfillFinished != nil
		})
		return mine
	}
	before := r.inbox("ben")
	if got := run(); got.BackfillRead != 1 || got.BackfillStored != 1 || got.BackfillError != "" {
		t.Fatalf("first run %+v", got)
	}
	if v, u := r.totals(); v != 5 || u != 0 {
		t.Fatalf("read more than was addressed there: %d %d", v, u)
	}
	if got := run(); got.BackfillRead != 1 || got.BackfillStored != 0 {
		t.Fatalf("second run %+v", got)
	}
	if after := r.inbox("ben"); len(after) != len(before) {
		t.Fatal("backfill changed the mailbox")
	}
	_, msgs, err := r.e.Snapshot(ctx, r.dir.accounts[r.addr("ben")].ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(fmt.Sprint(m.Flags)), "seen") {
			t.Fatal("backfill marked mail read")
		}
	}
	if code := call("GET", "summary?days=401", "", nil); code != http.StatusBadRequest {
		t.Fatalf("days=401 = %d", code)
	}
	if code := call("GET", "summary?days=30&domain="+r.domain, "", nil); code != http.StatusOK {
		t.Fatalf("summary = %d", code)
	}
}

func TestDMARCBackfillGivesASubdomainItsOwn(t *testing.T) {
	r := newDMARCRig(t, false) // no worker: only the backfill reads
	ctx, child := context.Background(), "sub."+r.domain
	r.deliver("child", testReportMail(r.address, testVouched("receiver.example"), testReportXML(child, "child", 9)))
	if _, err := r.e.SetDMARCAddress(ctx, child, r.address); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.e.DB.Exec(`DELETE FROM mailbox_dmarc_reports WHERE domain=$1`, child)
		_, _ = r.e.DB.Exec(`DELETE FROM mailbox_dmarc_addresses WHERE domain=$1`, child)
	})
	if res, err := r.svc.dmarcBackfill(ctx, r.domain, r.address); err != nil || res.stored != 1 {
		t.Fatalf("backfill %+v %v", res, err)
	}
	days, err := r.e.DMARCSummary(ctx, []string{child}, time.Now().AddDate(0, 0, -5))
	if err != nil || len(days) != 1 || days[0].Messages != 9 {
		t.Fatalf("the subdomain's report went to its parent: %+v %v", days, err)
	}
}

func TestDMARCLimitsAndRetention(t *testing.T) {
	r := newDMARCRig(t, false)
	ctx, now := context.Background(), time.Now().UTC()
	put := func(id string, verified bool, age time.Duration) bool {
		t.Helper()
		f, err := dmarcrpt.ParseAttachment(testReportXML(r.domain, id, 1), now)
		if err != nil {
			t.Fatal(err)
		}
		f.ReportMetadata.DateRange.Begin -= int64(age / time.Second)
		f.ReportMetadata.DateRange.End -= int64(age / time.Second)
		ok, err := r.e.storeDMARCReport(ctx, dmarcReport{domain: r.domain, sender: "receiver.example", verified: verified, received: now, feedback: f}, now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for i := range dmarcUnverifiedPerDay {
		if !put(fmt.Sprint("u", i), false, 0) {
			t.Fatalf("refused unverified report %d", i)
		}
	}
	if put("one-too-many", false, 0) {
		t.Fatal("no limit on unverified reports")
	}
	if !put("real", true, 0) {
		t.Fatal("junk crowded out a verified report")
	}
	if put("ancient", true, dmarcKeep+24*time.Hour) {
		t.Fatal("stored a report too old to keep")
	}
	if !put("ageing", true, dmarcKeep-48*time.Hour) {
		t.Fatal("refused a report still worth keeping")
	}
	if err := r.e.deleteOldDMARC(ctx, now.AddDate(0, 0, 3)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := r.e.DB.QueryRow(`SELECT count(*) FROM mailbox_dmarc_reports WHERE domain=$1 AND report_id='ageing'`, r.domain).Scan(&n); err != nil || n != 0 {
		t.Fatalf("not aged out: %d %v", n, err)
	}
}
