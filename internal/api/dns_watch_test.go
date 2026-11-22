package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/miekg/dns"
)

func dnsReport(domain string, statuses map[string]dnshealth.Status) dnshealth.Report {
	r := dnshealth.Report{Domain: domain, Hostname: "mail.example.net"}
	for _, id := range []string{"mx", "spf", "dkim", "dmarc"} {
		st := statuses[id]
		if st == "" {
			st = dnshealth.StatusOK
		}
		r.Checks = append(r.Checks, dnshealth.Check{ID: id, Name: strings.ToUpper(id), Status: st, Summary: id + " " + string(st), Fix: "fix " + id, Record: "record " + id})
	}
	return r
}

func TestDNSWatchChanges(t *testing.T) {
	const W, F, U, I = dnshealth.StatusWarn, dnshealth.StatusFail, dnshealth.StatusUnknown, dnshealth.StatusInfo
	state := dnsWatchState{}
	sweep := func(reports ...dnshealth.Report) []dnsNotice {
		t.Helper()
		var n []dnsNotice
		state, n = dnsChanges(state, reports)
		return n
	}

	if n := sweep(dnsReport("a.example", nil), dnsReport("b.example", map[string]dnshealth.Status{"dmarc": I})); len(n) != 0 {
		t.Fatalf("clean domains alerted: %+v", n)
	}
	n := sweep(dnsReport("a.example", map[string]dnshealth.Status{"spf": F}), dnsReport("b.example", nil))
	if len(n) != 1 || n[0].subject != "DNS problem for a.example" || !strings.Contains(n[0].body, "SPF: spf fail") || !strings.Contains(n[0].body, "Record: record spf") || strings.Contains(n[0].body, "DKIM") {
		t.Fatalf("new SPF failure: %+v", n)
	}
	// The same problem again is not news, and neither is DNS not answering.
	if n := sweep(dnsReport("a.example", map[string]dnshealth.Status{"spf": U}), dnsReport("b.example", nil)); len(n) != 0 {
		t.Fatalf("repeat or unknown alerted: %+v", n)
	}
	if n := sweep(dnsReport("a.example", map[string]dnshealth.Status{"spf": F, "dkim": U}), dnsReport("b.example", map[string]dnshealth.Status{"dkim": U})); len(n) != 0 {
		t.Fatalf("unknown raised a problem: %+v", n)
	}
	// A second problem is news, and the email lists both.
	n = sweep(dnsReport("a.example", map[string]dnshealth.Status{"spf": F, "dkim": W}), dnsReport("b.example", nil))
	if len(n) != 1 || !strings.Contains(n[0].body, "SPF") || !strings.Contains(n[0].body, "DKIM") {
		t.Fatalf("second problem: %+v", n)
	}
	// One of two fixed: still bad, nothing to say.
	if n := sweep(dnsReport("a.example", map[string]dnshealth.Status{"dkim": W}), dnsReport("b.example", nil)); len(n) != 0 {
		t.Fatalf("partial fix alerted: %+v", n)
	}
	n = sweep(dnsReport("a.example", nil), dnsReport("b.example", nil))
	if len(n) != 1 || !strings.Contains(n[0].subject, "healthy again") {
		t.Fatalf("recovery: %+v", n)
	}
	// A domain no longer hosted is dropped.
	sweep(dnsReport("b.example", nil))
	if _, ok := state["a.example"]; ok {
		t.Fatal("removed domain kept")
	}
}

// What the last sweep saw survives a restart, so a deploy doesn't repeat it.
func TestDNSWatchStatePersists(t *testing.T) {
	s := &Server{configPath: filepath.Join(t.TempDir(), "elemta.toml")}
	if f := s.loadDNSWatch(); len(f.Domains) != 0 || !f.Checked.IsZero() {
		t.Fatalf("fresh state: %+v", f)
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	reports := []dnshealth.Report{dnsReport("a.example", map[string]dnshealth.Status{"spf": dnshealth.StatusFail})}
	next, _ := dnsChanges(dnsWatchState{}, reports)
	s.saveDNSWatch(recordSweep(dnsWatchFile{}, next, reports, now))
	f := s.loadDNSWatch()
	if !f.Checked.Equal(now) || len(f.Domains["a.example"].Checks) != 1 || f.Domains["a.example"].Checks[0].Summary != "spf fail" {
		t.Fatalf("saved sweep: %+v", f)
	}
	if _, n := dnsChanges(f.state(), reports); len(n) != 0 {
		t.Fatalf("problem known before the restart alerted again: %+v", n)
	}
}

// The file the previous version wrote, problem IDs only, still stops repeat
// alerts after the upgrade.
func TestDNSWatchReadsOldState(t *testing.T) {
	s := &Server{configPath: filepath.Join(t.TempDir(), "elemta.toml")}
	if err := os.WriteFile(s.dnsWatchPath(), []byte(`{"a.example":["spf"],"b.example":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := s.loadDNSWatch()
	if !f.Checked.IsZero() || len(f.Domains) != 2 {
		t.Fatalf("old state: %+v", f)
	}
	if _, n := dnsChanges(f.state(), []dnshealth.Report{dnsReport("a.example", map[string]dnshealth.Status{"spf": dnshealth.StatusFail}), dnsReport("b.example", nil)}); len(n) != 0 {
		t.Fatalf("upgrade repeated an alert: %+v", n)
	}
}

func TestDNSWatchRecordsSince(t *testing.T) {
	t1 := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	t2, t3 := t1.Add(6*time.Hour), t1.Add(12*time.Hour)
	step := func(prev dnsWatchFile, now time.Time, reports ...dnshealth.Report) dnsWatchFile {
		next, _ := dnsChanges(prev.state(), reports)
		return recordSweep(prev, next, reports, now)
	}
	f := step(dnsWatchFile{}, t1, dnsReport("a.example", map[string]dnshealth.Status{"spf": dnshealth.StatusFail}), dnsReport("b.example", nil))
	if a := f.Domains["a.example"]; a.Since == nil || !a.Since.Equal(t1) {
		t.Fatalf("first problem: %+v", a)
	}
	if b := f.Domains["b.example"]; b.Since != nil || len(b.Checks) != 0 {
		t.Fatalf("clean domain: %+v", b)
	}
	// Still bad, and DNS didn't answer this time: the time it started and
	// what it said are kept.
	f = step(f, t2, dnsReport("a.example", map[string]dnshealth.Status{"spf": dnshealth.StatusUnknown}))
	if a := f.Domains["a.example"]; !a.Since.Equal(t1) || len(a.Checks) != 1 || a.Checks[0].Status != dnshealth.StatusFail {
		t.Fatalf("carried problem: %+v", a)
	}
	f = step(f, t3, dnsReport("a.example", nil))
	if a := f.Domains["a.example"]; a.Since != nil || len(a.Problems) != 0 {
		t.Fatalf("fixed: %+v", a)
	}
}

func TestDNSHealthStatus(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	s := &Server{configPath: filepath.Join(t.TempDir(), "elemta.toml")}
	all := func(string) bool { return true }
	if st := s.dnsHealthStatus(now, all); st.Status != "unknown" || !strings.Contains(st.Message, "mail administration") {
		t.Fatalf("no provisioner: %+v", st)
	}
	s.provisioner = &provision.Service{}
	if st := s.dnsHealthStatus(now, all); st.Status != "unknown" || !strings.Contains(st.Message, "Not checked yet") {
		t.Fatalf("before the first sweep: %+v", st)
	}
	reports := []dnshealth.Report{
		dnsReport("a.example", nil),
		dnsReport("b.example", map[string]dnshealth.Status{"dmarc": dnshealth.StatusWarn}),
		dnsReport("c.example", map[string]dnshealth.Status{"dkim": dnshealth.StatusWarn, "mx": dnshealth.StatusFail}),
	}
	next, _ := dnsChanges(dnsWatchState{}, reports)
	s.saveDNSWatch(recordSweep(dnsWatchFile{}, next, reports, now.Add(-time.Hour)))

	st := s.dnsHealthStatus(now, all)
	if st.Status != "warning" || st.Message != "2 domains have DNS problems." || len(st.Domains) != 3 {
		t.Fatalf("status: %+v", st)
	}
	got := []string{}
	for _, d := range st.Domains {
		got = append(got, d.Domain+"="+d.Status)
	}
	if strings.Join(got, " ") != "c.example=critical b.example=warning a.example=ok" {
		t.Fatalf("order and status: %v", got)
	}
	if c := st.Domains[0]; len(c.Problems) != 2 || c.Since == "" || c.Problems[0].Fix == "" {
		t.Fatalf("problem details: %+v", c)
	}

	// A domain administrator sees only their own domains.
	st = s.dnsHealthStatus(now, func(d string) bool { return d == "a.example" })
	if st.Status != "ok" || len(st.Domains) != 1 || st.Domains[0].Domain != "a.example" {
		t.Fatalf("scoped: %+v", st)
	}

	if st := s.dnsHealthStatus(now.Add(dnsWatchStale+time.Hour), all); st.Status != "warning" || !strings.Contains(st.Message, "hasn't run since") {
		t.Fatalf("stale: %+v", st)
	}
}

// Inside Compose, Docker's DNS answers for the MTA's alias, the mail domain,
// and says it has no MX. The override asks a real resolver instead.
func TestDNSCheckResolverOverride(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeMX {
			m.Answer = append(m.Answer, &dns.MX{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mx.example.net."})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	t.Setenv("ELEMTA_DNS_CHECK_RESOLVER", pc.LocalAddr().String())
	r, ok := newDNSCheckResolver().(*net.Resolver)
	if !ok {
		t.Fatal("no resolver override")
	}
	mx, err := r.LookupMX(context.Background(), "example.org")
	if err != nil || len(mx) != 1 || mx[0].Host != "mx.example.net." {
		t.Fatalf("lookup through the override: %v %v", mx, err)
	}
}

// The Health page's DNS card is mail administration: a dashboard viewer
// without it gets nothing, an administrator gets the last sweep.
func TestDNSHealthStatusRoute(t *testing.T) {
	base, _ := startProvisionAPIWith(t, func(s *Server) {
		reports := []dnshealth.Report{dnsReport("example.com", map[string]dnshealth.Status{"spf": dnshealth.StatusFail})}
		next, _ := dnsChanges(dnsWatchState{}, reports)
		s.saveDNSWatch(recordSweep(dnsWatchFile{}, next, reports, time.Now().UTC()))
	})
	code, _ := userRequest(t, "GET", base+"/api/provision/dns-health/status", "viewer", testUserPassword, nil)
	if code != http.StatusForbidden {
		t.Fatalf("viewer got %d", code)
	}
	code, body := userRequest(t, "GET", base+"/api/provision/dns-health/status", "root", testAdminPassword, nil)
	if code != http.StatusOK || !strings.Contains(body, `"domain":"example.com"`) || !strings.Contains(body, `"status":"critical"`) || !strings.Contains(body, "spf fail") {
		t.Fatalf("admin got %d %s", code, body)
	}
}
