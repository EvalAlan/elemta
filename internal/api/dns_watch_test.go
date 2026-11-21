package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/dnshealth"
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
	if st := s.loadDNSWatch(); len(st) != 0 {
		t.Fatalf("fresh state: %v", st)
	}
	s.saveDNSWatch(dnsWatchState{"a.example": {"spf"}})
	st := s.loadDNSWatch()
	if _, n := dnsChanges(st, []dnshealth.Report{dnsReport("a.example", map[string]dnshealth.Status{"spf": dnshealth.StatusFail})}); len(n) != 0 {
		t.Fatalf("problem known before the restart alerted again: %+v", n)
	}
}
