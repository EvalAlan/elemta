package dnshealth

import (
	"context"
	"strings"
	"testing"
)

func TestDMARCReportAuthorization(t *testing.T) {
	with := func(record string, extra map[string][]string) Report {
		d := healthy()
		d.txt["_dmarc.example.org"] = []string{record}
		for k, v := range extra {
			d.txt[k] = v
		}
		return run(t, d, nil)
	}
	const external = "v=DMARC1; p=reject; rua=mailto:dmarc@example.net!10m"
	const name = "example.org._report._dmarc.example.net"

	r := with(external, nil)
	want(t, r, "dmarc-reports", StatusWarn, "won't send")
	if c := check(t, r, "dmarc-reports"); c.Record != "v=DMARC1" || c.Fix != "Publish this TXT record at "+name+"." {
		t.Fatalf("what to publish: %+v", c)
	}
	want(t, with(external, map[string][]string{name: {"v=DMARC1"}}), "dmarc-reports", StatusOK, "can send")
	// The same organization needs no record.
	want(t, with("v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.org", nil), "dmarc-reports", StatusOK, "can send")
	want(t, with("v=DMARC1; p=reject", nil), "dmarc-reports", StatusInfo, "No DMARC reports")
}

// An inherited record's authorization is published under the domain that
// has the record, not the subdomain it covers.
func TestLookupDMARC(t *testing.T) {
	d := healthy()
	d.txt["_dmarc.example.org"] = []string{"v=DMARC1; p=reject; sp=quarantine; rua=mailto:A@Example.net, https://x.example/r"}
	p, err := LookupDMARC(context.Background(), d, "dev.example.org")
	if err != nil || p.From != "example.org" || p.Policy != "quarantine" || len(p.Reports) != 1 || p.Reports[0] != "a@example.net" {
		t.Fatalf("%+v %v", p, err)
	}
}

// The denniston.us record as it was published on 2026-11-23: no ';' after
// either address. Receivers read the whole tail as rua's value, so no
// reports are sent. The checker took everything after the '@' as the report
// domain and asked for an authorization record at
// "denniston.us._report._dmarc.denniston.us ruf=mailto:... pct=100".
const runTogether = "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:dmarc-feedback@example.org ruf=mailto:dmarc-feedback@example.org pct=100"

func TestDMARCRecordMissingSeparators(t *testing.T) {
	d := healthy()
	d.txt["_dmarc.example.org"] = []string{runTogether}
	r := run(t, d, nil)

	c := want(t, r, "dmarc", StatusWarn, "no ';' before ruf, pct")
	const fixed = "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:dmarc-feedback@example.org; ruf=mailto:dmarc-feedback@example.org; pct=100"
	if c.Record != fixed || c.Fix != "Replace the TXT record at _dmarc.example.org with this one." {
		t.Fatalf("repair: %+v", c)
	}

	c = want(t, r, "dmarc-reports", StatusWarn, "isn't a usable mail address")
	if strings.Contains(c.Fix, "_report._dmarc") || c.Record != "" {
		t.Fatalf("asked for an authorization record for a malformed address: %+v", c)
	}

	// Once repaired, nothing is wrong: the addresses are the record's own.
	d.txt["_dmarc.example.org"] = []string{fixed}
	r = run(t, d, nil)
	want(t, r, "dmarc", StatusOK, "rejected")
	want(t, r, "dmarc-reports", StatusOK, "can send")
}

func TestDMARCRunTogether(t *testing.T) {
	for record, want := range map[string]string{
		"v=DMARC1; p=reject":                            "",
		"v=DMARC1;p=reject;rua=mailto:a@example.org":    "",
		"v=DMARC1; p=reject sp=none":                    "sp",
		"v=DMARC1; p=reject; RUA=mailto:a@x.org PCT=50": "pct",
		// A space before the '=' is still a tag.
		"v=DMARC1; p=quarantine; rua=mailto:a@x.org fo =1": "fo",
	} {
		tags, _ := dmarcRunTogether(record)
		if got := strings.Join(tags, ","); got != want {
			t.Errorf("%q: %q, want %q", record, got, want)
		}
	}
}

func TestLookupDMARCKeepsOnlyUsableAddresses(t *testing.T) {
	d := healthy()
	d.txt["_dmarc.example.org"] = []string{runTogether}
	p, err := LookupDMARC(context.Background(), d, "example.org")
	if err != nil || len(p.Reports) != 0 || len(p.Malformed) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	for host, ok := range map[string]bool{
		"example.org": true, "mail-1.example.org": true, "EXAMPLE.ORG": true,
		"": false, "exa mple.org": false, "example.org=x": false, "-bad.org": false, "a..org": false,
		"example.org ruf=mailto:x@example.org pct=100": false,
	} {
		if isHostname(host) != ok {
			t.Errorf("isHostname(%q) = %v, want %v", host, !ok, ok)
		}
	}
}
