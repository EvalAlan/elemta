package dnshealth

import (
	"context"
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
