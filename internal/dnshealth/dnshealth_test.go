package dnshealth

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

const testDKIM = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB"

// fakeDNS answers from maps. A name absent from every map is NXDOMAIN, which
// is what the checks have to tell apart from servfail.
type fakeDNS struct {
	mx       map[string][]*net.MX
	ip       map[string][]string
	txt      map[string][]string
	ptr      map[string][]string
	srv      map[string][]*net.SRV
	servfail map[string]bool
}

func nx(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) fail(name string) error {
	if f.servfail[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return nil
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if err := f.fail(name); err != nil {
		return nil, err
	}
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, nx(name)
}

func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	name = strings.TrimSuffix(name, ".")
	if err := f.fail(name); err != nil {
		return nil, err
	}
	if r, ok := f.mx[name]; ok {
		return r, nil
	}
	return nil, nx(name)
}

func (f *fakeDNS) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	name = strings.TrimSuffix(name, ".")
	if err := f.fail(name); err != nil {
		return nil, err
	}
	r, ok := f.ip[name]
	if !ok {
		return nil, nx(name)
	}
	out := make([]net.IPAddr, 0, len(r))
	for _, a := range r {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err := f.fail(addr); err != nil {
		return nil, err
	}
	if r, ok := f.ptr[addr]; ok {
		return r, nil
	}
	return nil, nx(addr)
}

func (f *fakeDNS) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	key := "_" + service + "._" + proto + "." + name
	if err := f.fail(key); err != nil {
		return "", nil, err
	}
	if r, ok := f.srv[key]; ok {
		return key, r, nil
	}
	return "", nil, nx(key)
}

// healthy is a domain with nothing wrong, served by mail.host.test. Each test
// breaks one thing, so a failure points at that check alone.
func healthy() *fakeDNS {
	return &fakeDNS{
		mx: map[string][]*net.MX{"example.org": {{Host: "mail.host.test.", Pref: 10}}},
		ip: map[string][]string{"mail.host.test": {"192.0.2.1"}},
		txt: map[string][]string{
			"example.org":                 {"v=spf1 mx -all", "unrelated"},
			"mail._domainkey.example.org": {testDKIM},
			"_dmarc.example.org":          {"v=DMARC1; p=reject; rua=mailto:r@example.org"},
			"_mta-sts.example.org":        {"v=STSv1; id=1"},
			"_smtp._tls.example.org":      {"v=TLSRPTv1; rua=mailto:r@example.org"},
		},
		ptr: map[string][]string{"192.0.2.1": {"mail.host.test."}},
		srv: map[string][]*net.SRV{
			"_imaps._tcp.example.org":      {{Target: "mail.host.test.", Port: 993}},
			"_submission._tcp.example.org": {{Target: "mail.host.test.", Port: 587}},
		},
	}
}

const goodPolicy = "version: STSv1\nmode: enforce\nmx: mail.host.test\nmax_age: 604800\n"

func run(t *testing.T, dns *fakeDNS, edit func(*Options)) Report {
	t.Helper()
	o := Options{
		Domain: "example.org", Hostname: "mail.host.test", Signing: SigningOn, Resolver: dns,
		DKIMKeys:    []DKIMKey{{Name: "mail._domainkey.example.org", Record: testDKIM}},
		FetchMTASTS: func(context.Context, string) (string, error) { return goodPolicy, nil },
	}
	if edit != nil {
		edit(&o)
	}
	return Run(context.Background(), o)
}

func check(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", id, r.Checks)
	return Check{}
}

func want(t *testing.T, r Report, id string, status Status, inSummary string) Check {
	t.Helper()
	c := check(t, r, id)
	if c.Status != status || !strings.Contains(c.Summary, inSummary) {
		t.Fatalf("%s = %s %q, want %s containing %q", id, c.Status, c.Summary, status, inSummary)
	}
	return c
}

func TestHealthyDomain(t *testing.T) {
	r := run(t, healthy(), nil)
	if r.Status != StatusOK {
		t.Fatalf("overall %s: %+v", r.Status, r.Checks)
	}
	for _, c := range r.Checks {
		if c.Status != StatusOK {
			t.Errorf("%s = %s: %s", c.ID, c.Status, c.Summary)
		}
	}
}

func TestMX(t *testing.T) {
	tests := []struct {
		name    string
		break_  func(*fakeDNS)
		status  Status
		summary string
	}{
		{"none", func(d *fakeDNS) { delete(d.mx, "example.org") }, StatusFail, "No MX"},
		{"elsewhere", func(d *fakeDNS) {
			d.mx["example.org"] = []*net.MX{{Host: "other.test.", Pref: 10}}
			d.ip["other.test"] = []string{"203.0.113.9"}
		}, StatusFail, "doesn't point at this server"},
		{"another name for this server", func(d *fakeDNS) {
			d.mx["example.org"] = []*net.MX{{Host: "mail.example.org.", Pref: 10}}
			d.ip["mail.example.org"] = []string{"192.0.2.1"}
		}, StatusOK, "reaches this server"},
		{"backup only", func(d *fakeDNS) {
			d.mx["example.org"] = []*net.MX{{Host: "mail.host.test.", Pref: 20}, {Host: "other.test.", Pref: 10}}
			d.ip["other.test"] = []string{"203.0.113.9"}
		}, StatusWarn, "backup"},
		{"host without address", func(d *fakeDNS) {
			d.mx["example.org"] = append(d.mx["example.org"], &net.MX{Host: "gone.test.", Pref: 20})
		}, StatusWarn, "no address"},
		{"null MX", func(d *fakeDNS) { d.mx["example.org"] = []*net.MX{{Host: ".", Pref: 0}} }, StatusFail, "null MX"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := healthy()
			tt.break_(d)
			want(t, run(t, d, nil), "mx", tt.status, tt.summary)
		})
	}
}

// A resolver hiccup must never read as a missing record, or the advice would
// be to publish what's already there.
func TestDNSFailureIsNeverReportedAsMissing(t *testing.T) {
	for _, tt := range []struct{ name, id string }{
		{"example.org", "mx"},
		{"_dmarc.example.org", "dmarc"},
		{"_mta-sts.example.org", "mta-sts"},
		{"_smtp._tls.example.org", "tls-rpt"},
		{"_imaps._tcp.example.org", "autoconfig"},
	} {
		d := healthy()
		d.servfail = map[string]bool{tt.name: true}
		r := run(t, d, nil)
		c := check(t, r, tt.id)
		if c.Status != StatusUnknown || c.Fix != "" || c.Record != "" {
			t.Errorf("%s with %s failing = %s, fix %q", tt.id, tt.name, c.Status, c.Fix)
		}
		if severity[r.Status] == 0 {
			t.Errorf("overall %s hides a check that couldn't run", r.Status)
		}
	}
}

func TestServerAddressUnknown(t *testing.T) {
	d := healthy()
	d.servfail = map[string]bool{"mail.host.test": true}
	r := run(t, d, nil)
	want(t, r, "mx", StatusUnknown, "no address to compare")
	want(t, r, "spf", StatusUnknown, "no address to test")
	want(t, r, "ptr", StatusUnknown, "no address")
}

func TestReverseDNS(t *testing.T) {
	d := healthy()
	delete(d.ptr, "192.0.2.1")
	c := want(t, run(t, d, nil), "ptr", StatusFail, "matching reverse DNS")
	if !strings.Contains(c.Fix, "mail.host.test") {
		t.Fatalf("fix %q", c.Fix)
	}

	// The name must lead back to the address.
	d = healthy()
	d.ptr["192.0.2.1"] = []string{"forged.test."}
	d.ip["forged.test"] = []string{"203.0.113.9"}
	want(t, run(t, d, nil), "ptr", StatusFail, "matching reverse DNS")

	d = healthy()
	d.ptr["192.0.2.1"] = []string{"li123.members.test."}
	d.ip["li123.members.test"] = []string{"192.0.2.1"}
	want(t, run(t, d, nil), "ptr", StatusWarn, "doesn't match")
}

func TestSPF(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		status  Status
		summary string
	}{
		{"none", []string{"unrelated"}, StatusFail, "No SPF"},
		{"two records", []string{"v=spf1 mx -all", "v=spf1 a -all"}, StatusFail, "More than one"},
		{"anyone may send", []string{"v=spf1 +all"}, StatusFail, "lets anyone"},
		{"bare all", []string{"v=spf1 all"}, StatusFail, "lets anyone"},
		{"excludes this server", []string{"v=spf1 ip4:203.0.113.9 -all"}, StatusFail, "doesn't cover"},
		{"softfail for this server", []string{"v=spf1 ip4:203.0.113.9 ~all"}, StatusWarn, "doesn't cover"},
		{"covers by address", []string{"v=spf1 ip4:192.0.2.1 -all"}, StatusOK, "may send"},
		{"softfail after a match", []string{"v=spf1 mx ~all"}, StatusOK, "may send"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := healthy()
			d.txt["example.org"] = tt.records
			want(t, run(t, d, nil), "spf", tt.status, tt.summary)
		})
	}
}

func TestDKIM(t *testing.T) {
	d := healthy()
	delete(d.txt, "mail._domainkey.example.org")
	c := want(t, run(t, d, nil), "dkim", StatusFail, "isn't published")
	if c.Record != testDKIM {
		t.Fatalf("the fix must give the record to publish, got %q", c.Record)
	}

	d = healthy()
	r := run(t, d, func(o *Options) { o.Signing, o.DKIMKeys = SigningNo, nil })
	want(t, r, "dkim", StatusFail, "No signing key")
	r = run(t, d, func(o *Options) { o.Signing = SigningOff })
	want(t, r, "dkim", StatusWarn, "Signing is off")
	r = run(t, d, func(o *Options) { o.DKIMKeys = []DKIMKey{{Name: "mail._domainkey.example.org"}} })
	want(t, r, "dkim", StatusUnknown, "can't read")
}

func TestDMARC(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		status  Status
		summary string
	}{
		{"none published", nil, StatusWarn, "No DMARC"},
		{"monitor only", []string{"v=DMARC1; p=none"}, StatusWarn, "only monitors"},
		{"partial", []string{"v=DMARC1; p=reject; pct=25"}, StatusWarn, "25%"},
		{"two records", []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, StatusFail, "More than one"},
		{"no policy", []string{"v=DMARC1; rua=mailto:r@example.org"}, StatusFail, "no valid policy"},
		{"quarantine", []string{"v=DMARC1; p=quarantine; rua=mailto:r@example.org"}, StatusOK, "quarantined"},
		{"no reports", []string{"v=DMARC1; p=reject"}, StatusOK, "No reports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := healthy()
			delete(d.txt, "_dmarc.example.org")
			if tt.records != nil {
				d.txt["_dmarc.example.org"] = tt.records
			}
			want(t, run(t, d, nil), "dmarc", tt.status, tt.summary)
		})
	}
}

// A subdomain with no record of its own is covered by its parent's. Calling
// that "no DMARC" would be a false alarm about a protected domain.
func TestDMARCInherited(t *testing.T) {
	sub := func(parent string) Report {
		d := healthy()
		d.mx["dev.example.org"] = d.mx["example.org"]
		d.txt["dev.example.org"] = d.txt["example.org"]
		d.txt["_dmarc.example.org"] = []string{parent}
		return run(t, d, func(o *Options) { o.Domain = "dev.example.org" })
	}
	want(t, sub("v=DMARC1; p=reject; rua=mailto:r@example.org"), "dmarc", StatusOK, "inherited from example.org")
	want(t, sub("v=DMARC1; p=reject; sp=none"), "dmarc", StatusWarn, "only monitors")
	want(t, sub("v=DMARC1; p=none; sp=reject; rua=mailto:r@example.org"), "dmarc", StatusOK, "rejected")
}

func TestMTASTS(t *testing.T) {
	d := healthy()
	delete(d.txt, "_mta-sts.example.org")
	want(t, run(t, d, nil), "mta-sts", StatusInfo, "Optional")

	// Both of these are what the first run against real domains turned up.
	stale := "version: STSv1\nmode: enforce\nmx: mail.old.test\nmax_age: 604800\n"
	r := run(t, healthy(), func(o *Options) {
		o.FetchMTASTS = func(context.Context, string) (string, error) { return stale, nil }
	})
	c := want(t, r, "mta-sts", StatusFail, "refuse to deliver")
	if !strings.Contains(c.Fix, "mail.host.test") || !strings.Contains(c.Fix, "id") {
		t.Fatalf("fix %q", c.Fix)
	}
	r = run(t, healthy(), func(o *Options) {
		o.FetchMTASTS = func(context.Context, string) (string, error) {
			return "", errors.New("x509: certificate is valid for other.test")
		}
	})
	c = want(t, r, "mta-sts", StatusFail, "can't serve it")
	if !strings.Contains(c.Summary, "x509") {
		t.Fatalf("the reason must reach the reader: %q", c.Summary)
	}

	r = run(t, healthy(), func(o *Options) {
		o.FetchMTASTS = func(context.Context, string) (string, error) {
			return strings.Replace(stale, "enforce", "testing", 1), nil
		}
	})
	want(t, r, "mta-sts", StatusWarn, "testing policy")
	r = run(t, healthy(), func(o *Options) {
		o.FetchMTASTS = func(context.Context, string) (string, error) { return "<html>nope</html>", nil }
	})
	want(t, r, "mta-sts", StatusFail, "can't be read")
	r = run(t, healthy(), func(o *Options) {
		o.FetchMTASTS = func(context.Context, string) (string, error) {
			return "version: STSv1\nmode: enforce\nmx: *.host.test\nmax_age: 86400\n", nil
		}
	})
	want(t, r, "mta-sts", StatusOK, "every MX")
}

func TestOptionalChecksNeverFailADomain(t *testing.T) {
	d := healthy()
	delete(d.txt, "_mta-sts.example.org")
	delete(d.txt, "_smtp._tls.example.org")
	d.srv = nil
	r := run(t, d, nil)
	if r.Status != StatusOK {
		t.Fatalf("overall %s, optional records can't make a domain unhealthy", r.Status)
	}
	want(t, r, "tls-rpt", StatusInfo, "Optional")
	want(t, r, "autoconfig", StatusInfo, "Optional")
}

func TestOverallIsTheWorst(t *testing.T) {
	d := healthy()
	delete(d.txt, "_dmarc.example.org")
	if r := run(t, d, nil); r.Status != StatusWarn {
		t.Fatalf("overall %s", r.Status)
	}
	delete(d.mx, "example.org")
	if r := run(t, d, nil); r.Status != StatusFail {
		t.Fatalf("overall %s", r.Status)
	}
}
