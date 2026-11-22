package api

import (
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/stretchr/testify/require"
)

func reportInputs(policy string, reportDays int) dmarcInputs {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	in := dmarcInputs{domains: []string{"example.com"}, window: 30, now: now, ours: map[string]bool{"192.0.2.1": true},
		hosted:   func(d string) bool { return d == "example.com" },
		policies: map[string]dnshealth.DMARCPolicy{"example.com": {From: "example.com", Policy: policy, Reports: []string{"r@elsewhere.example", "rua@example.com"}}}}
	for i := range reportDays {
		in.days = append(in.days, mailpolicy.DMARCDay{Domain: "example.com", PolicyDomain: "example.com", Day: now.AddDate(0, 0, -i-1).Format("2006-01-02"),
			Sender: "receiver.example", Verified: true, P: policy, Reports: 1, Messages: 10, Aligned: 8})
	}
	src := func(ip, dkim, spf, signer string, verified bool) mailpolicy.DMARCSource {
		return mailpolicy.DMARCSource{Domain: "example.com", SourceIP: ip, DKIM: dkim, SPF: spf, DKIMDomain: signer, Verified: verified, Messages: 5}
	}
	in.sources = []mailpolicy.DMARCSource{
		src("192.0.2.1", "pass", "pass", "example.com", true),
		src("198.51.100.2", "fail", "pass", "", true),
		src("198.51.100.3", "pass", "fail", "example.com", true),
		src("203.0.113.9", "fail", "fail", "spammer.example", true), // plain forgery
		src("203.0.113.66", "fail", "fail", "example.com", false),   // only claimed
	}
	return in
}

func TestDMARCReportView(t *testing.T) {
	in := reportInputs("reject", 20)
	in.days = append(in.days, mailpolicy.DMARCDay{Domain: "example.com", Day: "2026-06-29", Sender: "claimed.example", Reports: 1, Messages: 99999})
	v := buildDMARCReport(in)[0]
	require.Equal(t, int64(200), v.Messages, "unverified reports in the totals")
	require.Equal(t, int64(160), v.Aligned)
	require.Equal(t, "2026-06-29", v.LastDay)
	require.Equal(t, "rua@example.com", v.Suggest, "only an address hosted here")
	require.Len(t, v.Days, 30)
	require.Equal(t, dmarcDayView{Day: "2026-06-30"}, v.Days[29])
	require.Equal(t, dmarcDayView{Day: "2026-06-29", Aligned: 8, Failing: 2}, v.Days[28])
	require.Len(t, v.Reporters, 1)
	require.Len(t, v.Unverified, 1)
	var kinds []string
	for _, s := range v.Sources {
		kinds = append(kinds, s.Kind)
	}
	require.Equal(t, []string{sourceThisServer, sourceAligned, sourceDKIMOnly, sourceFailing}, kinds)
	require.Empty(t, v.Advice, "forgery being rejected isn't a problem")
}

func TestDMARCAdvice(t *testing.T) {
	advice := func(in dmarcInputs) []dmarcAdvice { return buildDMARCReport(in)[0].Advice }

	got := advice(reportInputs("none", 14))
	require.Len(t, got, 1)
	require.Contains(t, got[0].Text, "p=quarantine")
	require.Contains(t, advice(reportInputs("quarantine", 14))[0].Text, "p=reject")
	require.Empty(t, advice(reportInputs("none", 13)), "fewer than 14 days")
	short := reportInputs("none", 14)
	short.window = 7
	require.Empty(t, advice(short), "a 7 day window")

	for name, bad := range map[string]mailpolicy.DMARCSource{
		"this server":    {SourceIP: "192.0.2.1"},
		"also passes":    {SourceIP: "198.51.100.2"},
		"broken signing": {SourceIP: "203.0.113.20", DKIMDomain: "mail.example.com"},
	} {
		in := reportInputs("none", 20)
		bad.Domain, bad.DKIM, bad.SPF, bad.Verified, bad.Messages = "example.com", "fail", "fail", true, 3
		in.sources = append(in.sources, bad)
		got := advice(in)
		require.Len(t, got, 1, name)
		require.Equal(t, "warning", got[0].Level, name)
		require.Contains(t, got[0].Text, bad.SourceIP, name)
	}

	// DNS silent: the policy reporters saw, and no guessing at an address.
	in := reportInputs("quarantine", 14)
	in.policies = nil
	v := buildDMARCReport(in)[0]
	require.False(t, v.Checked)
	require.Equal(t, "quarantine", v.Policy)
	require.Empty(t, v.Suggest)
}
