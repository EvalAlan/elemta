package authresult

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dmarc"
)

// The libraries do SPF, DKIM and DMARC record parsing. What is ours is the
// alignment rule, what happens when a check is inconclusive, and the header —
// and each of those has a way of failing that refuses legitimate mail.

// TestAlignmentIsWhatMakesDMARCMeanSomething.
//
// SPF passing for a domain the recipient never sees says nothing about whether
// the visible From is genuine. A forgery with its own SPF-passing envelope
// domain and a From of someone else's is exactly the attack DMARC exists for,
// and it gets through anything that checks SPF without checking alignment.
func TestAlignmentIsWhatMakesDMARCMeanSomething(t *testing.T) {
	cases := []struct {
		authenticated, from string
		strict              bool
		want                bool
		why                 string
	}{
		{"example.com", "example.com", false, true, "the same domain"},
		{"example.com", "example.com", true, true, "the same domain, strictly"},
		{"mail.example.com", "example.com", false, true, "a subdomain aligns when relaxed"},
		{"mail.example.com", "example.com", true, false, "a subdomain does not align when strict"},
		{"attacker.example", "example.com", false, false, "an unrelated domain never aligns"},
		{"notexample.com", "example.com", false, false, "a domain that merely ends similarly"},
		{"bounce.example.com", "news.example.com", false, true, "siblings share an organisational domain"},
		{"bounce.example.com", "news.example.com", true, false, "siblings do not align strictly"},
		{"co.uk", "victim.co.uk", false, false, "a public suffix is nobody's organisation"},
		{"attacker.co.uk", "victim.co.uk", false, false, "neighbours under a public suffix"},
		{"", "example.com", false, false, "nothing authenticated"},
		{"example.com", "", false, false, "no From domain"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if got := aligned(tc.authenticated, tc.from, tc.strict); got != tc.want {
				t.Errorf("aligned(%q, %q, strict=%v) = %v, want %v",
					tc.authenticated, tc.from, tc.strict, got, tc.want)
			}
		})
	}
}

// TestDisabledVerifierAcceptsEverything: a server that has not turned this on
// must behave exactly as it did before, including writing no verdict.
func TestDisabledVerifierAcceptsEverything(t *testing.T) {
	v := New(Config{Enabled: false})
	results := v.Verify(t.Context(), nil, "helo.example", "someone@example.com", nil, nil)
	if results.Disposition != "accept" {
		t.Errorf("disposition = %q, want accept", results.Disposition)
	}
	if results.SPF.Value != "" || results.DMARC.Value != "" {
		t.Error("a disabled verifier should not report verdicts it did not reach")
	}
}

// TestPolicyIsRecordedButNotEnforcedByDefault.
//
// The first thing DMARC enforcement does on a real server is reject mail from
// forwarders and mailing lists, which break SPF alignment by design. An
// operator should be able to see what enforcing would have done before it
// starts doing it.
func TestPolicyIsRecordedButNotEnforcedByDefault(t *testing.T) {
	results := Results{
		Disposition: "accept",
		DMARC:       Result{Method: "dmarc", Value: "fail"},
		Policy:      "reject",
	}
	// With enforcement off this is the whole outcome: a failure is recorded, a
	// policy is recorded, and the message is still accepted.
	if results.Disposition != "accept" {
		t.Error("a failing DMARC must not reject on its own")
	}
	header := results.Header("mail.example.com")
	if !strings.Contains(header, "dmarc=fail") || !strings.Contains(header, "p=reject") {
		t.Errorf("the header should record both the result and the policy: %q", header)
	}
}

// TestHeaderCannotWriteHeadersOfItsOwn: the values come from DNS and from
// libraries, so they are constrained — but this string becomes a header, and a
// header containing CR or LF can add headers.
func TestHeaderCannotWriteHeadersOfItsOwn(t *testing.T) {
	results := Results{
		SPF:   Result{Method: "spf", Value: "pass", Domain: "evil.example\r\nX-Injected: yes"},
		DMARC: Result{Method: "dmarc", Value: "none"},
	}
	header := results.Header("mail.example.com")
	if strings.ContainsAny(header, "\r\n") {
		t.Errorf("header contains line breaks: %q", header)
	}
}

// TestHeaderIsWrittenEvenWhenNothingPassed. The point of the header is to say
// what was checked; omitting it when the answer is "nothing" leaves a reader
// unable to tell that from "never looked".
func TestHeaderIsWrittenEvenWhenNothingPassed(t *testing.T) {
	header := Results{}.Header("mail.example.com")
	for _, want := range []string{"mail.example.com", "spf=none", "dkim=none", "dmarc=none"} {
		if !strings.Contains(header, want) {
			t.Errorf("header %q is missing %q", header, want)
		}
	}
}

func TestHeaderRecordsEachDKIMSignature(t *testing.T) {
	results := Results{
		SPF: Result{Method: "spf", Value: "pass", Domain: "example.com"},
		DKIM: []Result{
			{Method: "dkim", Value: "pass", Domain: "example.com"},
			{Method: "dkim", Value: "fail", Domain: "forwarder.example"},
		},
		DMARC: Result{Method: "dmarc", Value: "pass", Domain: "example.com"},
	}
	header := results.Header("mail.example.com")
	// A forwarder's broken signature says nothing about the original sender's,
	// so both are reported rather than reduced to one verdict.
	if !strings.Contains(header, "dkim=pass header.d=example.com") ||
		!strings.Contains(header, "dkim=fail header.d=forwarder.example") {
		t.Errorf("both signatures should appear: %q", header)
	}
}

func TestDomainOf(t *testing.T) {
	cases := map[string]string{
		"someone@example.com":   "example.com",
		"<someone@Example.COM>": "example.com",
		"  a@b.example  ":       "b.example",
		"not-an-address":        "",
		"":                      "",
	}
	for input, want := range cases {
		if got := domainOf(input); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestUnsignedMessageIsNotAFailure: most mail is unsigned, and treating the
// absence of a signature as a failed one would mark almost everything.
func TestUnsignedMessageIsNotAFailure(t *testing.T) {
	results := VerifyDKIM(t.Context(), []byte("Subject: hello\r\nFrom: a@example.com\r\n\r\nbody\r\n"))
	if len(results) != 0 {
		t.Errorf("an unsigned message produced %d results, want none", len(results))
	}
}

// TestCheckIsBoundedByOneTimeout is the stress-run failure: with every plugin
// allowed ten seconds and run one after another, a resolver that stopped
// answering held the client at end-of-DATA for twenty to thirty-six seconds,
// and it hung up. The whole check must fit in one Timeout however many
// lookups hang.
func TestCheckIsBoundedByOneTimeout(t *testing.T) {
	v := New(Config{
		Enabled: true, SPFEnabled: true, DKIMEnabled: true, DMARCEnabled: true, ARCEnabled: true,
		Timeout:    200 * time.Millisecond,
		SPFTimeout: 10 * time.Second, DMARCTimeout: 10 * time.Second, ARCTimeout: 10 * time.Second,
	})
	v.resolver = newCachingResolver(&fakeResolver{hang: true})
	v.arc.SetResolver(v.resolver.LookupTXT)

	message := []byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; c=relaxed/relaxed;\r\n" +
		" h=from; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; b=AAAA\r\n" +
		"From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")

	start := time.Now()
	results := v.Check(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", "a@example.com", message)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Check took %v with a 200ms budget", elapsed)
	}
	if results.SPF.Value != "temperror" {
		t.Errorf("SPF = %q, want temperror", results.SPF.Value)
	}
	if results.DMARC.Value != "temperror" {
		t.Errorf("DMARC = %q, want temperror", results.DMARC.Value)
	}
	if results.Disposition != "accept" {
		t.Errorf("disposition = %q: an unanswered lookup must not refuse mail", results.Disposition)
	}
}

// TestCheckAgreesWithVerify: running the checks together must not change
// what they conclude.
func TestCheckAgreesWithVerify(t *testing.T) {
	zone := &fakeResolver{zone: map[string][]string{
		"example.com":          {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.example.com":   {"v=DMARC1; p=reject"},
		"other.example":        {"v=spf1 -all"},
		"_dmarc.other.example": {"v=DMARC1; p=quarantine"},
	}}
	v := New(Config{Enabled: true, SPFEnabled: true, DKIMEnabled: true, DMARCEnabled: true, EnforceDMARC: true})
	v.resolver = newCachingResolver(zone)

	for _, tc := range []struct {
		from             string
		spf, dmarc, disp string
	}{
		{"a@example.com", "pass", "pass", "accept"},
		{"a@other.example", "fail", "fail", "quarantine"},
	} {
		message := []byte("From: " + tc.from + "\r\nSubject: hello\r\n\r\nbody\r\n")
		got := v.Check(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", tc.from, message)
		if got.SPF.Value != tc.spf || got.DMARC.Value != tc.dmarc || got.Disposition != tc.disp {
			t.Errorf("%s: Check = spf %q dmarc %q disposition %q, want %q %q %q",
				tc.from, got.SPF.Value, got.DMARC.Value, got.Disposition, tc.spf, tc.dmarc, tc.disp)
		}
		want := v.Verify(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", tc.from, message, nil)
		if got.SPF.Value != want.SPF.Value || got.DMARC.Value != want.DMARC.Value ||
			got.Policy != want.Policy || got.Disposition != want.Disposition {
			t.Errorf("%s: Check %+v disagrees with Verify %+v", tc.from, got, want)
		}
	}
}

// headerFromZone is a world with a victim that publishes p=reject and an
// attacker whose SPF authorises the connecting address.
func headerFromZone() *fakeResolver {
	return &fakeResolver{zone: map[string][]string{
		"attacker.example":          {"v=spf1 ip4:192.0.2.1 -all"},
		"victim.example":            {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.victim.example":     {"v=DMARC1; p=reject"},
		"strict.example":            {"v=spf1 ip4:192.0.2.1 -all"},
		"mail.strict.example":       {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.strict.example":     {"v=DMARC1; p=quarantine; aspf=s"},
		"mail.relaxed.example":      {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.relaxed.example":    {"v=DMARC1; p=reject"},
		"_dmarc.subpol.example":     {"v=DMARC1; p=none; sp=reject"},
		"_dmarc.quarantine.example": {"v=DMARC1; p=quarantine"},
	}}
}

func headerFromVerifier(enforce bool) *Verifier {
	v := New(Config{Enabled: true, SPFEnabled: true, DMARCEnabled: true, EnforceDMARC: enforce})
	v.resolver = newCachingResolver(headerFromZone())
	return v
}

// checkBoth runs Check and Verify on one message so neither path can drift
// back to judging the envelope.
func checkBoth(t *testing.T, v *Verifier, mailFrom, headers string) Results {
	t.Helper()
	message := []byte(headers + "Subject: hello\r\n\r\nbody\r\n")
	ip := net.ParseIP("192.0.2.1")
	got := v.Check(t.Context(), ip, "helo.example", mailFrom, message)
	want := v.Verify(t.Context(), ip, "helo.example", mailFrom, message, nil)
	if got.DMARC != want.DMARC || got.Policy != want.Policy || got.Disposition != want.Disposition {
		t.Errorf("Check %+v disagrees with Verify %+v", got, want)
	}
	return got
}

// TestDMARCJudgesTheHeaderFromNotTheEnvelope is the spoof DMARC exists to
// stop: the envelope names the forger's own SPF-passing domain and the From
// the reader sees names someone else's. Judging the envelope reported
// dmarc=pass for a forged From and left a p=reject domain unprotected.
func TestDMARCJudgesTheHeaderFromNotTheEnvelope(t *testing.T) {
	got := checkBoth(t, headerFromVerifier(true), "bounce@attacker.example", "From: CEO <ceo@victim.example>\r\n")
	if got.SPF.Value != "pass" || got.SPF.Domain != "attacker.example" {
		t.Errorf("SPF = %+v: SPF still judges the envelope and should pass for it", got.SPF)
	}
	if got.DMARC.Value != "fail" || got.DMARC.Domain != "victim.example" {
		t.Errorf("DMARC = %+v, want fail for victim.example", got.DMARC)
	}
	if got.Policy != "reject" || got.Disposition != "reject" {
		t.Errorf("policy %q disposition %q, want reject/reject", got.Policy, got.Disposition)
	}
	if header := got.Header("mx.example"); !strings.Contains(header, "dmarc=fail (p=reject) header.from=victim.example") {
		t.Errorf("header does not report the forged From: %q", header)
	}

	// Recorded but not acted on when the operator has not asked for it.
	if got := checkBoth(t, headerFromVerifier(false), "bounce@attacker.example", "From: ceo@victim.example\r\n"); got.Disposition != "accept" {
		t.Errorf("disposition without enforcement = %q, want accept", got.Disposition)
	}
}

func TestDMARCPassesForAnAlignedSender(t *testing.T) {
	got := checkBoth(t, headerFromVerifier(true), "bounce@victim.example", "From: ceo@victim.example\r\n")
	if got.DMARC.Value != "pass" || got.Disposition != "accept" {
		t.Errorf("DMARC %+v disposition %q, want pass/accept", got.DMARC, got.Disposition)
	}
}

func TestDMARCRelaxedAndStrictSPFAlignment(t *testing.T) {
	v := headerFromVerifier(true)
	relaxed := checkBoth(t, v, "bounce@mail.relaxed.example", "From: news@relaxed.example\r\n")
	if relaxed.DMARC.Value != "pass" {
		t.Errorf("relaxed: a subdomain envelope should align, got %+v", relaxed.DMARC)
	}
	strict := checkBoth(t, v, "bounce@mail.strict.example", "From: news@strict.example\r\n")
	if strict.DMARC.Value != "fail" || strict.Disposition != "quarantine" {
		t.Errorf("strict: a subdomain envelope must not align, got %+v disposition %q", strict.DMARC, strict.Disposition)
	}
	exact := checkBoth(t, v, "bounce@strict.example", "From: news@strict.example\r\n")
	if exact.DMARC.Value != "pass" {
		t.Errorf("strict: an exact match should align, got %+v", exact.DMARC)
	}
}

// TestDMARCDKIMAlignmentFollowsTheHeaderFrom: a valid signature by the
// forger's own domain is not a signature by the victim's.
func TestDMARCDKIMAlignmentFollowsTheHeaderFrom(t *testing.T) {
	relaxed := &dmarc.Record{Policy: dmarc.PolicyReject, DKIMAlignment: dmarc.AlignmentRelaxed}
	strict := &dmarc.Record{Policy: dmarc.PolicyReject, DKIMAlignment: dmarc.AlignmentStrict}
	for _, tc := range []struct {
		signer string
		record *dmarc.Record
		want   string
	}{
		{"attacker.example", relaxed, "fail"},
		{"victim.example", strict, "pass"},
		{"mail.victim.example", relaxed, "pass"},
		{"mail.victim.example", strict, "fail"},
	} {
		signed := Results{DKIM: []Result{{Method: "dkim", Value: "pass", Domain: tc.signer}}}
		got, _, _ := evaluateDMARC("victim.example", tc.record, nil, signed)
		if got.Value != tc.want {
			t.Errorf("d=%s adkim=%s: dmarc=%s, want %s", tc.signer, tc.record.DKIMAlignment, got.Value, tc.want)
		}
	}
}

// TestDMARCWithoutAUsableFromNeverPasses: no From, or one that cannot be read,
// identifies no domain. That must not be mistaken for a pass, and with no
// domain there is no policy to enforce.
func TestDMARCWithoutAUsableFromNeverPasses(t *testing.T) {
	v := headerFromVerifier(true)
	for name, headers := range map[string]string{
		"missing":     "",
		"unparseable": "From: <<not an address\r\n",
		"no domain":   "From: someone\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := checkBoth(t, v, "bounce@victim.example", headers)
			if got.DMARC.Value != "permerror" || got.Disposition != "accept" {
				t.Errorf("DMARC %+v disposition %q, want permerror/accept", got.DMARC, got.Disposition)
			}
		})
	}
}

// TestDMARCMultipleFromDomainsNeverPass: a forger adding their own From next
// to the victim's must not get to choose which one is judged.
func TestDMARCMultipleFromDomainsNeverPass(t *testing.T) {
	v := headerFromVerifier(true)
	for name, headers := range map[string]string{
		"two headers":         "From: me@attacker.example\r\nFrom: ceo@victim.example\r\n",
		"two addresses":       "From: me@attacker.example, ceo@victim.example\r\n",
		"too many to look up": "From: a@a.example, b@b.example, c@c.example, d@d.example, e@e.example\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := checkBoth(t, v, "bounce@attacker.example", headers)
			if got.DMARC.Value != "fail" || got.Disposition != "reject" {
				t.Errorf("DMARC %+v policy %q disposition %q, want fail/reject", got.DMARC, got.Policy, got.Disposition)
			}
		})
	}

	// The strictest failing policy is the one applied.
	got := checkBoth(t, v, "bounce@attacker.example", "From: a@quarantine.example, b@attacker.example\r\n")
	if got.DMARC.Value != "fail" || got.Policy != "quarantine" || got.Disposition != "quarantine" {
		t.Errorf("DMARC %+v policy %q disposition %q, want fail/quarantine", got.DMARC, got.Policy, got.Disposition)
	}
	// Two addresses at one domain are one author domain.
	same := checkBoth(t, v, "bounce@victim.example", "From: a@victim.example, b@Victim.Example\r\n")
	if same.DMARC.Value != "pass" {
		t.Errorf("two addresses at one domain: %+v, want pass", same.DMARC)
	}
}

// TestDMARCSubdomainInheritsOrganisationalPolicy: without the fallback a
// forger sidesteps p=reject by putting a subdomain in the From.
func TestDMARCSubdomainInheritsOrganisationalPolicy(t *testing.T) {
	v := headerFromVerifier(true)
	got := checkBoth(t, v, "bounce@attacker.example", "From: ceo@anything.victim.example\r\n")
	if got.DMARC.Value != "fail" || got.Disposition != "reject" {
		t.Errorf("DMARC %+v disposition %q, want fail/reject", got.DMARC, got.Disposition)
	}
	sub := checkBoth(t, v, "bounce@attacker.example", "From: x@news.subpol.example\r\n")
	if sub.Policy != "reject" {
		t.Errorf("subdomain policy = %q, want reject from sp=", sub.Policy)
	}
}

// Aggregate reports need the published record and the DKIM selectors, which
// the verdict alone does not carry.
func TestCheckKeepsPolicyAndSelectorsForReports(t *testing.T) {
	zone := &fakeResolver{zone: map[string][]string{
		"example.com":        {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=quarantine; pct=50; aspf=s; rua=mailto:rua@example.com!10m"},
	}}
	v := New(Config{Enabled: true, SPFEnabled: true, DKIMEnabled: true, DMARCEnabled: true})
	v.resolver = newCachingResolver(zone)
	message := []byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.com;\r\n" +
		"  s=sel1; c=relaxed/relaxed; h=from; bh=AAAA; b=AAAA\r\n" +
		"From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")

	got := v.Check(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", "a@example.com", message)
	p := got.DMARCPolicy
	if p == nil {
		t.Fatal("no policy recorded")
	}
	if p.Domain != "example.com" || p.P != "quarantine" || p.SP != "quarantine" || p.Pct != 50 ||
		p.ASPF != "s" || p.ADKIM != "r" || len(p.RUA) != 1 || p.RUA[0] != "mailto:rua@example.com!10m" {
		t.Errorf("policy = %+v", p)
	}
	if !p.SPFAligned || p.DKIMAligned {
		t.Errorf("alignment = spf %v dkim %v", p.SPFAligned, p.DKIMAligned)
	}
	if len(got.DKIM) != 1 || got.DKIM[0].Selector != "sel1" {
		t.Errorf("DKIM = %+v, want selector sel1", got.DKIM)
	}
}

func TestHeaderFromDomain(t *testing.T) {
	cases := map[string]string{
		"From: A <a@Example.COM>\r\nTo: b@x\r\n\r\nbody": "example.com",
		"Subject: x\r\nFrom: a@example.com\r\n\r\n":      "example.com",
		"From: a@example.com\n\nbody":                    "example.com",
		"Subject: x\r\n\r\nFrom: a@body.test\r\n":        "",
		"From: a@one.test, b@two.test\r\n\r\n":           "",
		"From: a@one.test\r\nFrom: b@two.test\r\n\r\n":   "",
		"From: not an address\r\n\r\n":                   "",
	}
	for msg, want := range cases {
		if got := HeaderFromDomain([]byte(msg)); got != want {
			t.Errorf("HeaderFromDomain(%q) = %q, want %q", msg, got, want)
		}
	}
}
