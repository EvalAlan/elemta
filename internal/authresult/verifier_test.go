package authresult

import (
	"net"
	"strings"
	"testing"
	"time"
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
	results := v.Verify(t.Context(), nil, "helo.example", "someone@example.com", nil)
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
	message := []byte("From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")

	for _, tc := range []struct {
		from             string
		spf, dmarc, disp string
	}{
		{"a@example.com", "pass", "pass", "accept"},
		{"a@other.example", "fail", "fail", "quarantine"},
	} {
		got := v.Check(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", tc.from, message)
		if got.SPF.Value != tc.spf || got.DMARC.Value != tc.dmarc || got.Disposition != tc.disp {
			t.Errorf("%s: Check = spf %q dmarc %q disposition %q, want %q %q %q",
				tc.from, got.SPF.Value, got.DMARC.Value, got.Disposition, tc.spf, tc.dmarc, tc.disp)
		}
		want := v.Verify(t.Context(), net.ParseIP("192.0.2.1"), "helo.example", tc.from, nil)
		if got.SPF.Value != want.SPF.Value || got.DMARC.Value != want.DMARC.Value ||
			got.Policy != want.Policy || got.Disposition != want.Disposition {
			t.Errorf("%s: Check %+v disagrees with Verify %+v", tc.from, got, want)
		}
	}
}
