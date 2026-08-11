package authresult

import (
	"strings"
	"testing"
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
