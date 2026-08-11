// Package authresult verifies who a message claims to be from.
//
// Elemta signed its outbound mail with DKIM and checked nothing on the way in.
// The plugin interfaces for SPF and DMARC existed with no implementation behind
// them and nothing calling them, so a forged sender was indistinguishable from
// a real one as far as this server was concerned.
//
// rspamd performs these checks when it is enabled and folds them into a score,
// which is not nothing — but a score is not a policy. A domain that publishes
// "reject anything that fails DMARC" is asking for a decision, and a server
// that cannot express that decision cannot honour it. It also could not say
// why it trusted a message, because it wrote no Authentication-Results header
// for anything downstream to read.
package authresult

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
)

// Result is one authentication method's verdict.
type Result struct {
	Method string `json:"method"` // spf, dkim, dmarc
	Value  string `json:"value"`  // pass, fail, softfail, none, temperror, permerror
	Domain string `json:"domain,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Results is everything learned about one message.
type Results struct {
	SPF   Result   `json:"spf"`
	DKIM  []Result `json:"dkim,omitempty"`
	DMARC Result   `json:"dmarc"`
	// Policy is what the sender's domain asked us to do with a failure:
	// none, quarantine or reject. Recorded even when it is not enforced, so an
	// operator can see what enforcing would have done before turning it on.
	Policy string `json:"policy,omitempty"`
	// Disposition is what we decided: accept, quarantine or reject.
	Disposition string `json:"disposition"`
}

// Config controls verification.
type Config struct {
	Enabled bool
	// EnforceDMARC honours a domain's published policy. Off by default: the
	// first thing DMARC enforcement does on a real server is reject mail from
	// forwarders and mailing lists, which break SPF alignment by design, so an
	// operator should see the results before acting on them.
	EnforceDMARC bool
	// Timeout bounds all the DNS work for one message. Verification happens
	// while a client waits at end-of-DATA, so it cannot be unbounded.
	Timeout time.Duration
	// Hostname identifies this server in the Authentication-Results header.
	Hostname string
}

// Verifier performs the checks.
type Verifier struct {
	config   Config
	resolver *net.Resolver
}

func New(config Config) *Verifier {
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	return &Verifier{config: config, resolver: net.DefaultResolver}
}

func (v *Verifier) Enabled() bool { return v != nil && v.config.Enabled }

// Verify checks one message.
//
// Every failure mode here resolves towards accepting. A DNS timeout is
// "temperror", not "fail"; an unparseable record is the sender's problem, not
// evidence of forgery. Treating an inconclusive check as a failure would refuse
// legitimate mail whenever a resolver hiccuped, which is a far more likely
// event than the forgery it would be catching.
func (v *Verifier) Verify(ctx context.Context, clientIP net.IP, heloName, mailFrom string, dkimResults []Result) Results {
	results := Results{Disposition: "accept"}
	if !v.Enabled() {
		return results
	}

	ctx, cancel := context.WithTimeout(ctx, v.config.Timeout)
	defer cancel()

	results.SPF = v.checkSPF(ctx, clientIP, heloName, mailFrom)
	results.DKIM = dkimResults

	fromDomain := domainOf(mailFrom)
	results.DMARC, results.Policy = v.checkDMARC(ctx, fromDomain, results)

	// A policy is only acted on when the operator has asked for it.
	if v.config.EnforceDMARC && results.DMARC.Value == "fail" {
		switch results.Policy {
		case "reject":
			results.Disposition = "reject"
		case "quarantine":
			results.Disposition = "quarantine"
		}
	}
	return results
}

func (v *Verifier) checkSPF(ctx context.Context, clientIP net.IP, heloName, mailFrom string) Result {
	if clientIP == nil {
		return Result{Method: "spf", Value: "none", Reason: "no client address"}
	}

	// RFC 7208 §2.4: the empty sender (a bounce) is checked against the HELO
	// name instead, since there is no envelope domain to check.
	sender := mailFrom
	if strings.TrimSpace(sender) == "" || sender == "<>" {
		sender = "postmaster@" + strings.TrimSpace(heloName)
	}

	result, err := spf.CheckHostWithSender(clientIP, heloName, sender, spf.WithContext(ctx))
	out := Result{Method: "spf", Domain: domainOf(sender), Value: string(result)}
	if err != nil {
		out.Reason = err.Error()
	}
	return out
}

// checkDMARC looks up the From domain's policy and decides alignment.
//
// DMARC passes when SPF or DKIM passes *and* the passing identity aligns with
// the From domain. Alignment is the whole point: SPF passing for a domain the
// recipient never sees says nothing about whether the visible From is genuine,
// which is exactly how a forgery gets through a naive check.
func (v *Verifier) checkDMARC(ctx context.Context, fromDomain string, results Results) (Result, string) {
	out := Result{Method: "dmarc", Domain: fromDomain}
	if fromDomain == "" {
		out.Value = "none"
		return out, ""
	}

	record, err := dmarc.LookupWithOptions(fromDomain, &dmarc.LookupOptions{
		LookupTXT: func(name string) ([]string, error) {
			return v.resolver.LookupTXT(ctx, name)
		},
	})
	if err != nil {
		// No record is "none": the domain has not asked for anything, which is
		// not a failure. A lookup that broke is "temperror" for the same reason
		// nothing else here fails closed.
		if err == dmarc.ErrNoPolicy {
			out.Value = "none"
			return out, ""
		}
		out.Value = "temperror"
		out.Reason = err.Error()
		return out, ""
	}

	policy := string(record.Policy)

	spfAligned := results.SPF.Value == "pass" &&
		aligned(results.SPF.Domain, fromDomain, record.SPFAlignment == dmarc.AlignmentStrict)
	dkimAligned := false
	for _, d := range results.DKIM {
		if d.Value == "pass" && aligned(d.Domain, fromDomain, record.DKIMAlignment == dmarc.AlignmentStrict) {
			dkimAligned = true
			break
		}
	}

	if spfAligned || dkimAligned {
		out.Value = "pass"
	} else {
		out.Value = "fail"
		out.Reason = "neither SPF nor DKIM passed for an identity aligned with the From domain"
	}
	return out, policy
}

// aligned reports whether an authenticated domain matches the From domain.
//
// Relaxed alignment — the default — accepts a shared organisational domain, so
// mail.example.com aligns with example.com. That is what lets an organisation
// send from a subdomain without publishing policy for every one of them.
func aligned(authenticated, from string, strict bool) bool {
	authenticated = strings.ToLower(strings.TrimSuffix(authenticated, "."))
	from = strings.ToLower(strings.TrimSuffix(from, "."))
	if authenticated == "" || from == "" {
		return false
	}
	if authenticated == from {
		return true
	}
	if strict {
		return false
	}
	return strings.HasSuffix(authenticated, "."+from) || strings.HasSuffix(from, "."+authenticated)
}

// Header renders the Authentication-Results header.
//
// Written even when nothing passed, and even when nothing is enforced. The
// point is that a later hop — or an operator reading a message — can see what
// this server checked and what it found, rather than having to infer it from
// whether the message arrived.
func (r Results) Header(hostname string) string {
	parts := []string{hostname}

	spfPart := "spf=" + orNone(r.SPF.Value)
	if r.SPF.Domain != "" {
		spfPart += " smtp.mailfrom=" + r.SPF.Domain
	}
	parts = append(parts, spfPart)

	if len(r.DKIM) == 0 {
		parts = append(parts, "dkim=none")
	}
	for _, d := range r.DKIM {
		part := "dkim=" + orNone(d.Value)
		if d.Domain != "" {
			part += " header.d=" + d.Domain
		}
		parts = append(parts, part)
	}

	dmarcPart := "dmarc=" + orNone(r.DMARC.Value)
	if r.Policy != "" {
		dmarcPart += " (p=" + r.Policy + ")"
	}
	if r.DMARC.Domain != "" {
		dmarcPart += " header.from=" + r.DMARC.Domain
	}
	parts = append(parts, dmarcPart)

	// The values come from libraries and from DNS, so they are constrained —
	// but this becomes a header, and a header that can contain CR or LF can
	// write headers of its own.
	return sanitizeHeader(strings.Join(parts, "; "))
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func sanitizeHeader(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, value)
}

func domainOf(address string) string {
	address = strings.Trim(strings.TrimSpace(address), "<>")
	if at := strings.LastIndex(address, "@"); at >= 0 {
		return strings.ToLower(address[at+1:])
	}
	return ""
}

// String is for logs.
func (r Results) String() string {
	return fmt.Sprintf("spf=%s dkim=%d dmarc=%s policy=%s disposition=%s",
		orNone(r.SPF.Value), len(r.DKIM), orNone(r.DMARC.Value), r.Policy, r.Disposition)
}

// VerifyDKIM checks the signatures on a received message.
//
// Separate from Verify because it needs the message bytes while the rest needs
// only the envelope, and because a message with no signature is an ordinary
// state rather than a failure — most mail is unsigned.
func VerifyDKIM(ctx context.Context, message []byte) []Result {
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(message), &dkim.VerifyOptions{
		// One bad signature must not stop the others being checked: a message
		// can carry several, and a forwarder's broken one says nothing about
		// the original sender's.
		MaxVerifications: 5,
	})
	if err != nil && len(verifications) == 0 {
		// No signatures, or a message that could not be parsed as one. Neither
		// is evidence of anything.
		return nil
	}

	results := make([]Result, 0, len(verifications))
	for _, verification := range verifications {
		result := Result{Method: "dkim", Domain: verification.Domain, Value: "pass"}
		if verification.Err != nil {
			result.Value = "fail"
			result.Reason = verification.Err.Error()
			// A signature this server cannot check is not a signature that
			// failed. Saying "fail" would let an unknown algorithm look like
			// forgery.
			if dkim.IsTempFail(verification.Err) {
				result.Value = "temperror"
			} else if dkim.IsPermFail(verification.Err) {
				result.Value = "permerror"
			}
		}
		results = append(results, result)
	}
	return results
}
