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
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
	arcplugin "github.com/EvalAlan/elemta/internal/arc"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// Result is one authentication method's verdict.
type Result struct {
	Method string `json:"method"` // spf, dkim, dmarc
	Value  string `json:"value"`  // pass, fail, softfail, none, temperror, permerror
	Domain string `json:"domain,omitempty"`
	// Selector is the DKIM s= tag. DMARC aggregate reports name it so the
	// domain owner can tell which of its keys signed.
	Selector string `json:"selector,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Results is everything learned about one message.
type Results struct {
	SPF   Result   `json:"spf"`
	DKIM  []Result `json:"dkim,omitempty"`
	DMARC Result   `json:"dmarc"`
	ARC   Result   `json:"arc"`
	// Policy is what the sender's domain asked us to do with a failure:
	// none, quarantine or reject. Recorded even when it is not enforced, so an
	// operator can see what enforcing would have done before turning it on.
	Policy string `json:"policy,omitempty"`
	// Disposition is what we decided: accept, quarantine or reject.
	Disposition string `json:"disposition"`
	// DMARCPolicy is the record the verdict was reached under, kept for
	// aggregate reporting. Not serialised: only the reporter needs it, and
	// only while the message is still in hand.
	DMARCPolicy *DMARCPolicy `json:"-"`
}

// DMARCPolicy is a published DMARC record and how one message aligned with it.
type DMARCPolicy struct {
	Domain string
	// P and SP are the published policies; SP defaults to P (RFC 7489 §6.3).
	P, SP string
	Pct   int
	// ADKIM and ASPF are "r" or "s".
	ADKIM, ASPF string
	// RUA is the aggregate report URIs exactly as published, size suffixes
	// included, so the reporter can apply them.
	RUA         []string
	DKIMAligned bool
	SPFAligned  bool
}

// Config controls verification.
type Config struct {
	Enabled bool
	// Individual switches are used by the built-in plugin UI. When Enabled is
	// true and all four are false, the legacy aggregate behavior enables
	// SPF/DKIM/DMARC together for backwards compatibility.
	SPFEnabled   bool
	DKIMEnabled  bool
	DMARCEnabled bool
	ARCEnabled   bool
	// EnforceDMARC honours a domain's published policy. Off by default: the
	// first thing DMARC enforcement does on a real server is reject mail from
	// forwarders and mailing lists, which break SPF alignment by design, so an
	// operator should see the results before acting on them.
	EnforceDMARC bool
	// Timeout bounds all the DNS work for one message. Verification happens
	// while a client waits at end-of-DATA, so it cannot be unbounded.
	Timeout time.Duration
	// Plugin-specific timeouts keep one plugin's dashboard setting from silently
	// changing another. Zero inherits Timeout for legacy aggregate configs.
	SPFTimeout   time.Duration
	DMARCTimeout time.Duration
	ARCTimeout   time.Duration
	// Hostname identifies this server in the Authentication-Results header.
	Hostname string
	// Resolver answers every lookup the checks make. Nil means
	// net.DefaultResolver. It exists so a caller can point verification at a
	// particular DNS server without mutating net.DefaultResolver, which every
	// other lookup in the process reads concurrently.
	Resolver Resolver
}

// Verifier performs the checks.
type Verifier struct {
	config Config
	// resolver caches TXT answers for every check, and is shared by all
	// sessions so a burst of mail from one domain costs one lookup.
	resolver *cachingResolver
	// arc is the RFC 8617 chain verifier. It is held here so that a reload
	// swaps one object and every check moves together, rather than leaving a
	// session verifying SPF under a new policy and ARC under the old one.
	arc *arcplugin.Plugin
}

func New(config Config) *Verifier {
	if config.Enabled && !config.SPFEnabled && !config.DKIMEnabled && !config.DMARCEnabled && !config.ARCEnabled {
		config.SPFEnabled = true
		config.DKIMEnabled = true
		config.DMARCEnabled = true
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.SPFTimeout <= 0 {
		config.SPFTimeout = config.Timeout
	}
	if config.DMARCTimeout <= 0 {
		config.DMARCTimeout = config.Timeout
	}
	if config.ARCTimeout <= 0 {
		config.ARCTimeout = config.Timeout
	}
	// A verification-only plugin needs no key, so this cannot fail; the sealing
	// side is constructed by the delivery path, which does validate.
	arcVerifier, _ := arcplugin.New(arcplugin.Config{
		Enabled: config.ARCEnabled,
		Verify:  config.ARCEnabled,
		Timeout: config.ARCTimeout,
	})
	var upstream Resolver = net.DefaultResolver
	if config.Resolver != nil {
		upstream = config.Resolver
	}
	resolver := newCachingResolver(upstream)
	arcVerifier.SetResolver(resolver.LookupTXT)
	return &Verifier{config: config, resolver: resolver, arc: arcVerifier}
}

// Check runs every enabled check on one message within a single time budget.
//
// The client is waiting at end-of-DATA for all of this, so what matters is
// how long the whole takes, not each part. SPF, DKIM, ARC and the DMARC record
// lookup do not depend on each other and run together; only the DMARC verdict
// waits, because it needs the SPF and DKIM outcomes. Each check still honours
// its own plugin timeout, but none can run past Timeout, so a resolver that
// stops answering costs one Timeout rather than one per check in turn.
func (v *Verifier) Check(ctx context.Context, clientIP net.IP, heloName, mailFrom string, message []byte) Results {
	results := Results{Disposition: "accept"}
	if !v.Enabled() {
		return results
	}
	ctx, cancel := context.WithTimeout(ctx, v.config.Timeout)
	defer cancel()

	// DMARC is about the From the recipient sees (RFC 7489 §3.1), not the
	// envelope. Parsed before anything starts so the policy lookups can run
	// alongside SPF and DKIM rather than after them.
	authors, authorErr := authorDomains(message)
	lookups := make([]dmarcLookup, len(authors))
	var wg sync.WaitGroup
	run := func(timeout time.Duration, check func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			check(checkCtx)
		}()
	}

	if v.config.SPFEnabled {
		run(v.config.SPFTimeout, func(ctx context.Context) {
			results.SPF = v.checkSPF(ctx, clientIP, heloName, mailFrom)
		})
	} else {
		results.SPF = Result{Method: "spf", Value: "none", Reason: "SPF plugin disabled"}
	}
	if v.config.DKIMEnabled {
		run(v.config.Timeout, func(ctx context.Context) {
			results.DKIM = verifyDKIM(ctx, message, v.resolver.LookupTXT)
		})
	}
	if v.config.DMARCEnabled && shouldLookUp(authors, authorErr) {
		for i, domain := range authors {
			run(v.config.DMARCTimeout, func(ctx context.Context) {
				lookups[i].record, lookups[i].err = v.lookupDMARC(ctx, domain)
			})
		}
	}
	if v.config.ARCEnabled {
		run(v.config.ARCTimeout, func(ctx context.Context) {
			results.ARC = v.VerifyARC(ctx, message)
		})
	} else {
		results.ARC = v.VerifyARC(ctx, message)
	}
	wg.Wait()

	if v.config.DMARCEnabled {
		results.DMARC, results.Policy, results.DMARCPolicy = decideDMARC(authors, authorErr, lookups, results)
	} else {
		results.DMARC = Result{Method: "dmarc", Value: "none", Reason: "DMARC plugin disabled"}
	}
	v.applyPolicy(&results)
	return results
}

func (v *Verifier) Enabled() bool {
	return v != nil && v.config.Enabled &&
		(v.config.SPFEnabled || v.config.DKIMEnabled || v.config.DMARCEnabled || v.config.ARCEnabled)
}

func (v *Verifier) DKIMEnabled() bool { return v != nil && v.config.DKIMEnabled }

// Verify checks one message.
//
// Every failure mode here resolves towards accepting. A DNS timeout is
// "temperror", not "fail"; an unparseable record is the sender's problem, not
// evidence of forgery. Treating an inconclusive check as a failure would refuse
// legitimate mail whenever a resolver hiccuped, which is a far more likely
// event than the forgery it would be catching.
//
// message is needed for its From header, which is the identity DMARC judges.
func (v *Verifier) Verify(ctx context.Context, clientIP net.IP, heloName, mailFrom string, message []byte, dkimResults []Result) Results {
	results := Results{Disposition: "accept"}
	if !v.Enabled() {
		return results
	}

	if v.config.SPFEnabled {
		spfCtx, cancel := context.WithTimeout(ctx, v.config.SPFTimeout)
		results.SPF = v.checkSPF(spfCtx, clientIP, heloName, mailFrom)
		cancel()
	} else {
		results.SPF = Result{Method: "spf", Value: "none", Reason: "SPF plugin disabled"}
	}
	results.DKIM = dkimResults

	if v.config.DMARCEnabled {
		dmarcCtx, cancel := context.WithTimeout(ctx, v.config.DMARCTimeout)
		authors, authorErr := authorDomains(message)
		lookups := make([]dmarcLookup, len(authors))
		if shouldLookUp(authors, authorErr) {
			for i, domain := range authors {
				lookups[i].record, lookups[i].err = v.lookupDMARC(dmarcCtx, domain)
			}
		}
		results.DMARC, results.Policy, results.DMARCPolicy = decideDMARC(authors, authorErr, lookups, results)
		cancel()
	} else {
		results.DMARC = Result{Method: "dmarc", Value: "none", Reason: "DMARC plugin disabled"}
	}

	v.applyPolicy(&results)
	return results
}

// applyPolicy acts on a published policy only when the operator has asked for
// it.
func (v *Verifier) applyPolicy(results *Results) {
	if v.config.EnforceDMARC && results.DMARC.Value == "fail" {
		switch results.Policy {
		case "reject":
			results.Disposition = "reject"
		case "quarantine":
			results.Disposition = "quarantine"
		}
	}
}

// VerifyARC evaluates the ARC chain over the message as received.
//
// Separate from Verify because it needs the message bytes while the rest needs
// only the envelope. Unlike SPF and DMARC, a chain that cannot be verified is
// reported as failed rather than inconclusive: an unverifiable chain is either
// damaged or forged, and honouring one would defeat the point of ARC. The
// result is recorded, not enforced — a broken chain means the chain cannot
// vouch for an earlier authentication result, not that the message is hostile.
func (v *Verifier) VerifyARC(ctx context.Context, message []byte) Result {
	if v == nil || !v.config.ARCEnabled || v.arc == nil {
		return Result{Method: "arc", Value: "none", Reason: "ARC plugin disabled"}
	}
	result := v.arc.Verify(ctx, message)
	return Result{Method: "arc", Value: result.Value, Reason: result.Reason}
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

	result, err := spf.CheckHostWithSender(clientIP, heloName, sender,
		spf.WithContext(ctx), spf.WithResolver(v.resolver))
	out := Result{Method: "spf", Domain: domainOf(sender), Value: string(result)}
	if err != nil {
		out.Reason = err.Error()
	}
	return out
}

// maxAuthorDomains bounds the policy lookups one message can cause. The From
// header is written by the sender, so without a bound it would decide how much
// DNS work this server does while the client waits.
const maxAuthorDomains = 4

var errNoFrom = errors.New("message has no From header")

// dmarcLookup is one author domain's policy lookup.
type dmarcLookup struct {
	record *dmarc.Record
	err    error
}

// authorDomains returns the distinct domains of the RFC5322.From addresses.
//
// Every From header is collected, not just the first: a forger who adds a
// second From with their own domain must not get to choose which one is
// judged, because mail clients disagree about which one they display.
func authorDomains(message []byte) ([]string, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil, fmt.Errorf("unparseable header: %w", err)
	}
	fields := msg.Header["From"]
	if len(fields) == 0 {
		return nil, errNoFrom
	}
	var domains []string
	seen := map[string]bool{}
	for _, field := range fields {
		addresses, err := mail.ParseAddressList(field)
		if err != nil {
			return nil, fmt.Errorf("unparseable From header: %w", err)
		}
		for _, address := range addresses {
			domain := strings.TrimSuffix(domainOf(address.Address), ".")
			if domain == "" {
				return nil, errors.New("From address has no domain")
			}
			if !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	return domains, nil
}

// shouldLookUp reports whether the author domains are worth fetching policy
// for. Beyond the bound the verdict does not depend on any record.
func shouldLookUp(authors []string, authorErr error) bool {
	return authorErr == nil && len(authors) <= maxAuthorDomains
}

// decideDMARC turns the author domains and their policies into one verdict.
//
// DMARC passes when SPF or DKIM passes *and* the passing identity aligns with
// the From domain. Alignment is the whole point: SPF passing for a domain the
// recipient never sees says nothing about whether the visible From is genuine,
// which is exactly how a forgery gets through a naive check.
// The returned policy is the one record a report can be filed under, so it is
// nil whenever the message is not judged under exactly one domain's record.
func decideDMARC(authors []string, authorErr error, lookups []dmarcLookup, results Results) (Result, string, *DMARCPolicy) {
	if authorErr != nil {
		// permerror rather than none: "none" reads as "this domain published
		// no policy", a claim about a domain we never identified. The message
		// is malformed (RFC 5322 requires exactly one From) and saying so lets
		// a later hop treat it accordingly. With no domain there is no policy
		// to apply, so the disposition is left alone; what matters is that
		// this can never read as a pass.
		return Result{Method: "dmarc", Value: "permerror", Reason: authorErr.Error()}, "", nil
	}
	if len(authors) == 1 {
		return evaluateDMARC(authors[0], lookups[0].record, lookups[0].err, results)
	}

	// Several author domains. RFC 7489 §6.6.1 lets a receiver reject these
	// outright and otherwise asks for the strictest policy among them. This
	// never passes, even if each domain would on its own: one verdict for the
	// message would otherwise belong to whichever domain the forger made
	// pass, while the reader may be shown the other.
	out := Result{Method: "dmarc", Value: "fail",
		Reason: fmt.Sprintf("From names %d domains: %s", len(authors), strings.Join(authors, ", "))}
	if len(authors) > maxAuthorDomains {
		// Too many to look up. Rejecting is what §6.6.1 permits, and anything
		// weaker would let a forger hide the victim past the bound.
		return out, string(dmarc.PolicyReject), nil
	}
	policy := ""
	for i, domain := range authors {
		verdict, domainPolicy, _ := evaluateDMARC(domain, lookups[i].record, lookups[i].err, results)
		if verdict.Value != "pass" && policyRank(domainPolicy) > policyRank(policy) {
			policy = domainPolicy
		}
	}
	return out, policy, nil
}

func policyRank(policy string) int {
	switch policy {
	case string(dmarc.PolicyReject):
		return 2
	case string(dmarc.PolicyQuarantine):
		return 1
	}
	return 0
}

// lookupDMARC fetches the From domain's policy. It is separate from the
// verdict so the lookup can run alongside SPF and DKIM.
//
// A subdomain with no record of its own is governed by its organisational
// domain (RFC 7489 §6.6.3). Without that fallback a forger sidesteps
// p=reject by writing From: anything@mail.victim.example.
func (v *Verifier) lookupDMARC(ctx context.Context, fromDomain string) (*dmarc.Record, error) {
	lookup := func(domain string) (*dmarc.Record, error) {
		return dmarc.LookupWithOptions(domain, &dmarc.LookupOptions{
			LookupTXT: func(name string) ([]string, error) {
				return v.resolver.LookupTXT(ctx, name)
			},
		})
	}
	record, err := lookup(fromDomain)
	org := organizationalDomain(fromDomain)
	if !errors.Is(err, dmarc.ErrNoPolicy) || org == fromDomain {
		return record, err
	}
	record, err = lookup(org)
	if err == nil && record.SubdomainPolicy != "" {
		inherited := *record
		inherited.Policy = record.SubdomainPolicy
		record = &inherited
	}
	return record, err
}

// evaluateDMARC decides alignment from a looked-up record.
func evaluateDMARC(fromDomain string, record *dmarc.Record, err error, results Results) (Result, string, *DMARCPolicy) {
	out := Result{Method: "dmarc", Domain: fromDomain}
	if fromDomain == "" {
		out.Value = "none"
		return out, "", nil
	}
	if err != nil {
		// No record is "none": the domain has not asked for anything, which is
		// not a failure. A lookup that broke is "temperror" for the same reason
		// nothing else here fails closed.
		if err == dmarc.ErrNoPolicy {
			out.Value = "none"
			return out, "", nil
		}
		out.Value = "temperror"
		out.Reason = err.Error()
		return out, "", nil
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
	return out, policy, publishedPolicy(fromDomain, record, dkimAligned, spfAligned)
}

func publishedPolicy(domain string, record *dmarc.Record, dkimAligned, spfAligned bool) *DMARCPolicy {
	p := &DMARCPolicy{
		Domain:      domain,
		P:           string(record.Policy),
		SP:          string(record.SubdomainPolicy),
		Pct:         100,
		ADKIM:       "r",
		ASPF:        "r",
		RUA:         append([]string(nil), record.ReportURIAggregate...),
		DKIMAligned: dkimAligned,
		SPFAligned:  spfAligned,
	}
	if p.SP == "" {
		p.SP = p.P
	}
	if record.Percent != nil {
		p.Pct = *record.Percent
	}
	if record.DKIMAlignment == dmarc.AlignmentStrict {
		p.ADKIM = "s"
	}
	if record.SPFAlignment == dmarc.AlignmentStrict {
		p.ASPF = "s"
	}
	return p
}

// aligned reports whether an authenticated domain matches the From domain.
//
// Relaxed alignment — the default — accepts a shared organisational domain, so
// mail.example.com aligns with example.com. That is what lets an organisation
// send from a subdomain without publishing policy for every one of them.
//
// The organisational domain comes from the public suffix list rather than
// from comparing suffixes: suffix matching aligns victim.co.uk with anything
// that authenticates as co.uk, and fails to align siblings such as
// bounce.example.com and news.example.com.
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
	return organizationalDomain(authenticated) == organizationalDomain(from)
}

// organizationalDomain is the registrable domain (RFC 7489 §3.2). A name that
// is itself a public suffix, or that the list cannot place, is its own
// organisational domain, so it aligns only on an exact match.
func organizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return org
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

	arcPart := "arc=" + orNone(r.ARC.Value)
	parts = append(parts, arcPart)

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
	return fmt.Sprintf("spf=%s dkim=%d dmarc=%s arc=%s policy=%s disposition=%s",
		orNone(r.SPF.Value), len(r.DKIM), orNone(r.DMARC.Value), orNone(r.ARC.Value), r.Policy, r.Disposition)
}

// VerifyDKIM checks the signatures on a received message.
//
// Separate from Verify because it needs the message bytes while the rest needs
// only the envelope, and because a message with no signature is an ordinary
// state rather than a failure — most mail is unsigned.
func VerifyDKIM(ctx context.Context, message []byte) []Result {
	return verifyDKIM(ctx, message, net.DefaultResolver.LookupTXT)
}

// verifyDKIM does the work of VerifyDKIM with key lookups bound to ctx. The
// library's own default lookup takes no context, so a key server that never
// answers would hold the client at end-of-DATA for as long as the system
// resolver keeps retrying.
func verifyDKIM(ctx context.Context, message []byte, lookupTXT func(context.Context, string) ([]string, error)) []Result {
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(message), &dkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			return lookupTXT(ctx, name)
		},
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

	selectors := dkimSelectors(message)
	results := make([]Result, 0, len(verifications))
	for i, verification := range verifications {
		result := Result{Method: "dkim", Domain: verification.Domain, Value: "pass"}
		// The library verifies signatures in header order but does not report
		// the selector, so take it from the same header, checking d= matches
		// in case the two ever disagree.
		if i < len(selectors) && strings.EqualFold(selectors[i].domain, verification.Domain) {
			result.Selector = selectors[i].selector
		}
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

type dkimTags struct{ domain, selector string }

// dkimSelectors returns the d= and s= tags of each DKIM-Signature header, in
// header order.
func dkimSelectors(message []byte) []dkimTags {
	var out []dkimTags
	var field string
	flush := func() {
		name, value, ok := strings.Cut(field, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
			return
		}
		var tags dkimTags
		for _, tag := range strings.Split(value, ";") {
			k, v, ok := strings.Cut(tag, "=")
			if !ok {
				continue
			}
			v = strings.Join(strings.Fields(v), "")
			switch strings.TrimSpace(k) {
			case "d":
				tags.domain = v
			case "s":
				tags.selector = v
			}
		}
		out = append(out, tags)
	}
	for _, line := range strings.Split(string(headerBlock(message)), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			field += line
			continue
		}
		flush()
		field = line
	}
	flush()
	return out
}

// headerBlock is the message up to the blank line that ends the header.
func headerBlock(message []byte) []byte {
	if i := bytes.Index(message, []byte("\r\n\r\n")); i >= 0 {
		return message[:i]
	}
	if i := bytes.Index(message, []byte("\n\n")); i >= 0 {
		return message[:i]
	}
	return message
}

// HeaderFromDomain returns the domain of the message's single RFC 5322 From
// address, or "" when there is none or more than one: DMARC has no single
// answer for a message with several authors (RFC 7489 §6.6.1).
func HeaderFromDomain(message []byte) string {
	head := append(append([]byte(nil), headerBlock(message)...), "\r\n\r\n"...)
	msg, err := mail.ReadMessage(bytes.NewReader(head))
	if err != nil {
		return ""
	}
	if len(msg.Header["From"]) != 1 {
		return ""
	}
	addrs, err := mail.ParseAddressList(msg.Header.Get("From"))
	if err != nil || len(addrs) != 1 {
		return ""
	}
	return domainOf(addrs[0].Address)
}
