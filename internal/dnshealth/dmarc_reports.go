package dnshealth

// Where a domain's DMARC reports are asked to go, and whether receivers will
// send them there.

import (
	"context"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DMARCPolicy is the record in effect for a domain.
type DMARCPolicy struct {
	// From is the domain that publishes the record: the domain itself or its
	// organizational domain. Empty when there is none.
	From   string `json:"from,omitempty"`
	Policy string `json:"policy,omitempty"`
	// Reports are the mail addresses in rua.
	Reports []string `json:"reports,omitempty"`
}

// LookupDMARC finds the policy covering domain. An error is DNS not
// answering, which says nothing about the policy.
func LookupDMARC(ctx context.Context, r Resolver, domain string) (DMARCPolicy, error) {
	c := &checker{Options: Options{Domain: domain, Resolver: r}}
	return c.publishedDMARC(ctx)
}

func (c *checker) publishedDMARC(ctx context.Context) (DMARCPolicy, error) {
	from := c.Domain
	records, err := c.txt(ctx, "_dmarc."+from, "v=dmarc1")
	if err != nil {
		return DMARCPolicy{}, err
	}
	if len(records) == 0 {
		org, err := publicsuffix.EffectiveTLDPlusOne(c.Domain)
		if err != nil || org == c.Domain {
			// A name with no organizational domain has no parent to ask.
			return DMARCPolicy{}, nil
		}
		from = org
		if records, err = c.txt(ctx, "_dmarc."+from, "v=dmarc1"); err != nil {
			return DMARCPolicy{}, err
		}
	}
	if len(records) != 1 {
		return DMARCPolicy{}, nil // none, or several, which receivers ignore
	}
	tags := dmarcTags(records[0])
	out := DMARCPolicy{From: from, Policy: strings.ToLower(tags["p"])}
	if sp := tags["sp"]; sp != "" && from != c.Domain {
		out.Policy = strings.ToLower(sp)
	}
	for _, uri := range strings.Split(tags["rua"], ",") {
		uri = strings.TrimSpace(uri)
		if len(uri) < len("mailto:") || !strings.EqualFold(uri[:len("mailto:")], "mailto:") {
			continue
		}
		address, _, _ := strings.Cut(uri[len("mailto:"):], "!") // a size limit
		if local, host, ok := strings.Cut(address, "@"); ok && local != "" && host != "" {
			out.Reports = append(out.Reports, strings.ToLower(strings.TrimSuffix(address, ".")))
		}
	}
	return out, nil
}

// dmarcReports checks RFC 7489 §7.1: a receiver sends reports to another
// organization's address only if that organization publishes a record saying
// it takes them. Without it they are silently not sent.
func (c *checker) dmarcReports(ctx context.Context) Check {
	check := Check{ID: "dmarc-reports", Name: "DMARC report delivery"}
	p, err := c.publishedDMARC(ctx)
	if err != nil {
		check.Status, check.Summary = StatusUnknown, "The DMARC lookup failed: "+dnsProblem(err)
		return check
	}
	if len(p.Reports) == 0 {
		check.Status, check.Summary = StatusInfo, "No DMARC reports are requested by mail."
		return check
	}
	var missing, hosts []string
	for _, address := range p.Reports {
		_, host, _ := strings.Cut(address, "@")
		if slices.Contains(hosts, host) || sameOrganization(host, p.From) {
			continue
		}
		hosts = append(hosts, host)
		name := p.From + "._report._dmarc." + host
		records, err := c.txt(ctx, name, "v=dmarc1")
		if err != nil {
			check.Status, check.Summary = StatusUnknown, "The lookup of "+name+" failed: "+dnsProblem(err)
			return check
		}
		if len(records) == 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		check.Status, check.Summary = StatusOK, "Receivers can send reports to "+strings.Join(p.Reports, ", ")+"."
		return check
	}
	check.Status = StatusWarn
	check.Summary = "Receivers won't send DMARC reports to an address in another domain until that domain agrees to take them."
	check.Fix = "Publish this TXT record at " + strings.Join(missing, ". and at ") + "."
	check.Record = "v=DMARC1"
	return check
}

func sameOrganization(a, b string) bool {
	org := func(d string) string {
		if o, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
			return o
		}
		return d
	}
	return strings.EqualFold(org(a), org(b))
}
