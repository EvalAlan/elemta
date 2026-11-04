// Package dnshealth checks whether a domain's public DNS lets it send and
// receive mail through this server.
//
// Each check answers one question and, when the answer is bad, says what to
// publish. A DNS failure is reported as StatusUnknown, never as a missing
// record: telling someone to add a record they already have, because their
// resolver had a bad moment, would send them to change working DNS.
package dnshealth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/EvalAlan/elemta/internal/delivery"
	"github.com/EvalAlan/elemta/internal/dkim"
	"golang.org/x/net/publicsuffix"
)

// Status is how one check came out, or the worst of them for a report.
type Status string

const (
	StatusOK      Status = "ok"
	StatusInfo    Status = "info"    // optional, and not set up
	StatusUnknown Status = "unknown" // DNS didn't answer, so this says nothing
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
)

// severity orders statuses for the overall result. Unknown sits above ok so a
// check that couldn't run never leaves a report looking clean.
var severity = map[Status]int{StatusOK: 0, StatusInfo: 0, StatusUnknown: 1, StatusWarn: 2, StatusFail: 3}

// Check is one question about the domain.
type Check struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Found   []string `json:"found,omitempty"`
	// Fix says what to change; Record is the value to publish, when there is
	// one exact answer.
	Fix    string `json:"fix,omitempty"`
	Record string `json:"record,omitempty"`
}

// Report is the outcome for one domain.
type Report struct {
	Domain   string    `json:"domain"`
	Hostname string    `json:"hostname"`
	Status   Status    `json:"status"`
	Checked  time.Time `json:"checked"`
	Checks   []Check   `json:"checks"`
}

// Resolver is what the checks ask of DNS. *net.Resolver satisfies it.
type Resolver interface {
	spf.DNSResolver
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// DKIMKey is a key the domain signs with.
type DKIMKey struct {
	Name   string // the DNS name it belongs at
	Record string // the record to publish there
}

// How the domain's mail is being signed.
const (
	SigningOn  = "on"
	SigningOff = "off" // switched off, for the domain or the whole server
	SigningNo  = "no-key"
)

// Options describes the domain and the server it should reach.
type Options struct {
	Domain string
	// Hostname is this server's mail host. Its addresses are how the checks
	// recognise this server, so a domain can point at any name for it.
	Hostname string
	Signing  string
	DKIMKeys []DKIMKey
	Resolver Resolver
	// FetchMTASTS returns the domain's policy file; nil fetches it over HTTPS.
	FetchMTASTS func(ctx context.Context, domain string) (string, error)
}

// Run checks the domain. Every check runs even if another fails, because
// someone fixing DNS wants the whole list at once.
func Run(ctx context.Context, o Options) Report {
	if o.FetchMTASTS == nil {
		o.FetchMTASTS = fetchMTASTS
	}
	c := &checker{Options: o}
	c.serverIPs, c.serverErr = c.addresses(ctx, o.Hostname)

	checks := []func(context.Context) Check{c.mx, c.reverseDNS, c.spf, c.dkim, c.dmarc, c.mtaSTS, c.tlsRPT, c.autoconfig}
	report := Report{Domain: o.Domain, Hostname: o.Hostname, Status: StatusOK, Checked: time.Now().UTC(), Checks: make([]Check, len(checks))}
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report.Checks[i] = check(ctx)
		}()
	}
	wg.Wait()
	for _, check := range report.Checks {
		if severity[check.Status] > severity[report.Status] {
			report.Status = check.Status
		}
	}
	return report
}

type checker struct {
	Options
	serverIPs []net.IP
	serverErr error
}

func notFound(err error) bool {
	var failed *net.DNSError
	return errors.As(err, &failed) && failed.IsNotFound
}

func dnsProblem(err error) string {
	var failed *net.DNSError
	if errors.As(err, &failed) {
		return failed.Err
	}
	return err.Error()
}

// addresses treats "no such name" as an empty answer, because callers word
// that differently from a lookup that failed.
func (c *checker) addresses(ctx context.Context, host string) ([]net.IP, error) {
	found, err := c.Resolver.LookupIPAddr(ctx, host)
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(found))
	for _, a := range found {
		out = append(out, a.IP)
	}
	return out, nil
}

func trimDot(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// txt returns the records at name starting with prefix. Like addresses, a name
// that doesn't exist is simply none.
func (c *checker) txt(ctx context.Context, name, prefix string) ([]string, error) {
	records, err := c.Resolver.LookupTXT(ctx, name)
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (c *checker) mx(ctx context.Context) Check {
	check := Check{ID: "mx", Name: "Incoming mail (MX)"}
	publish := func() {
		check.Fix = "Publish an MX record for " + c.Domain + "."
		check.Record = "10 " + c.Hostname + "."
	}
	records, err := c.Resolver.LookupMX(ctx, c.Domain)
	if err != nil && !notFound(err) {
		check.Status, check.Summary = StatusUnknown, "The MX lookup failed: "+dnsProblem(err)
		return check
	}
	if len(records) == 0 {
		check.Status, check.Summary = StatusFail, "No MX record, so this domain can't reliably receive mail."
		publish()
		return check
	}
	records = slices.Clone(records)
	slices.SortStableFunc(records, func(a, b *net.MX) int { return int(a.Pref) - int(b.Pref) })

	best, here, broken := records[0].Pref, false, false
	primaryHere := false
	for _, r := range records {
		host := trimDot(r.Host)
		ips, err := c.addresses(ctx, host)
		line := fmt.Sprintf("%d %s", r.Pref, host)
		switch {
		case host == "":
			check.Status, check.Summary = StatusFail, "The domain publishes a null MX, which says it accepts no mail."
			check.Found = []string{"0 ."}
			publish()
			return check
		case err != nil:
			line += " (lookup failed: " + dnsProblem(err) + ")"
			check.Found = append(check.Found, line)
			continue
		case len(ips) == 0:
			broken = true
			line += " (has no address)"
		default:
			line += " → " + joinIPs(ips)
		}
		check.Found = append(check.Found, line)
		if overlaps(ips, c.serverIPs) {
			here = true
			primaryHere = primaryHere || r.Pref == best
		}
	}
	switch {
	case c.serverErr != nil || len(c.serverIPs) == 0:
		check.Status, check.Summary = StatusUnknown, "An MX is published, but "+c.Hostname+" has no address to compare it with."
	case !here:
		check.Status, check.Summary = StatusFail, "The MX doesn't point at this server, so mail for this domain goes elsewhere."
		check.Fix = "Point the MX at this server when you're ready to move mail here."
		check.Record = "10 " + c.Hostname + "."
	case broken:
		check.Status, check.Summary = StatusWarn, "One MX host has no address, so senders waste a try on it."
		check.Fix = "Remove that MX record or give the host an address."
	case !primaryHere:
		check.Status, check.Summary = StatusWarn, "This server is only a backup MX: mail goes to another host first."
	default:
		check.Status, check.Summary = StatusOK, "Incoming mail reaches this server."
	}
	return check
}

func joinIPs(ips []net.IP) string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return strings.Join(out, ", ")
}

func overlaps(a, b []net.IP) bool {
	return slices.ContainsFunc(a, func(ip net.IP) bool {
		return slices.ContainsFunc(b, ip.Equal)
	})
}

// reverseDNS is about the server rather than the domain, but receivers judge
// each domain's mail by it, and it's the record people forget because it's
// set at the hosting provider rather than in the zone.
func (c *checker) reverseDNS(ctx context.Context) Check {
	check := Check{ID: "ptr", Name: "Reverse DNS", Status: StatusOK}
	if c.serverErr != nil || len(c.serverIPs) == 0 {
		check.Status, check.Summary = StatusUnknown, c.Hostname+" has no address to check."
		return check
	}
	raise := func(s Status) {
		if severity[s] > severity[check.Status] {
			check.Status = s
		}
	}
	var missing, wrong []string
	for _, ip := range c.serverIPs {
		names, err := c.Resolver.LookupAddr(ctx, ip.String())
		if err != nil && !notFound(err) {
			raise(StatusUnknown)
			check.Found = append(check.Found, ip.String()+" (lookup failed: "+dnsProblem(err)+")")
			continue
		}
		if len(names) == 0 {
			missing = append(missing, ip.String())
			check.Found = append(check.Found, ip.String()+" → nothing")
			continue
		}
		name := trimDot(names[0])
		check.Found = append(check.Found, ip.String()+" → "+name)
		forward, err := c.addresses(ctx, name)
		if err != nil {
			raise(StatusUnknown)
			continue
		}
		if !slices.ContainsFunc(forward, ip.Equal) {
			missing = append(missing, ip.String())
			continue
		}
		if name != trimDot(c.Hostname) {
			wrong = append(wrong, ip.String())
		}
	}
	switch {
	case len(missing) > 0:
		raise(StatusFail)
		check.Summary = "Large receivers refuse or junk mail from an address without matching reverse DNS."
		check.Fix = "At your hosting provider, set the reverse DNS of " + strings.Join(missing, ", ") + " to " + c.Hostname + ", and make sure that name resolves back to it."
	case len(wrong) > 0:
		raise(StatusWarn)
		check.Summary = "Reverse DNS works, but doesn't match the name this server gives when it sends mail."
		check.Fix = "Set the reverse DNS of " + strings.Join(wrong, ", ") + " to " + c.Hostname + "."
	case check.Status == StatusOK:
		check.Summary = "This server's address maps to its name and back."
	default:
		check.Summary = "Reverse DNS couldn't be fully checked."
	}
	return check
}

var spfAll = regexp.MustCompile(`(?i)(^|\s)([+?~-]?)all(\s|$)`)

func (c *checker) spf(ctx context.Context) Check {
	check := Check{ID: "spf", Name: "Sending permission (SPF)"}
	suggestion := "v=spf1 mx -all"
	records, err := c.txt(ctx, c.Domain, "v=spf1")
	if err != nil {
		check.Status, check.Summary = StatusUnknown, "The SPF lookup failed: "+dnsProblem(err)
		return check
	}
	check.Found = records
	switch len(records) {
	case 0:
		check.Status, check.Summary = StatusFail, "No SPF record, so receivers can't tell this server may send for the domain."
		check.Fix, check.Record = "Publish this TXT record at "+c.Domain+".", suggestion
		return check
	case 1:
	default:
		check.Status, check.Summary = StatusFail, "More than one SPF record, which makes SPF fail for every message."
		check.Fix = "Merge them into a single TXT record."
		return check
	}
	if m := spfAll.FindStringSubmatch(records[0]); m != nil && (m[2] == "" || m[2] == "+") {
		check.Status, check.Summary = StatusFail, "The record ends in +all, which lets anyone send as this domain."
		check.Fix, check.Record = "Replace it with a record that names your servers.", suggestion
		return check
	}
	if c.serverErr != nil || len(c.serverIPs) == 0 {
		check.Status, check.Summary = StatusUnknown, "An SPF record is published, but "+c.Hostname+" has no address to test it with."
		return check
	}
	check.Status, check.Summary = StatusOK, "This server may send for the domain."
	for _, ip := range c.serverIPs {
		result, err := spf.CheckHostWithSender(ip, c.Hostname, "postmaster@"+c.Domain, spf.WithContext(ctx), spf.WithResolver(c.Resolver))
		switch result {
		case spf.Pass:
		case spf.TempError:
			check.Status, check.Summary = StatusUnknown, "SPF couldn't be evaluated: a lookup failed."
		case spf.PermError:
			check.Status, check.Summary = StatusFail, "The record is broken: "+err.Error()+". Receivers treat that as a failure."
			check.Fix = "Fix the record. Too many include: or mx mechanisms is the usual cause."
			return check
		default:
			check.Status = StatusFail
			if result == spf.SoftFail || result == spf.Neutral {
				check.Status = StatusWarn
			}
			check.Summary = fmt.Sprintf("The record doesn't cover this server (%s gives %s).", ip, result)
			check.Fix = "Add this server to the record: mx if the MX points here, or ip4:/ip6: with its address."
			return check
		}
	}
	return check
}

func (c *checker) dkim(ctx context.Context) Check {
	check := Check{ID: "dkim", Name: "Signatures (DKIM)"}
	switch c.Signing {
	case SigningOff:
		check.Status, check.Summary = StatusWarn, "Signing is off, so this domain's mail goes out unsigned."
		check.Fix = "Turn signing back on under the domain's keys."
		return check
	case SigningOn:
	default:
		check.Status, check.Summary = StatusFail, "No signing key, so this domain's mail goes out unsigned."
		check.Fix = "Generate a key under the domain's keys, publish it, then sign with it."
		return check
	}
	check.Status, check.Summary = StatusOK, "The published key matches the one this server signs with."
	for _, key := range c.DKIMKeys {
		if key.Record == "" {
			check.Status, check.Summary = StatusUnknown, "This server can't read the signing key at "+key.Name+", so it can't be compared."
			continue
		}
		state, found, err := dkim.CheckDNS(ctx, c.Resolver.LookupTXT, key.Name, key.Record)
		if err != nil {
			check.Status, check.Summary = StatusUnknown, "The lookup of "+key.Name+" failed: "+dnsProblem(err)
			continue
		}
		if found != "" {
			check.Found = append(check.Found, found)
		}
		switch state {
		case dkim.DNSMissing:
			check.Status, check.Summary = StatusFail, "The signing key isn't published, so signatures can't be verified."
			check.Fix, check.Record = "Publish this TXT record at "+key.Name+".", key.Record
			return check
		case dkim.DNSMismatch:
			check.Status, check.Summary = StatusFail, "DNS has a different key, so every signature fails."
			check.Fix, check.Record = "Replace the TXT record at "+key.Name+" with this one.", key.Record
			return check
		}
	}
	return check
}

func dmarcTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// dmarc follows RFC 7489: a domain without a record of its own is covered by
// its organizational domain's, and sp, when set, overrides p for subdomains.
func (c *checker) dmarc(ctx context.Context) Check {
	check := Check{ID: "dmarc", Name: "Forgery policy (DMARC)"}
	suggestion := "v=DMARC1; p=quarantine; rua=mailto:postmaster@" + c.Domain
	missing := func() Check {
		check.Status, check.Summary = StatusWarn, "No DMARC policy, so receivers decide for themselves what to do with forged mail."
		check.Fix, check.Record = "Publish this TXT record at _dmarc."+c.Domain+".", suggestion
		return check
	}
	records, err := c.txt(ctx, "_dmarc."+c.Domain, "v=dmarc1")
	if err != nil {
		check.Status, check.Summary = StatusUnknown, "The DMARC lookup failed: "+dnsProblem(err)
		return check
	}
	inherited := ""
	if len(records) == 0 {
		org, orgErr := publicsuffix.EffectiveTLDPlusOne(c.Domain)
		if orgErr != nil || org == c.Domain {
			return missing()
		}
		if records, err = c.txt(ctx, "_dmarc."+org, "v=dmarc1"); err != nil {
			check.Status, check.Summary = StatusUnknown, "The DMARC lookup failed: "+dnsProblem(err)
			return check
		}
		if len(records) == 0 {
			return missing()
		}
		inherited = org
	}
	check.Found = records
	if len(records) > 1 {
		check.Status, check.Summary = StatusFail, "More than one DMARC record, so receivers ignore the policy."
		check.Fix = "Keep one record at _dmarc." + c.Domain + "."
		return check
	}
	tags := dmarcTags(records[0])
	policy := tags["p"]
	if sp := tags["sp"]; inherited != "" && sp != "" {
		policy = sp
	}
	from := ""
	if inherited != "" {
		from = " (inherited from " + inherited + ")"
	}
	switch policy {
	case "reject", "quarantine":
		check.Status, check.Summary = StatusOK, "Forged mail is "+map[string]string{"reject": "rejected", "quarantine": "quarantined"}[policy]+from+"."
		if pct, err := strconv.Atoi(tags["pct"]); err == nil && pct < 100 {
			check.Status, check.Summary = StatusWarn, fmt.Sprintf("The %s policy only covers %d%% of mail%s.", policy, pct, from)
		}
		if check.Status == StatusOK && tags["rua"] == "" {
			check.Summary += " No reports are requested (rua), so you won't see who sends as this domain."
		}
	case "none":
		check.Status, check.Summary = StatusWarn, "The policy is p=none"+from+", which only monitors: forged mail is still delivered."
		check.Fix = "Move to p=quarantine once reports show your own mail passing."
	default:
		check.Status, check.Summary = StatusFail, "The record has no valid policy, so receivers ignore it."
		check.Fix, check.Record = "Replace it with this one.", suggestion
	}
	return check
}

func fetchMTASTS(ctx context.Context, domain string) (string, error) {
	client := &http.Client{
		Timeout: 6 * time.Second,
		// RFC 8461 section 3.3: a redirect is not a policy.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTPS returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(body), err
}

// fetchProblem drops the method and URL Go wraps around a failed request; the
// sentence reporting it already names the address.
func fetchProblem(err error) string {
	var failed *url.Error
	if errors.As(err, &failed) {
		return failed.Err.Error()
	}
	return err.Error()
}

func (c *checker) mtaSTS(ctx context.Context) Check {
	check := Check{ID: "mta-sts", Name: "Encryption policy (MTA-STS)"}
	records, err := c.txt(ctx, "_mta-sts."+c.Domain, "v=stsv1")
	if err != nil {
		check.Status, check.Summary = StatusUnknown, "The MTA-STS lookup failed: "+dnsProblem(err)
		return check
	}
	if len(records) == 0 {
		check.Status, check.Summary = StatusInfo, "Not set up. Optional: it stops attackers downgrading incoming mail to unencrypted."
		return check
	}
	check.Found = records
	text, err := c.FetchMTASTS(ctx, c.Domain)
	if err != nil {
		// The failure that matters most: senders that fetched an earlier
		// policy keep enforcing it until max_age runs out, and this one can't
		// replace it.
		check.Status, check.Summary = StatusFail, "DNS advertises a policy, but https://mta-sts."+c.Domain+" can't serve it: "+fetchProblem(err)+"."
		check.Fix = "Serve the policy from that name with a valid certificate, or remove the _mta-sts record. Senders that saved an older policy keep following it until it expires."
		return check
	}
	policy := delivery.ParseMTASTSPolicy(text)
	if policy == nil {
		check.Status, check.Summary = StatusFail, "The policy file can't be read as an MTA-STS policy."
		check.Fix = "Serve a valid policy at https://mta-sts." + c.Domain + "/.well-known/mta-sts.txt."
		return check
	}
	check.Found = append(check.Found, "mode: "+policy.Mode, "mx: "+strings.Join(policy.MX, ", "))
	if policy.Mode == "none" {
		check.Status, check.Summary = StatusOK, "The policy is published with mode none, so it asks nothing of senders."
		return check
	}
	mx, err := c.Resolver.LookupMX(ctx, c.Domain)
	if err != nil {
		check.Status, check.Summary = StatusUnknown, "The policy was read, but it can't be compared with the MX."
		return check
	}
	var unlisted []string
	for _, r := range mx {
		if host := trimDot(r.Host); !policy.MatchesMX(host) {
			unlisted = append(unlisted, host)
		}
	}
	switch {
	case len(unlisted) == 0:
		check.Status, check.Summary = StatusOK, "The policy lists every MX, in "+policy.Mode+" mode."
	case policy.Mode == "enforce":
		check.Status = StatusFail
		check.Summary = "The enforce policy doesn't list " + strings.Join(unlisted, ", ") + ", so senders that honour it refuse to deliver there."
		check.Fix = "Add mx: " + unlisted[0] + " to the policy and change the id in the _mta-sts record."
	default:
		check.Status, check.Summary = StatusWarn, "The testing policy doesn't list "+strings.Join(unlisted, ", ")+"."
		check.Fix = "Add mx: " + unlisted[0] + " to the policy and change the id in the _mta-sts record."
	}
	return check
}

func (c *checker) tlsRPT(ctx context.Context) Check {
	check := Check{ID: "tls-rpt", Name: "Encryption reports (TLS-RPT)"}
	records, err := c.txt(ctx, "_smtp._tls."+c.Domain, "v=tlsrptv1")
	switch {
	case err != nil:
		check.Status, check.Summary = StatusUnknown, "The TLS-RPT lookup failed: "+dnsProblem(err)
	case len(records) == 0:
		check.Status, check.Summary = StatusInfo, "Not set up. Optional: senders report TLS problems reaching this domain."
		check.Record = "v=TLSRPTv1; rua=mailto:postmaster@" + c.Domain
		check.Fix = "To turn it on, publish this TXT record at _smtp._tls." + c.Domain + "."
	case len(records) > 1:
		check.Found = records
		check.Status, check.Summary = StatusWarn, "More than one TLS-RPT record, so senders ignore them."
		check.Fix = "Keep one record at _smtp._tls." + c.Domain + "."
	default:
		check.Found = records
		check.Status, check.Summary = StatusOK, "Senders report TLS problems to the address published."
	}
	return check
}

// autoconfig looks at what mail apps use to find the server. Being absent only
// means people type the settings in, so it's never worse than a note.
func (c *checker) autoconfig(ctx context.Context) Check {
	check := Check{ID: "autoconfig", Name: "Mail app setup (SRV)", Status: StatusOK, Summary: "Mail apps can find this server."}
	var missing []string
	for _, service := range []string{"imaps", "submission"} {
		_, records, err := c.Resolver.LookupSRV(ctx, service, "tcp", c.Domain)
		name := "_" + service + "._tcp." + c.Domain
		switch {
		case err != nil && !notFound(err):
			check.Status, check.Summary = StatusUnknown, "The lookup of "+name+" failed: "+dnsProblem(err)
			return check
		case len(records) == 0:
			missing = append(missing, name)
		default:
			check.Found = append(check.Found, fmt.Sprintf("%s → %s:%d", name, trimDot(records[0].Target), records[0].Port))
		}
	}
	if len(missing) > 0 {
		check.Status, check.Summary = StatusInfo, "Not fully set up. Optional: without it, some mail apps need their settings typed in."
		check.Fix = "To add it, publish SRV records at " + strings.Join(missing, " and ") + "."
	}
	return check
}
