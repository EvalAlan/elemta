package api

// The DMARC page's view of the received reports: per domain, who sent mail
// in its name, how that went, and what's worth doing about it. Totals count
// verified reports only. Nothing here changes DNS or asks a third party
// about a sender: places come from the local location database.

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/gorilla/mux"
)

const (
	dmarcLookupTimeout = 4 * time.Second
	dmarcLookupsAtOnce = 8
	// dmarcReadyDays is how many days of verified reports it takes before
	// a stricter policy is suggested: two weeks takes in the senders that
	// only run weekly.
	dmarcReadyDays = 14

	sourceThisServer = "this server"
	sourceAligned    = "aligned sender"
	// DKIM alone is what a forwarder leaves, and also how most sending
	// services are set up; the report can't tell them apart.
	sourceDKIMOnly = "DKIM only: likely forwarder or sending service"
	sourceFailing  = "failing"
)

type dmarcDomainView struct {
	Domain   string                   `json:"domain"`
	Address  *mailpolicy.DMARCAddress `json:"address,omitempty"`
	Suggest  string                   `json:"suggested,omitempty"` // a local rua
	Policy   string                   `json:"policy,omitempty"`
	From     string                   `json:"policy_from,omitempty"`
	Checked  bool                     `json:"policy_checked"` // false: DNS didn't answer
	Messages int64                    `json:"messages"`
	Aligned  int64                    `json:"aligned"`
	// LastDay is the newest day a verified report covers.
	LastDay    string           `json:"last_report,omitempty"`
	Days       []dmarcDayView   `json:"daily"`
	Reporters  []dmarcReporter  `json:"reporters"`
	Unverified []dmarcReporter  `json:"unverified"`
	Sources    []dmarcSourceRow `json:"sources"`
	Advice     []dmarcAdvice    `json:"advice"`
	reportDays int
}

type dmarcDayView struct {
	Day     string `json:"day"`
	Aligned int64  `json:"aligned"`
	Failing int64  `json:"failing"`
}

type dmarcReporter struct {
	Sender   string `json:"sender"`
	Org      string `json:"org,omitempty"`
	Reports  int64  `json:"reports"`
	Messages int64  `json:"messages"`
}

type dmarcSourceRow struct {
	mailpolicy.DMARCSource
	Kind  string `json:"kind"`
	Place string `json:"place,omitempty"`
}

type dmarcAdvice struct {
	Level string `json:"level"` // warning or ok
	Text  string `json:"text"`
}

type dmarcInputs struct {
	domains   []string
	addresses []mailpolicy.DMARCAddress
	policies  map[string]dnshealth.DMARCPolicy // only those DNS answered
	hosted    func(string) bool
	days      []mailpolicy.DMARCDay
	sources   []mailpolicy.DMARCSource
	ours      map[string]bool
	place     func(string) string
	window    int
	now       time.Time
}

func buildDMARCReport(in dmarcInputs) []dmarcDomainView {
	out := make([]dmarcDomainView, 0, len(in.domains))
	for _, domain := range in.domains {
		v := dmarcDomainView{Domain: domain, Days: []dmarcDayView{}, Reporters: []dmarcReporter{}, Unverified: []dmarcReporter{}, Sources: []dmarcSourceRow{}, Advice: []dmarcAdvice{}}
		for _, a := range in.addresses {
			if a.Domain == domain {
				v.Address = &a
			}
		}
		if p, ok := in.policies[domain]; ok {
			v.Checked, v.Policy, v.From = true, p.Policy, p.From
			for _, a := range p.Reports {
				if _, host, _ := strings.Cut(a, "@"); in.hosted(host) {
					v.Suggest = a
					break
				}
			}
		}
		v.count(in)
		v.addSources(in)
		v.advise(in.window)
		out = append(out, v)
	}
	return out
}

func (v *dmarcDomainView) count(in dmarcInputs) {
	today := in.now.UTC().Truncate(24 * time.Hour)
	index := map[string]int{}
	for i := in.window - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		index[day] = len(v.Days)
		v.Days = append(v.Days, dmarcDayView{Day: day})
	}
	add := func(list []dmarcReporter, d mailpolicy.DMARCDay) []dmarcReporter {
		i := slices.IndexFunc(list, func(r dmarcReporter) bool { return r.Sender == d.Sender })
		if i < 0 {
			list = append(list, dmarcReporter{Sender: d.Sender, Org: d.Org})
			i = len(list) - 1
		}
		list[i].Reports += d.Reports
		list[i].Messages += d.Messages
		return list
	}
	seen := map[string]bool{}
	for _, d := range in.days {
		if d.Domain != v.Domain {
			continue
		}
		if !d.Verified {
			v.Unverified = add(v.Unverified, d)
			continue
		}
		v.Reporters = add(v.Reporters, d)
		v.Messages += d.Messages
		v.Aligned += d.Aligned
		seen[d.Day] = true
		if d.Day >= v.LastDay {
			v.LastDay = d.Day
			if !v.Checked {
				// DNS didn't answer; what reporters saw is the next best.
				v.Policy = d.P
				if d.SP != "" && d.PolicyDomain != v.Domain {
					v.Policy = d.SP
				}
			}
		}
		if i, ok := index[d.Day]; ok {
			v.Days[i].Aligned += d.Aligned
			v.Days[i].Failing += d.Messages - d.Aligned
		}
	}
	v.reportDays = len(seen)
	byVolume := func(a, b dmarcReporter) int {
		return cmp.Or(cmp.Compare(b.Messages, a.Messages), cmp.Compare(a.Sender, b.Sender))
	}
	slices.SortFunc(v.Reporters, byVolume)
	slices.SortFunc(v.Unverified, byVolume)
}

func passedDMARC(s mailpolicy.DMARCSource) bool { return s.DKIM == "pass" || s.SPF == "pass" }

func (v *dmarcDomainView) addSources(in dmarcInputs) {
	for _, s := range in.sources {
		if s.Domain != v.Domain || !s.Verified {
			continue
		}
		row := dmarcSourceRow{DMARCSource: s, Kind: sourceFailing}
		switch {
		case in.ours[s.SourceIP]:
			row.Kind = sourceThisServer
		case s.SPF == "pass":
			row.Kind = sourceAligned
		case s.DKIM == "pass":
			row.Kind = sourceDKIMOnly
		}
		if in.place != nil {
			row.Place = in.place(s.SourceIP)
		}
		v.Sources = append(v.Sources, row)
	}
}

// advise says what to do. Forged mail fails by design, so failing alone is
// no problem; what matters is failing mail that looks like the domain's own.
func (v *dmarcDomainView) advise(window int) {
	passes := map[string]bool{}
	for _, s := range v.Sources {
		if passedDMARC(s.DMARCSource) {
			passes[s.SourceIP] = true
		}
	}
	type problem struct {
		ip, why string
		count   int64
	}
	var problems []problem
	for _, s := range v.Sources {
		if passedDMARC(s.DMARCSource) {
			continue
		}
		why := ""
		switch {
		case s.Kind == sourceThisServer:
			why = "is this server: check the domain's DKIM signing and SPF record"
		case passes[s.SourceIP]:
			why = "also sends mail that passes, so it's probably yours and partly misconfigured"
		case s.DKIMDomain != "" && (s.DKIMDomain == v.Domain || strings.HasSuffix(s.DKIMDomain, "."+v.Domain)):
			why = "signs as this domain but the signature fails: a wrong key, or mail changed on the way"
		default:
			continue
		}
		if i := slices.IndexFunc(problems, func(p problem) bool { return p.ip == s.SourceIP }); i >= 0 {
			problems[i].count += s.Messages
			continue
		}
		problems = append(problems, problem{s.SourceIP, why, s.Messages})
	}
	slices.SortStableFunc(problems, func(a, b problem) int { return cmp.Compare(b.count, a.count) })
	for i, p := range problems {
		if i == 5 {
			v.Advice = append(v.Advice, dmarcAdvice{"warning", fmt.Sprintf("%d more legitimate-looking sources are failing.", len(problems)-i)})
			break
		}
		v.Advice = append(v.Advice, dmarcAdvice{"warning", fmt.Sprintf("Legitimate-looking source failing: %s (%d messages) %s.", p.ip, p.count, p.why)})
	}
	if len(problems) > 0 || v.Aligned == 0 || window < dmarcReadyDays || v.reportDays < dmarcReadyDays {
		return
	}
	next := map[string]string{"none": "p=quarantine", "quarantine": "p=reject"}[v.Policy]
	if next == "" {
		return
	}
	where := ""
	if v.From != "" && v.From != v.Domain {
		where = " (the policy is inherited from " + v.From + ")"
	}
	v.Advice = append(v.Advice, dmarcAdvice{"ok", fmt.Sprintf(
		"Ready to tighten to %s%s: %d days of verified reports, and no legitimate-looking source failing. First check that none of the failing sources below is yours.", next, where, v.reportDays)})
}

func lookupPublishedDMARC(ctx context.Context, domain string) (dnshealth.DMARCPolicy, error) {
	return dnshealth.LookupDMARC(ctx, dnsCheckResolver(), domain)
}

// publishedPolicies asks DNS about each domain. One it didn't answer for is
// left out, which isn't the same as having no policy.
func (s *Server) publishedPolicies(ctx context.Context, domains []string) map[string]dnshealth.DMARCPolicy {
	lookup := s.dmarcLookup
	if lookup == nil {
		lookup = lookupPublishedDMARC
	}
	out := map[string]dnshealth.DMARCPolicy{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(ctx, 3*dmarcLookupTimeout)
	defer cancel()
	slots := make(chan struct{}, dmarcLookupsAtOnce)
	for _, d := range domains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			c, cancel := context.WithTimeout(ctx, dmarcLookupTimeout)
			defer cancel()
			if p, err := lookup(c, d); err == nil {
				mu.Lock()
				out[d] = p
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// serverAddresses are the mail host's, which is how this server appears in
// other people's reports.
func (s *Server) serverAddresses(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	if s.mainConfig == nil || s.mainConfig.Hostname == "" {
		return out
	}
	lookup := s.hostLookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return dnsCheckResolver().LookupIPAddr(ctx, host)
		}
	}
	c, cancel := context.WithTimeout(ctx, dmarcLookupTimeout)
	defer cancel()
	addrs, err := lookup(c, s.mainConfig.Hostname)
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out[ip.Unmap().String()] = true
		}
	}
	return out
}

func (s *Server) sourcePlace(ip string) string {
	p, ok := s.locations.Locate(net.ParseIP(ip))
	if !ok {
		return ""
	}
	if p.City != "" {
		return p.City + ", " + p.Country
	}
	return p.Country
}

func (s *Server) dmarcReportRoutes(protected *mux.Router) {
	protected.HandleFunc("/dmarc/report", s.provisionCall(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		selected, window, err := dmarcSelection(r)
		if err != nil {
			return err
		}
		c, err := s.provisioner.MailboxAdmin()
		if err != nil {
			return err
		}
		all, err := s.provisioner.Domains(ctx)
		if err != nil {
			return err
		}
		sc := scopeOf(r)
		hosted := map[string]bool{}
		var domains []string
		for _, d := range all {
			if !d.Configured {
				continue
			}
			hosted[d.Name] = true
			if sc.domain(d.Name) && (len(selected) == 0 || slices.Contains(selected, d.Name)) {
				domains = append(domains, d.Name)
			}
		}
		slices.Sort(domains)
		in := dmarcInputs{domains: domains, hosted: func(d string) bool { return hosted[d] }, window: window, now: time.Now()}
		if len(domains) > 0 {
			if in.addresses, err = c.DMARCAddresses(ctx); err != nil {
				return err
			}
			if in.days, err = c.DMARCSummary(ctx, selected, window); err != nil {
				return err
			}
			if in.sources, err = c.DMARCSources(ctx, selected, window); err != nil {
				return err
			}
			in.policies, in.ours = s.publishedPolicies(ctx, domains), s.serverAddresses(ctx)
			if s.locations != nil {
				in.place = s.sourcePlace
			}
		}
		writeJSON(w, map[string]any{"days": window, "manage": sc.all, "locations": s.locations != nil, "domains": buildDMARCReport(in)})
		return nil
	})).Methods("GET")
}
