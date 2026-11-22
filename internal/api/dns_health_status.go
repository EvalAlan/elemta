package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
)

// dnsCheckResolver is the resolver the DNS checks ask. They must see what
// the rest of the internet sees, and inside Compose the default resolver is
// Docker's, which answers container names and network aliases itself. When
// one of those is a hosted domain (the cloud overlay used to give the MTA
// the mail domain as an alias), Docker says that domain has no MX and
// points it at a private address. ELEMTA_DNS_CHECK_RESOLVER names a DNS
// server to ask directly instead, an address with an optional port; the
// compose files set it to the stack's own resolver.
var dnsCheckResolver = sync.OnceValue(newDNSCheckResolver)

func newDNSCheckResolver() dnshealth.Resolver {
	addr := strings.TrimSpace(os.Getenv("ELEMTA_DNS_CHECK_RESOLVER"))
	if addr == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

// dnsWatchStale is when the Health page says the scheduled check has
// stopped: two missed sweeps, so one slow or skipped run doesn't alarm.
const dnsWatchStale = 2*dnsWatchEvery + time.Hour

// DNSHealthStatus is the Health page's DNS card: what the last scheduled
// check found for each hosted domain the viewer manages.
type DNSHealthStatus struct {
	Status  string            `json:"status"` // ok, warning or unknown
	Message string            `json:"message"`
	Checked string            `json:"checked,omitempty"`
	Domains []DNSHealthDomain `json:"domains"`
}

type DNSHealthDomain struct {
	Domain string `json:"domain"`
	// ok, warning (only warnings) or critical (something fails).
	Status   string            `json:"status"`
	Since    string            `json:"since,omitempty"`
	Problems []dnshealth.Check `json:"problems,omitempty"`
}

func (s *Server) dnsHealthStatus(now time.Time, visible func(string) bool) DNSHealthStatus {
	st := DNSHealthStatus{Status: "unknown", Domains: []DNSHealthDomain{}}
	if s.provisioner == nil {
		st.Message = "Scheduled DNS checks need mail administration set up."
		return st
	}
	f := s.loadDNSWatch()
	if f.Checked.IsZero() {
		st.Message = fmt.Sprintf("Not checked yet. The first scheduled check runs %s after the admin console starts, then every %s.", dnsWatchFirst, dnsWatchEvery)
		return st
	}
	st.Checked = f.Checked.UTC().Format(time.RFC3339)
	bad := 0
	for name, rec := range f.Domains {
		if !visible(name) {
			continue
		}
		d := DNSHealthDomain{Domain: name, Status: "ok", Problems: rec.Checks}
		if len(rec.Problems) > 0 {
			bad++
			d.Status = "warning"
			for _, c := range rec.Checks {
				if c.Status == dnshealth.StatusFail {
					d.Status = "critical"
				}
			}
		}
		if rec.Since != nil {
			d.Since = rec.Since.UTC().Format(time.RFC3339)
		}
		st.Domains = append(st.Domains, d)
	}
	// Problems first, so the card leads with what needs doing.
	rank := map[string]int{"critical": 0, "warning": 1, "ok": 2}
	slices.SortFunc(st.Domains, func(a, b DNSHealthDomain) int {
		if r := rank[a.Status] - rank[b.Status]; r != 0 {
			return r
		}
		return strings.Compare(a.Domain, b.Domain)
	})
	switch {
	case now.Sub(f.Checked) > dnsWatchStale:
		st.Status = "warning"
		st.Message = "The scheduled DNS check hasn't run since " + f.Checked.UTC().Format("2006-01-02 15:04 MST") + "; the results below may be out of date."
	case bad == 1:
		st.Status = "warning"
		st.Message = "1 domain has DNS problems."
	case bad > 1:
		st.Status = "warning"
		st.Message = fmt.Sprintf("%d domains have DNS problems.", bad)
	default:
		st.Status = "ok"
		st.Message = "Every domain passed."
	}
	return st
}

func (s *Server) handleDNSHealthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.dnsHealthStatus(time.Now(), scopeOf(r).domain))
}
