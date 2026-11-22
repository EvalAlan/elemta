package api

// Needs attention: the problems the Health, Abuse and Queues pages each know
// about, in one list on the Dashboard, worst first. A source that can't be
// read says so; saying nothing would look the same as all being well.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"
)

const (
	attentionCritical = "critical"
	attentionWarning  = "warning"
	attentionUnknown  = "unknown"
	attentionInfo     = "info"

	// signInAlertWindow is how long an unusual sign-in stays on the list.
	// The Abuse page keeps it until it's dismissed.
	signInAlertWindow = 24 * time.Hour
)

type attentionItem struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Since    string `json:"since,omitempty"`
	// View is the console page where it's dealt with.
	View string `json:"link,omitempty"`
}

func couldNotCheck(title, detail, view string) attentionItem {
	return attentionItem{Severity: attentionUnknown, Title: title, Detail: "Couldn't check: " + detail, View: view}
}

func severityOf(level int) string {
	if level == 2 {
		return attentionCritical
	}
	return attentionWarning
}

func (s *Server) attention(ctx context.Context, now time.Time) []attentionItem {
	out := []attentionItem{}
	if s.monitor != nil {
		out = append(out, s.monitor.attention(now)...)
	}
	out = append(out, s.backupAttention(now)...)
	out = append(out, s.certificateAttention()...)
	out = append(out, s.dnsAttention(now)...)
	out = append(out, s.abuseAttention(ctx, now)...)
	rank := map[string]int{attentionCritical: 0, attentionWarning: 1, attentionUnknown: 2, attentionInfo: 3}
	slices.SortStableFunc(out, func(a, b attentionItem) int { return rank[a.Severity] - rank[b.Severity] })
	return out
}

func (s *Server) backupAttention(now time.Time) []attentionItem {
	if s.backupStatusPath() == "" {
		return nil
	}
	st := s.backupStatus(now)
	switch {
	case !st.Configured && st.Status == "warning":
		return []attentionItem{couldNotCheck("Backups", st.Message, "health")}
	case !st.Configured || st.Status == "ok":
		// Backups that were never set up are a choice, shown on Health.
		return nil
	}
	item := attentionItem{Severity: attentionWarning, Title: "Backups", Detail: st.Message, View: "health"}
	if st.Status == "critical" {
		item.Severity, item.Since = attentionCritical, st.LastSuccess
	}
	return []attentionItem{item}
}

func (s *Server) certificateAttention() []attentionItem {
	if s.mainConfig == nil {
		return []attentionItem{couldNotCheck("TLS certificate", "no configuration is available to the console.", "certificates")}
	}
	st := s.tlsCertificateStatus()
	if !st.Configured {
		return nil
	}
	switch st.Status {
	case "critical", "expired":
		return []attentionItem{{Severity: attentionCritical, Title: "TLS certificate", Detail: st.Message, View: "certificates"}}
	case "warning":
		return []attentionItem{{Severity: attentionWarning, Title: "TLS certificate", Detail: st.Message, View: "certificates"}}
	}
	return nil
}

func (s *Server) dnsAttention(now time.Time) []attentionItem {
	if s.provisioner == nil {
		return nil
	}
	f := s.loadDNSWatch()
	// Before the first sweep there's nothing wrong, just nothing known yet.
	if f.Checked.IsZero() {
		if now.Sub(serverStartTime) < 2*dnsWatchFirst {
			return nil
		}
		return []attentionItem{couldNotCheck("DNS", "no scheduled check has finished since the console started.", "health")}
	}
	var out []attentionItem
	if now.Sub(f.Checked) > dnsWatchStale {
		out = append(out, couldNotCheck("DNS", "the scheduled check has stopped running.", "health"))
	}
	st := s.dnsHealthStatus(now, func(string) bool { return true })
	for _, d := range st.Domains {
		if d.Status == "ok" {
			continue
		}
		item := attentionItem{Severity: attentionWarning, Title: "DNS for " + d.Domain, Since: d.Since, View: "health"}
		if d.Status == "critical" {
			item.Severity = attentionCritical
		}
		for _, c := range d.Problems {
			if item.Detail != "" {
				item.Detail += " "
			}
			item.Detail += c.Name + ": " + c.Summary
		}
		if item.Detail == "" {
			item.Detail = "The last scheduled check found a problem."
		}
		out = append(out, item)
	}
	return out
}

func (s *Server) abuseAttention(ctx context.Context, now time.Time) []attentionItem {
	if s.abuse == nil {
		return nil
	}
	var out []attentionItem
	// Holds and alerts both read as empty when Valkey can't be reached.
	if s.abuse.UsesValkey() && !s.abuse.Shared(ctx) {
		out = append(out, couldNotCheck("Abuse protection", "Valkey can't be reached, so holds, sign-in alerts and alert emails aren't working.", "abuse"))
	}
	for _, h := range s.abuse.Holds(ctx) {
		out = append(out, attentionItem{Severity: attentionCritical, Title: "Sending held for " + h.Account, Detail: h.Reason,
			Since: h.Created.UTC().Format(time.RFC3339), View: "abuse"})
	}
	recent, latest := 0, time.Time{}
	accounts := map[string]bool{}
	for _, a := range s.abuse.Alerts(ctx) {
		if now.Sub(a.Time) > signInAlertWindow {
			continue
		}
		recent++
		accounts[a.Account] = true
		if a.Time.After(latest) {
			latest = a.Time
		}
	}
	if recent > 0 {
		out = append(out, attentionItem{Severity: attentionWarning, Title: "Unusual sign-ins",
			Detail: fmt.Sprintf("Alerts in the last 24 hours: %d, accounts: %d.", recent, len(accounts)),
			Since:  latest.UTC().Format(time.RFC3339), View: "abuse"})
	}
	if len(s.abuse.Policy().AlertEmail) == 0 {
		out = append(out, attentionItem{Severity: attentionInfo, Title: "Alert emails",
			Detail: "No alert addresses are set, so none of these problems is emailed to anyone.", View: "abuse"})
	}
	return out
}

func (s *Server) handleAttention(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"items": s.attention(ctx, time.Now())})
}
