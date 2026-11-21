package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/dnshealth"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Scheduled DNS checks.
//
// The Domains page checks a domain's DNS when someone asks, which is when
// they're setting it up. DNS breaks later, quietly: a registrar change drops
// the DKIM record, someone edits SPF for a new mail service and leaves this
// server out, an MTA-STS policy expires. Mail then lands in spam or bounces
// for days before anyone connects it to DNS. So the admin process runs the
// same checks on every hosted domain every few hours and emails the alert
// addresses when a domain gains a problem, and once when it's clean again.
//
// What it last saw is kept in a file beside the configuration, so a restart
// or a deploy doesn't announce the same problems again.

const (
	dnsWatchEvery = 6 * time.Hour
	// dnsWatchFirst lets the rest of the stack start before the first sweep.
	dnsWatchFirst = 5 * time.Minute
)

// dnsWatchState is, per domain, the IDs of the checks that were warn or fail.
type dnsWatchState map[string][]string

type dnsNotice struct{ subject, body string }

// problems returns the IDs of r's bad checks. A check DNS couldn't answer
// keeps whatever it was last time: a resolver's bad moment neither raises
// a problem nor clears one.
func problems(r dnshealth.Report, before []string) []string {
	var out []string
	for _, c := range r.Checks {
		switch {
		case c.Status == dnshealth.StatusWarn || c.Status == dnshealth.StatusFail:
			out = append(out, c.ID)
		case c.Status == dnshealth.StatusUnknown && slices.Contains(before, c.ID):
			out = append(out, c.ID)
		}
	}
	slices.Sort(out)
	return out
}

// dnsChanges compares a sweep with the previous one and returns the new state
// and the emails to send. Domains no longer hosted are dropped silently.
func dnsChanges(prev dnsWatchState, reports []dnshealth.Report) (dnsWatchState, []dnsNotice) {
	next := dnsWatchState{}
	var notices []dnsNotice
	for _, r := range reports {
		before := prev[r.Domain]
		now := problems(r, before)
		next[r.Domain] = now
		var added []string
		for _, id := range now {
			if !slices.Contains(before, id) {
				added = append(added, id)
			}
		}
		switch {
		case len(added) > 0:
			notices = append(notices, dnsNotice{"DNS problem for " + r.Domain, dnsProblemBody(r, now)})
		case len(now) == 0 && len(before) > 0:
			notices = append(notices, dnsNotice{"DNS for " + r.Domain + " is healthy again",
				"The DNS problems reported earlier for " + r.Domain + " are fixed. Every check passed.\n"})
		}
	}
	return next, notices
}

func dnsProblemBody(r dnshealth.Report, ids []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The scheduled DNS check found problems with %s, which this server (%s) sends and receives mail for. Until they're fixed, mail from it may be marked as spam or refused, or mail to it may not arrive.\n\n", r.Domain, r.Hostname)
	for _, c := range r.Checks {
		if !slices.Contains(ids, c.ID) {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", c.Name, c.Summary)
		if c.Fix != "" {
			fmt.Fprintf(&b, "  Fix: %s\n", c.Fix)
		}
		if c.Record != "" {
			fmt.Fprintf(&b, "  Record: %s\n", c.Record)
		}
		b.WriteString("\n")
	}
	b.WriteString("The Domains page in the admin console runs the check again on demand. You'll get one more email when it's clean.\n")
	return b.String()
}

func (s *Server) dnsWatchPath() string {
	if s.configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.configPath), "dns-health-state.json")
}

func (s *Server) loadDNSWatch() dnsWatchState {
	st := dnsWatchState{}
	if path := s.dnsWatchPath(); path != "" {
		// #nosec G304 -- a fixed name beside the operator's configuration file
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &st)
		}
	}
	return st
}

func (s *Server) saveDNSWatch(st dnsWatchState) {
	path := s.dnsWatchPath()
	if path == "" {
		return
	}
	data, err := json.Marshal(st)
	if err == nil {
		tmp := path + ".new"
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		slog.Warn("Could not save the DNS check state; problems may be emailed again", "error", err)
	}
}

// dnsSweep checks every active hosted domain, one at a time: a handful of
// lookups each, a few times a day, needs no hurry.
func (s *Server) dnsSweep(ctx context.Context) []dnshealth.Report {
	if s.provisioner == nil {
		return nil
	}
	domains, err := s.provisioner.Domains(ctx)
	if err != nil {
		slog.Warn("Scheduled DNS check couldn't list domains", "error", err)
		return nil
	}
	var reports []dnshealth.Report
	for _, d := range domains {
		if !d.Configured || (d.Status != "" && d.Status != mailpolicy.DomainActive) {
			continue
		}
		view, err := s.domainSettings(ctx, d.Name)
		if err != nil {
			slog.Warn("Scheduled DNS check skipped a domain", "domain", d.Name, "error", err)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, dnsHealthTimeout)
		reports = append(reports, s.runDNSHealth(cctx, view))
		cancel()
	}
	return reports
}

// watchDNS runs the sweep until stop closes.
func (s *Server) watchDNS(stop <-chan struct{}) {
	if s.abuse == nil || s.provisioner == nil {
		return
	}
	state := s.loadDNSWatch()
	timer := time.NewTimer(dnsWatchFirst)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		reports := s.dnsSweep(ctx)
		if ctx.Err() == nil && len(reports) > 0 {
			var notices []dnsNotice
			state, notices = dnsChanges(state, reports)
			s.saveDNSWatch(state)
			for _, n := range notices {
				slog.Warn("DNS check alert", "subject", n.subject)
				if !s.abuse.Notify(ctx, n.subject, n.body) {
					slog.Warn("DNS check alert not emailed: set alert addresses on the Abuse page")
				}
			}
		}
		cancel()
		timer.Reset(dnsWatchEvery)
	}
}
