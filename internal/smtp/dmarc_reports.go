package smtp

import (
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/authresult"
	"github.com/EvalAlan/elemta/internal/dmarcrpt"
	"github.com/EvalAlan/elemta/internal/queue"
)

// dmarcStateFileName is the counts file inside the state directory.
const dmarcStateFileName = "dmarc-reports-state.json"

// initDMARCReports starts RFC 7489 aggregate reporting. A failure to start
// is logged, not fatal: reports are a courtesy to other domains, and
// accepting mail must not depend on them. Returns nil when reporting is off.
func initDMARCReports(config *Config, manager *queue.Manager, processor *queue.Processor, slogger *slog.Logger) *dmarcrpt.Reporter {
	cfg := config.DMARCReports
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if manager == nil || processor == nil {
		slogger.Warn("DMARC reporting not started: it needs the queue processor to send reports")
		return nil
	}
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = config.QueueDir
	}
	var stateFile string
	if stateDir != "" {
		stateFile = filepath.Join(stateDir, dmarcStateFileName)
	}
	enqueue := func(id, from string, to []string, subject string, content []byte) error {
		_, err := manager.EnqueueMessageWithID(id, from, to, subject, content, queue.PriorityLow, time.Now())
		return err
	}
	reporter, err := dmarcrpt.NewReporter(dmarcrpt.Config{
		OrganizationName: cfg.OrganizationName,
		ContactEmail:     cfg.ContactEmail,
		Hostname:         config.Hostname,
		From:             cfg.ReportFrom,
		StateFile:        stateFile,
	}, enqueue, slogger)
	if err != nil {
		slogger.Warn("DMARC reporting not started", "error", err)
		return nil
	}
	reporter.Start()
	processor.OnStop(reporter.Stop)
	slogger.Info("DMARC aggregate reporting (RFC 7489) enabled", "report_from", cfg.ReportFrom, "state_file", stateFile)
	return reporter
}

// SetDMARCReports gives the session the aggregate report counter.
func (s *Session) SetDMARCReports(reporter *dmarcrpt.Reporter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dmarcReports = reporter
}

// dmarcEvaluation turns one message's verification into a report row. It
// reports false when there is nothing a report should say: no policy, no
// rua, or a message whose evaluation would be misattributed.
func dmarcEvaluation(results authresult.Results, clientIP net.IP, mailFrom string, message []byte) (dmarcrpt.Evaluation, bool) {
	p := results.DMARCPolicy
	if p == nil || len(p.RUA) == 0 || clientIP == nil {
		return dmarcrpt.Evaluation{}, false
	}
	// The verifier judges the header From domain, so the two agree for every
	// message it evaluated under one record. The check stays as a guard: a
	// row reported under a domain the verdict was not about would tell an
	// owner about mail that was never evaluated under its policy.
	headerFrom := authresult.HeaderFromDomain(message)
	if headerFrom == "" || !strings.EqualFold(headerFrom, p.Domain) {
		return dmarcrpt.Evaluation{}, false
	}
	disposition := results.Disposition
	if disposition == "" || disposition == "accept" {
		disposition = "none"
	}
	var reason string
	if results.DMARC.Value == "fail" && disposition == "none" && p.P != "" && p.P != "none" {
		// The domain asked for quarantine or reject and enforcement is off;
		// the report has to say the departure was ours.
		reason = "local_policy"
	}
	eval := dmarcrpt.Evaluation{
		SourceIP:     clientIP.String(),
		HeaderFrom:   headerFrom,
		EnvelopeFrom: envelopeDomain(mailFrom),
		Policy: dmarcrpt.Policy{
			Domain: p.Domain, P: p.P, SP: p.SP, Pct: p.Pct, ADKIM: p.ADKIM, ASPF: p.ASPF,
			RUA: p.RUA,
		},
		Disposition:    disposition,
		DKIMAligned:    p.DKIMAligned,
		SPFAligned:     p.SPFAligned,
		OverrideReason: reason,
		SPF:            dmarcrpt.SPFAuth{Domain: results.SPF.Domain, Result: results.SPF.Value},
	}
	for _, d := range results.DKIM {
		eval.DKIM = append(eval.DKIM, dmarcrpt.DKIMAuth{Domain: d.Domain, Selector: d.Selector, Result: d.Value})
	}
	return eval, true
}

func envelopeDomain(mailFrom string) string {
	addr := strings.Trim(strings.TrimSpace(mailFrom), "<>")
	if at := strings.LastIndexByte(addr, '@'); at >= 0 {
		return strings.ToLower(addr[at+1:])
	}
	return ""
}
