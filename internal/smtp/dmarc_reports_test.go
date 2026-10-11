package smtp

import (
	"log/slog"
	"net"
	"testing"

	"github.com/EvalAlan/elemta/internal/authresult"
)

// Reports are mail to third parties; nothing is sent unless asked for.
func TestDMARCReportsOffByDefault(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	if r := initDMARCReports(&Config{}, nil, nil, logger); r != nil {
		t.Error("DMARC reporting started with no [dmarc_reports] section")
	}
	if r := initDMARCReports(&Config{DMARCReports: &DMARCReportsConfig{ReportFrom: "d@example.com"}}, nil, nil, logger); r != nil {
		t.Error("DMARC reporting started without enabled = true")
	}
	if r := initDMARCReports(&Config{DMARCReports: &DMARCReportsConfig{Enabled: true}}, nil, nil, logger); r != nil {
		t.Error("DMARC reporting started without the queue it sends through")
	}
}

func reportableResults() authresult.Results {
	return authresult.Results{
		SPF:         authresult.Result{Method: "spf", Value: "pass", Domain: "example.com"},
		DKIM:        []authresult.Result{{Method: "dkim", Value: "fail", Domain: "example.com", Selector: "s1"}},
		DMARC:       authresult.Result{Method: "dmarc", Value: "pass", Domain: "example.com"},
		Policy:      "reject",
		Disposition: "accept",
		DMARCPolicy: &authresult.DMARCPolicy{
			Domain: "example.com", P: "reject", SP: "reject", Pct: 100, ADKIM: "r", ASPF: "r",
			RUA: []string{"mailto:rua@example.com"}, SPFAligned: true,
		},
	}
}

var fromExample = []byte("From: Someone <someone@example.com>\r\nSubject: hi\r\n\r\nbody\r\n")

func TestDMARCEvaluationFromResults(t *testing.T) {
	e, ok := dmarcEvaluation(reportableResults(), net.ParseIP("192.0.2.1"), "<bounce@example.com>", fromExample)
	if !ok {
		t.Fatal("a reportable evaluation was skipped")
	}
	if e.SourceIP != "192.0.2.1" || e.HeaderFrom != "example.com" || e.EnvelopeFrom != "example.com" {
		t.Errorf("identifiers = %+v", e)
	}
	if e.Disposition != "none" || !e.SPFAligned || e.DKIMAligned || e.OverrideReason != "" {
		t.Errorf("evaluation = %+v", e)
	}
	if len(e.DKIM) != 1 || e.DKIM[0].Selector != "s1" || e.SPF.Result != "pass" {
		t.Errorf("auth results = %+v %+v", e.DKIM, e.SPF)
	}
}

// A failure the operator chose not to act on is reported as such, so the
// domain owner does not read "none" as their policy being ignored silently.
func TestDMARCEvaluationMarksUnenforcedFailure(t *testing.T) {
	res := reportableResults()
	res.DMARC.Value = "fail"
	res.DMARCPolicy.SPFAligned = false
	e, ok := dmarcEvaluation(res, net.ParseIP("192.0.2.1"), "a@example.com", fromExample)
	if !ok || e.Disposition != "none" || e.OverrideReason != "local_policy" {
		t.Errorf("evaluation = %+v", e)
	}
	res.Disposition = "reject"
	if e, _ := dmarcEvaluation(res, net.ParseIP("192.0.2.1"), "a@example.com", fromExample); e.Disposition != "reject" || e.OverrideReason != "" {
		t.Errorf("enforced evaluation = %+v", e)
	}
}

func TestDMARCEvaluationSkipsWhatItCannotReport(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	noPolicy := reportableResults()
	noPolicy.DMARCPolicy = nil
	noRUA := reportableResults()
	noRUA.DMARCPolicy.RUA = nil
	cases := map[string]struct {
		res authresult.Results
		ip  net.IP
		msg []byte
	}{
		"no policy":                 {noPolicy, ip, fromExample},
		"no rua":                    {noRUA, ip, fromExample},
		"no client address":         {reportableResults(), nil, fromExample},
		"From names another domain": {reportableResults(), ip, []byte("From: x@other.test\r\n\r\n")},
		"no From header":            {reportableResults(), ip, []byte("Subject: hi\r\n\r\n")},
		"several From addresses":    {reportableResults(), ip, []byte("From: a@example.com, b@example.com\r\n\r\n")},
	}
	for name, c := range cases {
		if _, ok := dmarcEvaluation(c.res, c.ip, "a@example.com", c.msg); ok {
			t.Errorf("%s: recorded", name)
		}
	}
}
