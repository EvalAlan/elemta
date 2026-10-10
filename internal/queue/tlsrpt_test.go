package queue

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/delivery"
	"github.com/EvalAlan/elemta/internal/tlsrpt"
)

type tlsRecorder struct {
	mu       sync.Mutex
	sessions []tlsrpt.Session
}

func (r *tlsRecorder) Record(s tlsrpt.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = append(r.sessions, s)
}

// stsSource is an MTA-STS manager stand-in that allows delivery and reports
// a fixed policy.
type stsSource struct{ policy *delivery.MTASTSPolicy }

func (stsSource) EnforcePolicy(context.Context, string, string, bool) error { return nil }
func (s stsSource) GetPolicy(context.Context, string) (*delivery.MTASTSPolicy, error) {
	return s.policy, nil
}

var testSTS = &delivery.MTASTSPolicy{Version: "STSv1", Mode: "testing", MX: []string{"mx.example.com"}, MaxAge: 86400}

func TestReportTLSClassification(t *testing.T) {
	cases := []struct {
		name       string
		policy     *delivery.MTASTSPolicy
		mx         string
		sess       outboundSession
		success    bool
		resultType string
		policyType string
	}{
		{"no policy, plaintext, no STARTTLS", nil, "mx.example.com",
			outboundSession{tls: tlsNone}, false, tlsrpt.ResultStartTLSNotSupported, tlsrpt.PolicyTypeNoPolicy},
		{"no policy, unverified TLS", nil, "mx.example.com",
			outboundSession{tls: tlsUnverified, starttlsOffered: true, verifyErr: x509.UnknownAuthorityError{}}, true, "", tlsrpt.PolicyTypeNoPolicy},
		{"sts, verified", testSTS, "mx.example.com",
			outboundSession{tls: tlsVerified, starttlsOffered: true}, true, "", tlsrpt.PolicyTypeSTS},
		{"sts, untrusted certificate", testSTS, "mx.example.com",
			outboundSession{tls: tlsUnverified, starttlsOffered: true, verifyErr: x509.UnknownAuthorityError{}}, false, tlsrpt.ResultCertificateNotTrusted, tlsrpt.PolicyTypeSTS},
		{"sts, wrong certificate name", testSTS, "mx.example.com",
			outboundSession{tls: tlsUnverified, starttlsOffered: true, verifyErr: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "mx.example.com"}}, false, tlsrpt.ResultCertificateHostMismatch, tlsrpt.PolicyTypeSTS},
		{"sts, MX not in policy", testSTS, "rogue.example.net",
			outboundSession{tls: tlsVerified, starttlsOffered: true}, false, tlsrpt.ResultValidationFailure, tlsrpt.PolicyTypeSTS},
		{"sts, STARTTLS not offered", testSTS, "mx.example.com",
			outboundSession{tls: tlsNone}, false, tlsrpt.ResultStartTLSNotSupported, tlsrpt.PolicyTypeSTS},
		{"mode none counts as no policy", &delivery.MTASTSPolicy{Version: "STSv1", Mode: "none"}, "mx.example.com",
			outboundSession{tls: tlsUnverified, starttlsOffered: true}, true, "", tlsrpt.PolicyTypeNoPolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &tlsRecorder{}
			h := NewSMTPDeliveryHandler(0)
			h.mtastsManager = stsSource{policy: c.policy}
			h.SetTLSReportRecorder(rec)
			sess := c.sess
			h.reportTLS(context.Background(), "example.com", c.mx, &sess)
			if len(rec.sessions) != 1 {
				t.Fatalf("recorded %d sessions", len(rec.sessions))
			}
			got := rec.sessions[0]
			if got.Success != c.success || got.ResultType != c.resultType || got.Policy.Type != c.policyType {
				t.Errorf("got success=%v result=%q policy=%q, want %v %q %q",
					got.Success, got.ResultType, got.Policy.Type, c.success, c.resultType, c.policyType)
			}
			if got.Policy.Type == tlsrpt.PolicyTypeSTS && len(got.Policy.Strings) == 0 {
				t.Error("sts policy recorded without its policy strings")
			}
		})
	}
}

// Each session is counted once, when it is set up, not once per message.
func TestReportTLSCountsSessionsNotMessages(t *testing.T) {
	srv := startReuseServer(t, 0)
	h := reuseHandler(srv)
	t.Cleanup(h.CloseIdleSessions)
	rec := &tlsRecorder{}
	h.SetTLSReportRecorder(rec)

	deliverOne(t, h, "a@one.test")
	deliverOne(t, h, "b@one.test")

	if len(rec.sessions) != 1 {
		t.Fatalf("recorded %d sessions for one connection", len(rec.sessions))
	}
	s := rec.sessions[0]
	if s.Policy.Domain != "one.test" || s.ResultType != tlsrpt.ResultStartTLSNotSupported || s.ReceivingIP != "127.0.0.1" {
		t.Errorf("recorded %+v", s)
	}
}
