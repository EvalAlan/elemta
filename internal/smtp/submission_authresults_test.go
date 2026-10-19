package smtp

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/EvalAlan/elemta/internal/authresult"
	"github.com/emersion/go-msgauth/authres"
)

type submissionAuthResolver struct {
	*net.Resolver
	calls atomic.Int64
}

func (r *submissionAuthResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.calls.Add(1)
	switch strings.TrimSuffix(name, ".") {
	case "example.com":
		return []string{"v=spf1 -all"}, nil
	case "_dmarc.example.com":
		return []string{"v=DMARC1; p=reject"}, nil
	default:
		return nil, &net.DNSError{Name: name, Err: "no record", IsNotFound: true}
	}
}

func TestSubmissionAuthenticationResults(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		for _, peer := range []string{"10.253.53.11:12345", "203.0.113.5:12345"} {
			t.Run(peer+"/authenticated="+map[bool]string{true: "yes", false: "no"}[authenticated], func(t *testing.T) {
				resolver := &submissionAuthResolver{Resolver: net.DefaultResolver}
				state := NewSessionState(quietLogger())
				state.SetAuthenticated(t.Context(), authenticated, "sender@example.com")
				session := &Session{
					state: state, logger: quietLogger(), remoteAddr: peer,
					authVerifier: authresult.New(authresult.Config{
						Enabled: true, EnforceDMARC: true, Resolver: resolver,
					}),
					// An earlier transaction must not leak results into submission.
					authChecked: true,
					authResults: authresult.Results{SPF: authresult.Result{Value: "fail"}},
				}
				message := []byte("From: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n")
				err := session.VerifyAuthentication(t.Context(), "sender@example.com", message)
				results, checked := session.AuthResults()
				if authenticated {
					if err != nil || checked || resolver.calls.Load() != 0 {
						t.Fatalf("submission ran inbound verification: err=%v checked=%v DNS=%d", err, checked, resolver.calls.Load())
					}
				} else if err == nil || !checked || results.SPF.Value != "fail" || results.DMARC.Value != "fail" {
					t.Fatalf("unauthenticated peer bypassed enforced verification: err=%v results=%+v checked=%v", err, results, checked)
				}

				dh := &DataHandler{
					session: session, state: state, config: &Config{Hostname: "mx.example.com"},
					conn: &fakeConn{remote: &mockAddr{addr: peer}},
				}
				headers := string(dh.buildServerHeaders(t.Context(), message, &MessageMetadata{}, nil))
				if authenticated {
					if !strings.Contains(headers, "Authentication-Results: mx.example.com; auth=pass smtp.auth=sender@example.com") {
						t.Fatalf("missing SMTP AUTH result: %s", headers)
					}
					for _, method := range []string{"spf=", "dkim=", "dmarc="} {
						if strings.Contains(headers, method) {
							t.Fatalf("submission claims receiver verdict %s", method)
						}
					}
				} else if !strings.Contains(headers, "spf=fail") || !strings.Contains(headers, "dmarc=fail") {
					t.Fatalf("inbound verdicts missing: %s", headers)
				}
			})
		}
	}
}

func TestSubmissionAuthIdentityCannotInjectResults(t *testing.T) {
	state := NewSessionState(quietLogger())
	state.SetAuthenticated(t.Context(), true, "sender; dmarc=pass\r\nX-Forged: yes")
	dh := &DataHandler{
		state: state, config: &Config{Hostname: "mx.example.com"},
		conn: &fakeConn{remote: &mockAddr{addr: "10.0.0.1:1234"}},
	}
	headers := string(dh.buildServerHeaders(t.Context(), []byte("From: a@example.com\r\n\r\n"), &MessageMetadata{}, nil))
	for _, line := range strings.Split(headers, "\r\n") {
		if value, ok := strings.CutPrefix(line, "Authentication-Results: "); ok {
			_, results, err := authres.Parse(value)
			if err != nil || len(results) != 1 {
				t.Fatalf("unsafe identity serialization: %q err=%v results=%v", value, err, results)
			}
			return
		}
	}
	t.Fatal("missing Authentication-Results")
}
