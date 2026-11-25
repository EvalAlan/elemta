package smtp

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/EvalAlan/elemta/internal/authresult"
)

// spfLookupResolver publishes a hard-fail SPF record and a p=none DMARC
// record for example.com, and counts SPF lookups.
type spfLookupResolver struct {
	*net.Resolver
	spfLookups atomic.Int64
}

func (r *spfLookupResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	switch strings.TrimSuffix(name, ".") {
	case "example.com":
		r.spfLookups.Add(1)
		return []string{"v=spf1 -all"}, nil
	case "_dmarc.example.com":
		return []string{"v=DMARC1; p=none"}, nil
	default:
		return nil, &net.DNSError{Name: name, Err: "no record", IsNotFound: true}
	}
}

// Mail handed back by this installation's own servers (allowed_relays) comes
// from private addresses no SPF record lists, so SPF isn't asked about it and
// reads "none"; DMARC still runs. Anyone else is SPF-checked as before.
func TestInternalRelaySkipsSPF(t *testing.T) {
	for _, tc := range []struct {
		peer       string
		spf        string
		spfLookups int64
	}{
		{"10.253.54.3:40000", "none", 0},
		{"203.0.113.5:40000", "fail", 1},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			resolver := &spfLookupResolver{Resolver: net.DefaultResolver}
			state := NewSessionState(quietLogger())
			config := &Config{Hostname: "mx.example.net", AllowedRelays: []string{"10.253.54.0/24"}}
			session := &Session{
				state: state, logger: quietLogger(), remoteAddr: tc.peer, config: config,
				authVerifier: authresult.New(authresult.Config{Enabled: true, Resolver: resolver}),
			}
			session.commandHandler = &CommandHandler{
				session: session, state: state, config: config,
				conn: &fakeConn{remote: &mockAddr{addr: tc.peer}},
			}
			message := []byte("From: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n")
			if err := session.VerifyAuthentication(t.Context(), "sender@example.com", message); err != nil {
				t.Fatalf("VerifyAuthentication: %v", err)
			}
			results, checked := session.AuthResults()
			if !checked {
				t.Fatal("sender checks didn't run")
			}
			if results.SPF.Value != tc.spf || resolver.spfLookups.Load() != tc.spfLookups {
				t.Errorf("spf=%q after %d SPF lookups, want %q after %d",
					results.SPF.Value, resolver.spfLookups.Load(), tc.spf, tc.spfLookups)
			}
			if results.DMARC.Value != "fail" {
				t.Errorf("DMARC didn't run: %+v", results.DMARC)
			}
		})
	}
}
