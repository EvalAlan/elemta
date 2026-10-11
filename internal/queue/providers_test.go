package queue

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func mustProviders(t *testing.T, overrides ...ProviderConfig) *ProviderRouter {
	t.Helper()
	r, err := NewProviderRouter(true, overrides)
	if err != nil {
		t.Fatalf("NewProviderRouter: %v", err)
	}
	return r
}

func mxHosts(hosts ...string) []*net.MX {
	out := make([]*net.MX, len(hosts))
	for i, h := range hosts {
		out[i] = &net.MX{Host: h, Pref: uint16(10 * (i + 1))}
	}
	return out
}

func TestProviderMatchesByMXHostNotRecipientDomain(t *testing.T) {
	r := mustProviders(t)
	for _, tc := range []struct {
		domain string
		mx     []*net.MX
		want   string
	}{
		{"gmail.com", mxHosts("gmail-smtp-in.l.google.com."), "gmail"},
		{"workspace-customer.example", mxHosts("aspmx.l.google.com.", "alt1.aspmx.l.google.com."), "gmail"},
		{"new-workspace.example", mxHosts("smtp.google.com"), "gmail"},
		{"yahoo.com", mxHosts("mta5.am0.yahoodns.net."), "yahoo"},
		{"aol.com", mxHosts("mx-aol.mail.gm0.yahoodns.net."), "yahoo"},
		{"hotmail.com", mxHosts("hotmail-com.olc.protection.outlook.com."), "microsoft"},
		{"m365-tenant.example", mxHosts("m365-tenant-example.mail.protection.outlook.com."), "microsoft"},
		// A provider as backup MX does not make the domain its customer.
		{"selfhosted.example", mxHosts("mx.selfhosted.example.", "aspmx.l.google.com."), ""},
		// Suffix match is on a label boundary.
		{"lookalike.example", mxHosts("mx.notgoogle.com."), ""},
		{"empty.example", nil, ""},
	} {
		got := providerName(r.matchMX(tc.domain, tc.mx))
		if got != tc.want {
			t.Errorf("%s via %v = %q, want %q", tc.domain, tc.mx, got, tc.want)
		}
		if providerName(r.known(tc.domain)) != tc.want {
			t.Errorf("%s: known() does not remember the match", tc.domain)
		}
	}

	// Two hosted domains share one shaping key, which is the point.
	g := r.known("gmail.com")
	if destinationKey(g, "gmail.com") != destinationKey(r.known("workspace-customer.example"), "workspace-customer.example") {
		t.Error("gmail.com and a Workspace domain are shaped separately")
	}
	if destinationKey(nil, "selfhosted.example") != "selfhosted.example" {
		t.Error("an unprofiled domain is not shaped under its own name")
	}
}

func TestProviderMemoForgetsADomainThatMovedAway(t *testing.T) {
	r := mustProviders(t)
	r.matchMX("moved.example", mxHosts("aspmx.l.google.com"))
	r.matchMX("moved.example", mxHosts("mx.moved.example"))
	if r.known("moved.example") != nil {
		t.Error("a domain that left Google is still shaped as Gmail")
	}
}

func TestProviderOverrides(t *testing.T) {
	r := mustProviders(t,
		ProviderConfig{Name: "Gmail", MaxConnections: 5, ThrottledMessagesPerMinute: 30, ThrottleSignals: []string{"Custom Signal"}},
		ProviderConfig{Name: "yahoo", Disabled: true},
		ProviderConfig{Name: "corp", MXSuffixes: []string{".mx.corp.example."}, MaxMessagesPerMinute: 100},
	)
	g := r.matchMX("gmail.com", mxHosts("gmail-smtp-in.l.google.com"))
	if g == nil || g.limits.MaxConnections != 5 || g.limits.ThrottledMessagesPerMinute != 30 {
		t.Fatalf("gmail override not applied: %+v", g)
	}
	if !containsAny("421 custom signal here", g.throttleSignals) || !containsAny("421 4.7.28", g.throttleSignals) {
		t.Error("override signals should add to the built-in ones, not replace them")
	}
	if r.matchMX("yahoo.com", mxHosts("mta5.am0.yahoodns.net")) != nil {
		t.Error("disabled yahoo profile still matches")
	}
	if c := r.matchMX("corp.example", mxHosts("a.mx.corp.example")); c == nil || c.limits.MaxMessagesPerMinute != 100 {
		t.Errorf("custom provider = %+v", c)
	}

	if r, err := NewProviderRouter(false, nil); r != nil || err != nil {
		t.Errorf("disabled = %v, %v; want nil, nil", r, err)
	}
}

func TestProviderOverridesRejectBadConfig(t *testing.T) {
	for name, cfg := range map[string][]ProviderConfig{
		"no name":         {{MXSuffixes: []string{"x.example"}}},
		"custom, no mx":   {{Name: "corp"}},
		"duplicate":       {{Name: "gmail"}, {Name: "Gmail"}},
		"shared suffix":   {{Name: "corp", MXSuffixes: []string{"google.com"}}},
		"unknown disable": {{Name: "nosuch", Disabled: true}},
		"negative":        {{Name: "gmail", MaxConnections: -1}},
		"empty mx entry":  {{Name: "corp", MXSuffixes: []string{" "}}},
	} {
		if _, err := NewProviderRouter(true, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassifyDeferral(t *testing.T) {
	r := mustProviders(t)
	gmail := r.matchMX("gmail.com", mxHosts("aspmx.l.google.com"))
	yahoo := r.matchMX("yahoo.com", mxHosts("mta5.am0.yahoodns.net"))
	ms := r.matchMX("outlook.com", mxHosts("outlook-com.olc.protection.outlook.com"))

	temp := func(diags ...string) []RecipientOutcome {
		var out []RecipientOutcome
		for _, d := range diags {
			out = append(out, RecipientOutcome{Status: RecipientTemporaryFailure, Diagnostic: d})
		}
		return append(out, RecipientOutcome{Status: RecipientDelivered})
	}
	wrapped := func(code int, msg string) error {
		return fmt.Errorf("MAIL FROM failed: %w", &textproto.Error{Code: code, Msg: msg})
	}

	for _, tc := range []struct {
		name     string
		p        *provider
		err      error
		outcomes []RecipientOutcome
		want     deferralKind
	}{
		{"gmail 4.7.28 on a recipient", gmail, nil,
			temp("421 4.7.28 Our system has detected an unusual rate of unsolicited mail originating from your IP address."), deferralThrottle},
		{"gmail 4.7.28 at MAIL FROM", gmail, wrapped(421, "4.7.28 Gmail has detected ... temporarily rate limited"), nil, deferralThrottle},
		{"gmail one busy mailbox", gmail, nil,
			temp("450 4.2.1 The user you are trying to contact is receiving mail at a rate that prevents additional messages from being delivered."), deferralRecipient},
		{"throttle beats recipient", gmail, nil,
			temp("450 4.2.1 receiving mail at a rate", "421 4.7.28 unusual rate of unsolicited mail"), deferralThrottle},
		{"recipient mixed with generic", gmail, nil,
			temp("452 4.2.2 mailbox full", "451 4.3.0 try later"), deferralGeneric},
		{"yahoo TSS04", yahoo, wrapped(421, "4.7.0 [TSS04] Messages from 203.0.113.20 temporarily deferred due to unexpected volume or user complaints"), nil, deferralThrottle},
		{"microsoft 4.7.650", ms, nil,
			temp("451 4.7.650 The mail server [203.0.113.20] has been temporarily rate limited due to IP reputation."), deferralThrottle},
		{"microsoft RP-001", ms, wrapped(421, "RP-001 (BAY004-MC1F36) Unfortunately, some messages from 203.0.113.20 weren't sent."), nil, deferralThrottle},
		{"unprofiled full mailbox", nil, nil, temp("452 4.2.2 Mailbox full"), deferralRecipient},
		{"unprofiled throttle text is generic", nil, nil, temp("421 4.7.28 unusual rate"), deferralGeneric},
		{"local timeout is generic", gmail, errors.New("dial tcp 4.2.2.1:25: i/o timeout"), nil, deferralGeneric},
		{"no information", gmail, nil, nil, deferralGeneric},
	} {
		if got := classifyDeferral(tc.p, tc.err, tc.outcomes); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestThrottlePenaltyHalvesRateAndDecays(t *testing.T) {
	s := NewShaper(ShapingConfig{BackoffInitial: time.Second, BackoffMax: time.Minute})
	limits := &Limits{ThrottledMessagesPerMinute: 120}
	release, err := s.AcquireWithLimits(context.Background(), "provider:gmail", limits)
	if err != nil {
		t.Fatal(err)
	}
	release()

	rate := func() int {
		for _, st := range s.Statuses() {
			if st.Domain == "provider:gmail" {
				return st.RatePerMinute
			}
		}
		return -1
	}
	if got := rate(); got != 0 {
		t.Fatalf("before any throttle rate = %d, want 0 (uncapped)", got)
	}

	b1 := s.ReportThrottle("provider:gmail", 10*time.Minute, time.Hour)
	if b1 != 10*time.Minute {
		t.Errorf("first throttle backoff = %s, want the provider's 10m, not the generic 1s", b1)
	}
	if got := rate(); got != 120 {
		t.Errorf("after one throttle rate = %d, want the throttled rate 120", got)
	}
	if b2 := s.ReportThrottle("provider:gmail", 10*time.Minute, time.Hour); b2 != 20*time.Minute {
		t.Errorf("second throttle backoff = %s, want 20m", b2)
	}
	if got := rate(); got != 60 {
		t.Errorf("after two throttles rate = %d, want 60", got)
	}
	for i := 0; i < 10; i++ {
		s.ReportThrottle("provider:gmail", 10*time.Minute, time.Hour)
	}
	if got := rate(); got != 15 {
		t.Errorf("penalty is not capped: rate = %d, want 120>>3 = 15", got)
	}

	// A success ends the pause but not the penalty: the pace that caused
	// the throttle is not the pace to go back to.
	s.ReportSuccess("provider:gmail")
	if _, backingOff := s.BackingOff("provider:gmail"); backingOff {
		t.Error("success did not clear the backoff")
	}
	if got := rate(); got != 15 {
		t.Errorf("success cleared the penalty: rate = %d", got)
	}

	// The penalty decays a level per quiet interval.
	s.mu.Lock()
	s.domains["provider:gmail"].penaltyDecayAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	release, err = s.AcquireWithLimits(context.Background(), "provider:gmail", limits)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if got := rate(); got != 30 {
		t.Errorf("after one quiet interval rate = %d, want 30", got)
	}
}

func TestRecipientDeferralDoesNotBackOff(t *testing.T) {
	s := NewShaper(ShapingConfig{BackoffInitial: time.Hour, BackoffMax: time.Hour})
	for i := 0; i < 20; i++ {
		s.ReportRecipientDeferral("provider:gmail")
	}
	if _, backingOff := s.BackingOff("provider:gmail"); backingOff {
		t.Error("full mailboxes backed off the whole provider")
	}
	if st := s.Statuses()[0]; st.Deferred != 20 || st.Failures != 0 {
		t.Errorf("status = %+v; want 20 deferrals counted and no failure streak", st)
	}
}

// TestProviderThrottleBacksOffEveryHostedDomain is the end-to-end property:
// Gmail throttles a delivery to one Workspace domain, and the next message to
// a different Google-hosted domain is refused before any DNS or connection,
// because Google applies the limit to the sending IP, not to the domain.
func TestProviderThrottleBacksOffEveryHostedDomain(t *testing.T) {
	addr, stop := startSMTPServer(t, "421 4.7.28 Our system has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited.")
	defer stop()

	h := NewSMTPDeliveryHandler(0)
	h.mtastsManager = allowMTASTS{}
	h.maxMXLookups = 1
	h.SetConnectionReuse(false)
	h.SetShaper(NewShaper(ShapingConfig{MaxConnectionsPerDomain: 10, BackoffInitial: time.Second, BackoffMax: time.Second}))
	h.SetProviderRouter(mustProviders(t))
	lookups := 0
	h.resolver = resolverFunc(func(_ context.Context, name string) ([]*net.MX, error) {
		lookups++
		return mxHosts("aspmx.l.google.com."), nil
	})
	dials := 0
	h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials++
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	_, err := h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "a@sender.example", To: []string{"x@workspace-a.example"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if err == nil || !(&Processor{}).isTemporaryFailure(err) {
		t.Fatalf("first delivery err = %v, want a temporary failure", err)
	}
	wait, backingOff := h.shaper.BackingOff("provider:gmail")
	if !backingOff || wait < 9*time.Minute {
		t.Fatalf("gmail backoff = %s, %v; want the provider's ~10m throttle backoff, not the generic 1s", wait, backingOff)
	}

	// workspace-b has never been seen; its MX lookup reveals Google, and the
	// shared provider state refuses it without connecting.
	_, err = h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "a@sender.example", To: []string{"y@workspace-b.example"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if !errors.Is(err, ErrDestinationBackingOff) && !strings.Contains(fmt.Sprint(err), ErrDestinationBackingOff.Error()) {
		t.Fatalf("second Google-hosted domain err = %v, want a backoff refusal", err)
	}
	if dials != 1 {
		t.Errorf("dialled %d times; a throttled provider must not be contacted again during its backoff", dials)
	}

	// Once workspace-b's provider is known, a retry is refused before DNS.
	before := lookups
	_, _ = h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "a@sender.example", To: []string{"y@workspace-b.example"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if lookups != before {
		t.Error("a domain known to be at a throttled provider was looked up again")
	}
}

func TestFullMailboxDoesNotBackOffTheProvider(t *testing.T) {
	addr, stop := startSMTPServer(t, "452 4.2.2 The email account that you tried to reach is over quota.")
	defer stop()

	h := NewSMTPDeliveryHandler(0)
	h.mtastsManager = allowMTASTS{}
	h.maxMXLookups = 1
	h.SetConnectionReuse(false)
	h.SetShaper(NewShaper(ShapingConfig{MaxConnectionsPerDomain: 10, BackoffInitial: time.Hour, BackoffMax: time.Hour}))
	h.SetProviderRouter(mustProviders(t))
	h.resolver = resolverFunc(func(context.Context, string) ([]*net.MX, error) {
		return mxHosts("gmail-smtp-in.l.google.com."), nil
	})
	h.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	_, err := h.DeliverMessageWithMetadata(context.Background(),
		Message{From: "a@sender.example", To: []string{"full@gmail.com"}}, []byte("Subject: x\r\n\r\nhi\r\n"))
	if err == nil {
		t.Fatal("over-quota recipient was reported delivered")
	}
	if _, backingOff := h.shaper.BackingOff("provider:gmail"); backingOff {
		t.Error("one full mailbox backed off all of Gmail")
	}
}
