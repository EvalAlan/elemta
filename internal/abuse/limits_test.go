package abuse

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestInboundMessagesPerAddress(t *testing.T) {
	p := DefaultPolicy()
	p.MessagesPerAddressPerHour = 3
	e := testEngine(t, p)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !e.InboundMessage(ctx, "203.0.113.5:25") {
			t.Fatalf("message %d refused under the limit", i+1)
		}
	}
	if e.InboundMessage(ctx, "203.0.113.5:25") {
		t.Fatal("over the limit was accepted")
	}
	if !e.InboundMessage(ctx, "203.0.113.6:25") {
		t.Fatal("another address shares the count")
	}
	if !e.InboundMessage(ctx, "127.0.0.1:25") {
		t.Fatal("loopback is exempt")
	}
	p.MessagesPerAddressPerHour = 0
	e = testEngine(t, p)
	for i := 0; i < 10; i++ {
		if !e.InboundMessage(ctx, "203.0.113.5:25") {
			t.Fatal("0 should turn the limit off")
		}
	}
}

// A taken-over account sends far past its usual volume; the hold must stop it,
// stay until released, and not catch it again from the mail that tripped it.
func TestOutboundHoldUntilReleased(t *testing.T) {
	p := DefaultPolicy()
	p.OutboundRecipientsPerHour = 3
	e := testEngine(t, p)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !e.OutboundRecipient(ctx, "Dana@example.com") {
			t.Fatalf("recipient %d refused under the limit", i+1)
		}
	}
	if e.OutboundRecipient(ctx, "dana@example.com") {
		t.Fatal("over the limit was accepted")
	}
	holds := e.Holds(ctx)
	if len(holds) != 1 || holds[0].Account != "dana@example.com" || holds[0].Recipients != 4 {
		t.Fatalf("holds = %+v", holds)
	}
	if e.OutboundRecipient(ctx, "dana@example.com") {
		t.Fatal("a held account sent")
	}
	if !e.OutboundRecipient(ctx, "lee@example.com") {
		t.Fatal("another account was held")
	}
	if err := e.Release(ctx, "dana@example.com", "admin"); err != nil {
		t.Fatal(err)
	}
	if !e.OutboundRecipient(ctx, "dana@example.com") || len(e.Holds(ctx)) != 0 {
		t.Fatal("release didn't let the account send")
	}
	events := e.Events(ctx)
	if len(events) < 2 || events[0].Action != "released" || events[1].Action != "held" {
		t.Fatalf("events = %+v", events)
	}
}

func TestOutboundHoldInLogMode(t *testing.T) {
	p := DefaultPolicy()
	p.Mode, p.OutboundRecipientsPerHour = ModeLog, 1
	e := testEngine(t, p)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !e.OutboundRecipient(ctx, "dana@example.com") {
			t.Fatal("log mode refused")
		}
	}
	if len(e.Holds(ctx)) != 0 {
		t.Fatal("log mode placed a hold")
	}
}

// One password tried on many accounts, once each, stays under the failure
// limit; the number of accounts is what gives it away.
func TestPasswordSprayingBlocks(t *testing.T) {
	p := blockPolicy()
	p.FailuresPerAddress, p.AccountsPerAddress = 100, 5
	e := testEngine(t, p)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		e.Failure(ctx, "203.0.113.9", "imap", fmt.Sprintf("user%d@example.com", i))
	}
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("blocked before the account limit")
	}
	// The same account again doesn't count twice.
	e.Failure(ctx, "203.0.113.9", "imap", "user0@example.com")
	if _, blocked := e.Blocked("203.0.113.9"); blocked {
		t.Fatal("a repeated account counted as a new one")
	}
	e.Failure(ctx, "203.0.113.9", "imap", "user4@example.com")
	if _, blocked := e.Blocked("203.0.113.9"); !blocked {
		t.Fatal("spraying five accounts wasn't blocked")
	}
}

func TestNewLimitsValidate(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.AccountsPerAddress = -1 },
		func(p *Policy) { p.MessagesPerAddressPerHour = -1 },
		func(p *Policy) { p.OutboundRecipientsPerHour = -1 },
	} {
		p := DefaultPolicy()
		change(&p)
		if p.Validate() == nil {
			t.Errorf("%+v was accepted", p)
		}
	}
}

// Holds and spraying are shared: the MTA replica that places a hold isn't
// necessarily the one the next message reaches. Set ELEMTA_TEST_VALKEY_ADDR.
func TestHoldsAndSprayingAreShared(t *testing.T) {
	addr := os.Getenv("ELEMTA_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("ELEMTA_TEST_VALKEY_ADDR not set")
	}
	ctx := context.Background()
	p := DefaultPolicy()
	p.OutboundRecipientsPerHour, p.AccountsPerAddress, p.FailuresPerAddress = 2, 3, 100
	one, two := New("mta-1", addr, nil), New("mta-2", addr, nil)
	for _, e := range []*Engine{one, two} {
		if err := e.Publish(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	account := fmt.Sprintf("shared-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() { _ = one.Release(ctx, account, "test") })
	one.OutboundRecipient(ctx, account)
	two.OutboundRecipient(ctx, account)
	if one.OutboundRecipient(ctx, account) {
		t.Fatal("the shared count didn't reach the limit")
	}
	if two.OutboundRecipient(ctx, account) {
		t.Fatal("a hold placed by one replica didn't stop the other")
	}
	if err := two.Release(ctx, account, "test"); err != nil {
		t.Fatal(err)
	}
	if !one.OutboundRecipient(ctx, account) {
		t.Fatal("a release by one replica didn't reach the other")
	}

	address := fmt.Sprintf("198.51.100.%d", time.Now().UnixNano()%200+20)
	one.Failure(ctx, address, "imap", "a@example.com")
	two.Failure(ctx, address, "pop3", "b@example.com")
	one.Failure(ctx, address, "imap", "c@example.com")
	if _, blocked := one.Blocked(address); !blocked {
		t.Fatal("spraying across two replicas wasn't blocked")
	}
	t.Cleanup(func() { _ = one.Unblock(ctx, address, "test") })
}

// A forged domain arrives from many addresses, each under its own cap.
func TestInboundMessagesPerSenderDomain(t *testing.T) {
	p := DefaultPolicy()
	p.MessagesPerDomainPerHour = 2
	e := testEngine(t, p)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if !e.InboundDomain(ctx, fmt.Sprintf("203.0.113.%d:25", i+1), "a@Forged.example") {
			t.Fatalf("message %d refused under the limit", i+1)
		}
	}
	if e.InboundDomain(ctx, "203.0.113.9:25", "b@forged.example") {
		t.Fatal("a third address got past the domain's limit")
	}
	if !e.InboundDomain(ctx, "203.0.113.9:25", "b@other.example") {
		t.Fatal("another domain shares the count")
	}
	if !e.InboundDomain(ctx, "203.0.113.9:25", "") {
		t.Fatal("a bounce was counted")
	}
}

// Each protocol can have its own connection limits; one not named keeps the
// general ones, and so does a zero.
func TestProtocolConnectionLimits(t *testing.T) {
	p := DefaultPolicy()
	p.ConnectionsPerAddress = 3
	p.ProtocolLimits = []ProtocolLimit{{Protocol: ProtocolPOP3, ConnectionsPerAddress: 1}, {Protocol: ProtocolIMAP, ConnectionsPerMinute: 2}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if n, m := p.ConnectionLimits(ProtocolIMAP); n != 3 || m != 2 {
		t.Fatalf("imap limits %d, %d", n, m)
	}
	e := testEngine(t, p)
	if _, ok := e.Acquire("203.0.113.5:1", ProtocolPOP3); !ok {
		t.Fatal("first POP3 connection refused")
	}
	if _, ok := e.Acquire("203.0.113.5:2", ProtocolPOP3); ok {
		t.Fatal("second POP3 connection allowed over its own limit")
	}
	if _, ok := e.Acquire("203.0.113.5:3", ProtocolSieve); !ok {
		t.Fatal("POP3's count spilled into ManageSieve")
	}
	for i := 0; i < 2; i++ {
		if !e.AllowRate("203.0.113.6:1", ProtocolIMAP) {
			t.Fatalf("IMAP connection %d refused under its rate", i+1)
		}
	}
	if e.AllowRate("203.0.113.6:1", ProtocolIMAP) {
		t.Fatal("IMAP over its own rate was allowed")
	}

	for name, bad := range map[string][]ProtocolLimit{
		"protocol": {{Protocol: "webmail", ConnectionsPerAddress: 1}},
		"twice":    {{Protocol: ProtocolIMAP}, {Protocol: ProtocolIMAP}},
		"negative": {{Protocol: ProtocolIMAP, ConnectionsPerMinute: -1}},
	} {
		q := DefaultPolicy()
		q.ProtocolLimits = bad
		if q.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, bad)
		}
	}
}
