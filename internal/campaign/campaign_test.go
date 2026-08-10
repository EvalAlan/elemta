package campaign

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeQueue records what a campaign hands to the queue.
type fakeQueue struct {
	mu       sync.Mutex
	messages []fakeMessage
	failOn   string // recipient address that should fail
}

type fakeMessage struct {
	From     string
	To       []string
	Subject  string
	Body     string
	Priority queue.Priority
}

func (f *fakeQueue) EnqueueMessage(from string, to []string, subject string, data []byte, priority queue.Priority, _ time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && len(to) > 0 && to[0] == f.failOn {
		return "", io.ErrUnexpectedEOF
	}
	f.messages = append(f.messages, fakeMessage{from, to, subject, string(data), priority})
	return "id", nil
}

func (f *fakeQueue) all() []fakeMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeMessage, len(f.messages))
	copy(out, f.messages)
	return out
}

func testCampaign() *Campaign {
	return &Campaign{
		ID:            "c1",
		Name:          "Test",
		From:          "news@example.com",
		Subject:       "Hello {{name}}",
		TextBody:      "Hi {{name}}, welcome.",
		HTMLBody:      "<p>Hi {{name}}, welcome.</p>",
		RatePerMinute: 60000,
		State:         StateDraft,
		Recipients: []Recipient{
			{Email: "alice@example.net", Vars: map[string]string{"name": "Alice"}},
			{Email: "bob@example.net", Vars: map[string]string{"name": "Bob"}},
		},
		CreatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------- validation

func TestValidateCatchesProblemsBeforeSending(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Campaign)
		want   string
	}{
		{"no name", func(c *Campaign) { c.Name = "" }, "name is required"},
		{"bad from", func(c *Campaign) { c.From = "not an address" }, "not a valid address"},
		{"no subject", func(c *Campaign) { c.Subject = "" }, "subject is required"},
		{"subject with a newline", func(c *Campaign) { c.Subject = "x\r\nBcc: victim@example.com" }, "line breaks"},
		{"no body", func(c *Campaign) { c.TextBody, c.HTMLBody = "", "" }, "body is required"},
		{"no recipients", func(c *Campaign) { c.Recipients = nil }, "at least one recipient"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testCampaign()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a validation error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	if err := testCampaign().Validate(); err != nil {
		t.Errorf("a well-formed campaign should validate: %v", err)
	}
}

// ------------------------------------------------------------------ merging

func TestMergeSubstitutesAndDropsUnknownFields(t *testing.T) {
	vars := map[string]string{"name": "Alice", "city": "Berlin"}

	if got := Merge("Hi {{name}} from {{ city }}", vars); got != "Hi Alice from Berlin" {
		t.Errorf("Merge = %q", got)
	}
	// An unknown field must not survive into the message: mail reading
	// "Hello {{first_name}}" is the classic bulk-send embarrassment.
	if got := Merge("Hi {{first_name}}", vars); strings.Contains(got, "{{") {
		t.Errorf("an unresolved field was left in the output: %q", got)
	}
}

// TestMergeHTMLEscapesValues pins that a crafted recipient variable cannot
// inject markup into everyone's copy of the message.
func TestMergeHTMLEscapesValues(t *testing.T) {
	vars := map[string]string{"name": `<script>alert(1)</script>`}
	got := MergeHTML("<p>Hi {{name}}</p>", vars)
	if strings.Contains(got, "<script>") {
		t.Errorf("a recipient variable injected raw HTML: %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("value was not escaped: %q", got)
	}
}

func TestUnresolvedFieldsWarnsBeforeSending(t *testing.T) {
	recipients := []Recipient{{Email: "a@example.net", Vars: map[string]string{"name": "A"}}}
	got := UnresolvedFields("Hi {{name}}, you live in {{city}}", recipients)
	if len(got) != 1 || got[0] != "city" {
		t.Errorf("UnresolvedFields = %v, want [city]", got)
	}
	if len(UnresolvedFields("Hi {{name}}", recipients)) != 0 {
		t.Error("a field every recipient supplies is not unresolved")
	}
}

// ------------------------------------------------------------ message building

func TestBuildMessageProducesMultipartWithCRLF(t *testing.T) {
	c := testCampaign()
	body, err := BuildMessage(c, c.Recipients[0], "mail.example.com")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	msg := string(body)

	for _, want := range []string{
		"From: <news@example.com>",
		"To: <alice@example.net>",
		"multipart/alternative",
		"text/plain; charset=utf-8",
		"text/html; charset=utf-8",
		"Precedence: bulk",
		"X-Campaign-ID: c1",
		"Hi Alice, welcome.",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message is missing %q:\n%s", want, msg)
		}
	}

	// The server enforces RFC 5321 CRLF in DATA, so a body assembled with bare
	// LF would be refused by the very server sending it.
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Error("message contains a bare LF; it would be refused in DATA")
	}
	// Plain text must come before HTML: clients render the last part they can.
	if strings.Index(msg, "text/plain") > strings.Index(msg, "text/html") {
		t.Error("text/plain must precede text/html in multipart/alternative")
	}
}

// TestBuildMessageRefusesHeaderInjectionViaMergeField is the one that matters
// most: a merge value is attacker-influenced data from an uploaded file, and it
// must not be able to write headers into every message.
func TestBuildMessageRefusesHeaderInjectionViaMergeField(t *testing.T) {
	c := testCampaign()
	c.Subject = "Hello {{name}}"
	r := Recipient{
		Email: "victim@example.net",
		Vars:  map[string]string{"name": "x\r\nBcc: attacker@evil.example"},
	}

	_, err := BuildMessage(c, r, "mail.example.com")
	if err == nil {
		t.Fatal("a merge value containing CRLF must not be written into a header")
	}
	if !strings.Contains(err.Error(), "line break") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildMessageHandlesSingleBodyTypes(t *testing.T) {
	t.Run("text only", func(t *testing.T) {
		c := testCampaign()
		c.HTMLBody = ""
		body, err := BuildMessage(c, c.Recipients[0], "mail.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "multipart") {
			t.Error("a text-only campaign should not be multipart")
		}
	})
	t.Run("html only", func(t *testing.T) {
		c := testCampaign()
		c.TextBody = ""
		body, err := BuildMessage(c, c.Recipients[0], "mail.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "text/html") {
			t.Error("an html-only campaign should be text/html")
		}
	})
}

// ------------------------------------------------------------------ parsing

func TestParseRecipients(t *testing.T) {
	t.Run("bare addresses", func(t *testing.T) {
		rs, problems, err := ParseRecipients("alice@example.net\nbob@example.net\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 2 || len(problems) != 0 {
			t.Errorf("got %d recipients, %d problems", len(rs), len(problems))
		}
	})

	t.Run("csv with merge fields", func(t *testing.T) {
		rs, _, err := ParseRecipients("email,name,city\nalice@example.net,Alice,Berlin\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 1 {
			t.Fatalf("got %d recipients", len(rs))
		}
		if rs[0].Vars["name"] != "Alice" || rs[0].Vars["city"] != "Berlin" {
			t.Errorf("merge fields not parsed: %+v", rs[0].Vars)
		}
	})

	t.Run("duplicates are dropped", func(t *testing.T) {
		rs, _, err := ParseRecipients("a@example.net\nA@EXAMPLE.NET\na@example.net\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 1 {
			t.Errorf("got %d recipients, want 1 — sending duplicates is the most visible way to look broken", len(rs))
		}
	})

	t.Run("bad rows are reported, not silently dropped", func(t *testing.T) {
		rs, problems, err := ParseRecipients("alice@example.net\nnot-an-address\n")
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 1 {
			t.Errorf("got %d valid recipients, want 1", len(rs))
		}
		if len(problems) != 1 {
			t.Errorf("a malformed line must be reported so the operator knows who was not mailed: %v", problems)
		}
	})
}

// ------------------------------------------------------------------- runner

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestRunnerSendsEveryRecipientOnce(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().State == StateCompleted })

	msgs := q.all()
	if len(msgs) != 2 {
		t.Fatalf("enqueued %d messages, want 2", len(msgs))
	}
	seen := map[string]int{}
	for _, m := range msgs {
		seen[m.To[0]]++
		// Bulk mail must not overtake ordinary transactional mail.
		if m.Priority != queue.PriorityLow {
			t.Errorf("campaign mail queued at priority %v, want low", m.Priority)
		}
	}
	for addr, n := range seen {
		if n != 1 {
			t.Errorf("%s received %d copies, want 1", addr, n)
		}
	}
	if got := c.Clone(); got.Sent != 2 || got.Failed != 0 {
		t.Errorf("sent=%d failed=%d, want 2/0", got.Sent, got.Failed)
	}
}

// TestRunnerUsesTheBareAddressAsEnvelopeSender.
//
// `News <news@example.com>` is a correct From header and an invalid MAIL FROM.
// Handing the display-name form to delivery got it stripped into
// `News <news@example.com` — an address with no closing bracket — which is
// where bounces for the campaign would then have gone. Found by watching a real
// send: the delivery agent logged "MAIL FROM still contains extra parameters
// after cleanup, stripping". Every campaign in these tests used a bare address,
// which is why nothing caught it.
func TestRunnerUsesTheBareAddressAsEnvelopeSender(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	c.From = "News <news@example.com>"
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().State == StateCompleted })

	msgs := q.all()
	if len(msgs) == 0 {
		t.Fatal("nothing was enqueued")
	}
	for _, m := range msgs {
		if m.From != "news@example.com" {
			t.Errorf("envelope sender = %q, want the bare address", m.From)
		}
		// The header keeps the display name; only the envelope is stripped.
		if !strings.Contains(m.Body, `From: "News" <news@example.com>`) &&
			!strings.Contains(m.Body, "From: News <news@example.com>") {
			t.Errorf("the From header lost its display name:\n%s", firstLines(m.Body, 6))
		}
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\r\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestRunnerResumesWithoutResending is what makes pause safe: a resumed
// campaign must not mail the people it already reached.
func TestRunnerResumesWithoutResending(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())

	c := testCampaign()
	c.Recipients = nil
	for i := 0; i < 20; i++ {
		c.Recipients = append(c.Recipients, Recipient{Email: string(rune('a'+i)) + "@example.net"})
	}
	c.RatePerMinute = 600 // 100ms apart, slow enough to interrupt
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().Sent >= 2 })
	if err := runner.Pause(c); err != nil {
		t.Fatalf("pause: %v", err)
	}
	sentAtPause := c.Clone().Sent

	c.RatePerMinute = 60000
	if err := runner.Start(c); err != nil {
		t.Fatalf("resume: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool { return c.Clone().State == StateCompleted })

	msgs := q.all()
	if len(msgs) != 20 {
		t.Errorf("enqueued %d messages for 20 recipients", len(msgs))
	}
	seen := map[string]int{}
	for _, m := range msgs {
		seen[m.To[0]]++
	}
	for addr, n := range seen {
		if n != 1 {
			t.Errorf("%s received %d copies after resume, want 1 (paused at %d sent)", addr, n, sentAtPause)
		}
	}
}

func TestRunnerRefusesToStartTwice(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	c.RatePerMinute = 60 // slow, so it is still running for the second call
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = runner.Cancel(c) }()

	if err := runner.Start(c); err == nil {
		t.Error("starting a running campaign must fail; otherwise every remaining recipient is mailed twice")
	}
}

func TestRunnerCancelStops(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	c.RatePerMinute = 60
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := runner.Cancel(c); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if got := c.Clone().State; got != StateCancelled {
		t.Errorf("state = %q, want cancelled", got)
	}
	if err := runner.Start(c); err == nil {
		t.Error("a cancelled campaign must not be restartable")
	}
}

func TestRunnerCountsFailuresAndContinues(t *testing.T) {
	store := NewStore()
	q := &fakeQueue{failOn: "alice@example.net"}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	store.Put(c)

	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().State == StateCompleted })

	got := c.Clone()
	if got.Sent != 1 || got.Failed != 1 {
		t.Errorf("sent=%d failed=%d, want 1/1 — one recipient failing must not stop the campaign", got.Sent, got.Failed)
	}
	if got.LastError == "" {
		t.Error("a failure should be reported on the campaign")
	}
}

func TestRunnerRespectsRateLimit(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())

	c := testCampaign()
	c.Recipients = nil
	for i := 0; i < 6; i++ {
		c.Recipients = append(c.Recipients, Recipient{Email: string(rune('a'+i)) + "@example.net"})
	}
	c.RatePerMinute = 1200 // 50ms apart
	store.Put(c)

	start := time.Now()
	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool { return c.Clone().State == StateCompleted })
	elapsed := time.Since(start)

	// Six messages at 50ms apart cannot finish in under ~250ms. Without a rate
	// limit this completes almost instantly.
	if elapsed < 200*time.Millisecond {
		t.Errorf("6 messages at 1200/min finished in %v; the rate limit is not being applied", elapsed)
	}
}

func TestSendTestUsesFirstRecipientVariables(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()

	if err := runner.SendTest(c, "operator@example.com"); err != nil {
		t.Fatalf("send test: %v", err)
	}
	msgs := q.all()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if !strings.Contains(msgs[0].Subject, "[TEST]") {
		t.Errorf("a test send should be marked: %q", msgs[0].Subject)
	}
	// Merge fields should render as they will in the real send, not as blanks.
	if !strings.Contains(msgs[0].Body, "Alice") {
		t.Error("test send did not use the first recipient's merge values")
	}
	if msgs[0].To[0] != "operator@example.com" {
		t.Errorf("test went to %s", msgs[0].To[0])
	}
}

// fakeSuppressionList answers for a fixed set of addresses.
type fakeSuppressionList struct{ blocked map[string]string }

func (f *fakeSuppressionList) SuppressedWithReason(_ context.Context, address string) (bool, string) {
	reason, ok := f.blocked[strings.ToLower(address)]
	return ok, reason
}

// TestRunnerSkipsSuppressedRecipients is the point of the suppression list: a
// campaign started today must not mail the addresses that bounced yesterday.
func TestRunnerSkipsSuppressedRecipients(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	runner.SetSuppressionList(&fakeSuppressionList{blocked: map[string]string{
		"alice@example.net": "bounce: 550 user unknown",
	}})

	c := testCampaign()
	store.Put(c)
	if err := runner.Start(c); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().State == StateCompleted })

	for _, m := range q.all() {
		for _, to := range m.To {
			if strings.EqualFold(to, "alice@example.net") {
				t.Error("a suppressed address was mailed")
			}
		}
	}

	got := c.Clone()
	// Counted as skipped rather than sent or failed: "sent" would overstate
	// reach and "failed" would look like a delivery problem to investigate.
	if got.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", got.Skipped)
	}
	if got.Sent != 1 {
		t.Errorf("sent = %d, want 1 (the recipient who is not suppressed)", got.Sent)
	}
	if got.Failed != 0 {
		t.Errorf("failed = %d, want 0 — a skip is not a failure", got.Failed)
	}
	// The campaign must still finish rather than stalling on the skipped index.
	if got.Remaining() != 0 {
		t.Errorf("remaining = %d, want 0", got.Remaining())
	}
}

// TestRunnerWithoutSuppressionListSendsToEveryone keeps the feature optional:
// a deployment without a list behaves as it did before one existed.
func TestRunnerWithoutSuppressionListSendsToEveryone(t *testing.T) {
	store, q := NewStore(), &fakeQueue{}
	runner := NewRunner(store, q, "mail.example.com", quiet())
	c := testCampaign()
	store.Put(c)
	if err := runner.Start(c); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return c.Clone().State == StateCompleted })

	if len(q.all()) != 2 || c.Clone().Skipped != 0 {
		t.Errorf("enqueued %d with %d skipped, want 2 and 0", len(q.all()), c.Clone().Skipped)
	}
}
