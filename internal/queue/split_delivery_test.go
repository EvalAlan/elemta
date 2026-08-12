package queue

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Routing decides where accepted mail goes. The tests that matter are the ones
// where getting it wrong is visible to a person: a message delivered twice, a
// message sent out over the internet that should have stayed local, or a local
// mailbox never receiving anything because an unrelated domain deferred.

// recordingHandler remembers what it was asked to deliver.
type recordingHandler struct {
	name      string
	delivered [][]string
	err       error
	status    RecipientDeliveryStatus
}

func (h *recordingHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

func (h *recordingHandler) DeliverMessageWithMetadata(_ context.Context, msg Message, _ []byte) (*DeliveryResult, error) {
	h.delivered = append(h.delivered, append([]string(nil), msg.To...))
	status := h.status
	if status == "" {
		status = RecipientDelivered
		if h.err != nil {
			status = RecipientTemporaryFailure
		}
	}
	diagnostic := ""
	if h.err != nil {
		diagnostic = h.err.Error()
	}
	return &DeliveryResult{
		Success:           h.err == nil,
		Error:             h.err,
		DeliveryHost:      h.name,
		RecipientOutcomes: outcomesFor(msg.To, status, diagnostic, ""),
	}, h.err
}

func (h *recordingHandler) GetFailedQueueRetentionHours() int { return 24 }

func newSplit(local, remote *recordingHandler) *SplitDeliveryHandler {
	return NewSplitDeliveryHandler(local, remote, []string{"example.com", "Mail.Example.COM"}, nil)
}

func TestRecipientsGoToTheRouteTheirDomainDeserves(t *testing.T) {
	local, remote := &recordingHandler{name: "dovecot"}, &recordingHandler{name: "smtp"}
	split := newSplit(local, remote)

	msg := Message{ID: "m1", From: "sender@example.com", To: []string{
		"inside@example.com",
		"outside@other.example",
		"inside2@MAIL.EXAMPLE.COM", // local domains match case-insensitively
	}}

	result, err := split.DeliverMessageWithMetadata(context.Background(), msg, []byte("body"))
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if !result.Success {
		t.Error("result is not successful although both routes succeeded")
	}

	if len(local.delivered) != 1 || len(local.delivered[0]) != 2 {
		t.Fatalf("local handler received %v, want the two local recipients", local.delivered)
	}
	if len(remote.delivered) != 1 || len(remote.delivered[0]) != 1 ||
		remote.delivered[0][0] != "outside@other.example" {
		t.Fatalf("remote handler received %v, want only the outside address", remote.delivered)
	}

	// Every recipient must be accounted for, or the queue cannot tell which
	// ones still need delivering.
	if len(result.RecipientOutcomes) != 3 {
		t.Errorf("got %d outcomes for 3 recipients: %+v", len(result.RecipientOutcomes), result.RecipientOutcomes)
	}
	routes := map[string]string{}
	for _, o := range result.RecipientOutcomes {
		routes[o.Recipient] = o.Route
	}
	if routes["inside@example.com"] != "local" || routes["outside@other.example"] != "remote" {
		t.Errorf("routes were not recorded per recipient: %v", routes)
	}
}

// TestLocalMailIsNeverSentOverTheInternet is the one with real consequences: a
// local domain leaking onto the remote route means internal mail leaves the
// building and its MX may not even be us.
func TestLocalMailIsNeverSentOverTheInternet(t *testing.T) {
	local, remote := &recordingHandler{name: "dovecot"}, &recordingHandler{name: "smtp"}
	split := newSplit(local, remote)

	msg := Message{ID: "m2", To: []string{"a@example.com", "b@example.com"}}
	if _, err := split.DeliverMessageWithMetadata(context.Background(), msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if len(remote.delivered) != 0 {
		t.Errorf("local-only mail reached the remote route: %v", remote.delivered)
	}
}

// TestPartialFailureReportsPerRecipient. The queue drops delivered recipients
// before retrying, so an accurate per-recipient result is what stops a remote
// deferral from redelivering to the local mailbox on every attempt — which the
// recipient experiences as the same message arriving over and over.
func TestPartialFailureReportsPerRecipient(t *testing.T) {
	local := &recordingHandler{name: "dovecot"}
	remote := &recordingHandler{name: "smtp", err: errors.New("450 4.7.1 try again later")}
	split := newSplit(local, remote)

	msg := Message{ID: "m3", To: []string{"inside@example.com", "outside@other.example"}}
	result, err := split.DeliverMessageWithMetadata(context.Background(), msg, []byte("body"))

	if err == nil {
		t.Fatal("a failing route must surface an error so the message is retried")
	}
	if result.Success {
		t.Error("result claims success although the remote route failed")
	}

	byRecipient := map[string]RecipientDeliveryStatus{}
	for _, o := range result.RecipientOutcomes {
		byRecipient[o.Recipient] = o.Status
	}
	if byRecipient["inside@example.com"] != RecipientDelivered {
		t.Errorf("the local recipient was delivered but is reported as %q; it would be delivered again on retry",
			byRecipient["inside@example.com"])
	}
	if byRecipient["outside@other.example"] != RecipientTemporaryFailure {
		t.Errorf("the failed remote recipient is reported as %q", byRecipient["outside@other.example"])
	}
}

// TestOneRouteFailingDoesNotStopTheOther: a deferral from an outside domain
// must not hold up mail to a mailbox two containers away.
func TestOneRouteFailingDoesNotStopTheOther(t *testing.T) {
	local := &recordingHandler{name: "dovecot"}
	remote := &recordingHandler{name: "smtp", err: errors.New("connection refused")}
	split := newSplit(local, remote)

	msg := Message{ID: "m4", To: []string{"inside@example.com", "outside@other.example"}}
	_, _ = split.DeliverMessageWithMetadata(context.Background(), msg, []byte("body"))

	if len(local.delivered) != 1 {
		t.Errorf("local delivery did not happen when the remote route failed: %v", local.delivered)
	}
}

// TestDuplicateRecipientsSurvive: duplicates in an envelope are legal, and the
// queue matches outcomes to recipients by occurrence rather than by address.
func TestDuplicateRecipientsSurvive(t *testing.T) {
	local, remote := &recordingHandler{name: "dovecot"}, &recordingHandler{name: "smtp"}
	split := newSplit(local, remote)

	msg := Message{ID: "m5", To: []string{
		"a@example.com", "a@example.com", "b@other.example", "b@other.example",
	}}
	result, err := split.DeliverMessageWithMetadata(context.Background(), msg, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecipientOutcomes) != 4 {
		t.Errorf("got %d outcomes for 4 envelope recipients", len(result.RecipientOutcomes))
	}
	if len(local.delivered[0]) != 2 || len(remote.delivered[0]) != 2 {
		t.Errorf("duplicates were collapsed: local=%v remote=%v", local.delivered, remote.delivered)
	}
}

// TestSingleRouteMessagesAreNotWrapped keeps the ordinary case identical to the
// behaviour before routing existed.
func TestSingleRouteMessagesAreNotWrapped(t *testing.T) {
	local, remote := &recordingHandler{name: "dovecot"}, &recordingHandler{name: "smtp"}
	split := newSplit(local, remote)

	result, err := split.DeliverMessageWithMetadata(context.Background(),
		Message{ID: "m6", To: []string{"only@other.example"}}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if result.DeliveryHost != "smtp" {
		t.Errorf("delivery host = %q; a single-route message should report its handler's own result", result.DeliveryHost)
	}
	if len(local.delivered) != 0 {
		t.Error("the local handler was consulted for a remote-only message")
	}
}

// TestMissingHandlerDefersRatherThanBounces: a route with nothing behind it is
// a configuration fault. Bouncing would destroy deliverable mail over it.
func TestMissingHandlerDefersRatherThanBounces(t *testing.T) {
	split := NewSplitDeliveryHandler(nil, &recordingHandler{name: "smtp"}, []string{"example.com"}, nil)

	result, err := split.DeliverMessageWithMetadata(context.Background(),
		Message{ID: "m7", To: []string{"inside@example.com"}}, []byte("body"))
	if err == nil {
		t.Fatal("expected an error when the local route has no handler")
	}
	for _, o := range result.RecipientOutcomes {
		if o.Status != RecipientTemporaryFailure {
			t.Errorf("recipient reported as %q; a missing handler must be temporary", o.Status)
		}
	}
	if !strings.Contains(err.Error(), "local") {
		t.Errorf("error does not say which route is unconfigured: %v", err)
	}
}

// TestNoLocalDomainsMeansEverythingIsRemote: a relay configured with no local
// domains must not start treating the internet as local.
func TestNoLocalDomainsMeansEverythingIsRemote(t *testing.T) {
	local, remote := &recordingHandler{name: "dovecot"}, &recordingHandler{name: "smtp"}
	split := NewSplitDeliveryHandler(local, remote, nil, nil)

	if _, err := split.DeliverMessageWithMetadata(context.Background(),
		Message{ID: "m8", To: []string{"someone@example.com"}}, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if len(local.delivered) != 0 {
		t.Errorf("with no local domains configured, mail still went local: %v", local.delivered)
	}
	if len(remote.delivered) != 1 {
		t.Errorf("remote handler received %v", remote.delivered)
	}
}
