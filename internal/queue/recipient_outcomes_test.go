package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type outcomeHandler struct {
	result *DeliveryResult
	err    error
}

func (h outcomeHandler) DeliverMessage(context.Context, Message, []byte) error { return h.err }
func (h outcomeHandler) DeliverMessageWithMetadata(context.Context, Message, []byte) (*DeliveryResult, error) {
	return h.result, h.err
}
func (outcomeHandler) GetFailedQueueRetentionHours() int { return 0 }

type bounceCapture struct{ messages []Message }

func (b *bounceCapture) GenerateBounceIfNeeded(_ context.Context, msg Message, _ string) *BounceResult {
	b.messages = append(b.messages, msg)
	return &BounceResult{}
}

type bounceDetailCapture struct {
	messages []Message
	reasons  []string
}

func (b *bounceDetailCapture) GenerateBounceIfNeeded(_ context.Context, msg Message, reason string) *BounceResult {
	b.messages = append(b.messages, msg)
	b.reasons = append(b.reasons, reason)
	return &BounceResult{}
}

func runMessage(t *testing.T, p *Processor, msg Message) {
	t.Helper()
	p.workerSem <- struct{}{}
	p.wg.Add(1)
	p.processMessage(msg)
}

func TestNormalizeDeliveryResultMalformedContracts(t *testing.T) {
	msg := Message{To: []string{"a@example.test"}}
	for _, tc := range []struct {
		name string
		res  *DeliveryResult
		err  error
	}{{"nil result and error", nil, nil}, {"unsuccessful and nil error", &DeliveryResult{Success: false}, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := normalizeDeliveryResult(msg, tc.res, tc.err)
			if res == nil || err == nil || len(res.RecipientOutcomes) != 1 || res.RecipientOutcomes[0].Status != RecipientTemporaryFailure {
				t.Fatalf("unsafe normalization: result=%+v err=%v", res, err)
			}
		})
	}
}

func TestNormalizeDeliveryResultMalformedRecipientOutcomes(t *testing.T) {
	msg := Message{To: []string{"a@example.test", "b@example.test"}}
	cases := []struct {
		name string
		res  *DeliveryResult
		err  error
		want []RecipientDeliveryStatus
	}{
		{"unknown status", &DeliveryResult{RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: "mystery"}}}, errors.New("451 temporary"), []RecipientDeliveryStatus{RecipientTemporaryFailure, RecipientTemporaryFailure}},
		{"empty and extra recipients", &DeliveryResult{RecipientOutcomes: []RecipientOutcome{{Recipient: "", Status: RecipientDelivered}, {Recipient: "extra@example.test", Status: RecipientDelivered}}}, errors.New("451 temporary"), []RecipientDeliveryStatus{RecipientTemporaryFailure, RecipientTemporaryFailure}},
		{"duplicate first wins", &DeliveryResult{RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientTemporaryFailure}, {Recipient: msg.To[0], Status: RecipientDelivered}}}, errors.New("partial"), []RecipientDeliveryStatus{RecipientTemporaryFailure, RecipientTemporaryFailure}},
		{"missing on success with error", &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientDelivered}}}, errors.New("partial"), []RecipientDeliveryStatus{RecipientDelivered, RecipientTemporaryFailure}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := normalizeDeliveryResult(msg, tc.res, tc.err)
			if len(got.RecipientOutcomes) != len(tc.want) {
				t.Fatalf("outcomes=%+v", got.RecipientOutcomes)
			}
			for i, want := range tc.want {
				if got.RecipientOutcomes[i].Recipient != msg.To[i] || got.RecipientOutcomes[i].Status != want {
					t.Fatalf("outcome[%d]=%+v", i, got.RecipientOutcomes[i])
				}
			}
		})
	}
}

func TestNormalizeDeliveryResultMalformedOutcomesStayTemporaryUnderPermanentAggregate(t *testing.T) {
	msg := Message{To: []string{"a@example.test", "b@example.test"}}
	permanent := &PermanentError{msg: "aggregate permanent failure"}
	cases := []struct {
		name     string
		outcomes []RecipientOutcome
		want     []RecipientDeliveryStatus
	}{
		{"missing", []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientPermanentFailure}}, []RecipientDeliveryStatus{RecipientPermanentFailure, RecipientTemporaryFailure}},
		{"unknown", []RecipientOutcome{{Recipient: msg.To[0], Status: "unknown"}}, []RecipientDeliveryStatus{RecipientTemporaryFailure, RecipientTemporaryFailure}},
		{"empty and extra", []RecipientOutcome{{Recipient: "", Status: RecipientPermanentFailure}, {Recipient: "extra@example.test", Status: RecipientPermanentFailure}}, []RecipientDeliveryStatus{RecipientTemporaryFailure, RecipientTemporaryFailure}},
		{"duplicate extra ignored", []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientPermanentFailure}, {Recipient: msg.To[0], Status: RecipientPermanentFailure}}, []RecipientDeliveryStatus{RecipientPermanentFailure, RecipientTemporaryFailure}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := normalizeDeliveryResult(msg, &DeliveryResult{RecipientOutcomes: tc.outcomes}, permanent)
			for i, outcome := range got.RecipientOutcomes {
				if outcome.Status != tc.want[i] {
					t.Fatalf("outcome[%d]=%+v; all=%+v", i, outcome, got.RecipientOutcomes)
				}
			}
		})
	}
}

func TestNormalizeDeliveryResultSuccessWithErrorUsesOutcomes(t *testing.T) {
	msg := Message{To: []string{"ok@example.test", "later@example.test"}}
	res, err := normalizeDeliveryResult(msg, &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientDelivered}, {Recipient: msg.To[1], Status: RecipientTemporaryFailure}}}, errors.New("partial"))
	if err == nil || !res.Success || res.RecipientOutcomes[0].Status != RecipientDelivered {
		t.Fatalf("partial contract was discarded: %+v, %v", res, err)
	}
}

func TestProcessorPersistsOnlyTemporaryRecipientsAfterPartialDelivery(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(dir, 0)
	id, err := manager.EnqueueMessage("sender@example.test", []string{"ok@one.test", "later@two.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := manager.GetMessage(id)
	p := NewProcessor(manager, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientDelivered, EnhancedStatusCode: "2.0.0"}, {Recipient: msg.To[1], Status: RecipientTemporaryFailure, EnhancedStatusCode: "4.5.1", Diagnostic: "greylisted"}}}, err: errors.New("partial")})
	runMessage(t, p, msg)
	manager.Stop()
	reloaded := NewManager(dir, 0)
	defer reloaded.Stop()
	stored, err := reloaded.GetMessage(id)
	if err != nil || len(stored.To) != 1 || stored.To[0] != "later@two.test" || stored.QueueType != Deferred {
		t.Fatalf("stored envelope: %+v %v", stored, err)
	}
}

func TestRecipientReductionPersistsAcrossBackendReload(t *testing.T) {
	for _, typ := range []string{"file", "sqlite", "indexedfs"} {
		t.Run(typ, func(t *testing.T) {
			dir := t.TempDir()
			open := func() StorageBackend {
				switch typ {
				case "file":
					return NewFileStorageBackend(dir)
				case "sqlite":
					b, err := NewSQLiteStorageBackend(filepath.Join(dir, "queue.db"), 1000, "WAL", "NORMAL")
					if err != nil {
						t.Fatal(err)
					}
					return b
				default:
					b, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{})
					if err != nil {
						t.Fatal(err)
					}
					return b
				}
			}
			backend := open()
			manager := NewManagerWithStorage(backend, 0)
			id, err := manager.EnqueueMessage("sender@example.test", []string{"ok@example.test", "later@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			msg, _ := manager.GetMessage(id)
			p := NewProcessor(manager, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientDelivered}, {Recipient: msg.To[1], Status: RecipientTemporaryFailure}}}, err: errors.New("451 temporary")})
			runMessage(t, p, msg)
			manager.Stop()
			if sqlite, ok := backend.(*SQLiteStorageBackend); ok {
				if err := sqlite.db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			fresh := open()
			defer func() {
				if sqlite, ok := fresh.(*SQLiteStorageBackend); ok {
					_ = sqlite.db.Close()
				}
			}()
			got, err := fresh.Retrieve(id)
			if err != nil || got.QueueType != Deferred || len(got.To) != 1 || got.To[0] != "later@example.test" {
				t.Fatalf("reloaded=%+v err=%v", got, err)
			}
		})
	}
}

type updateFailBackend struct {
	StorageBackend
	fail bool
}

func (b *updateFailBackend) Update(msg Message) error {
	if b.fail {
		return errors.New("injected update failure")
	}
	return b.StorageBackend.Update(msg)
}

type metricCapture struct {
	recent  []string
	domains []string // "domain:outcome" pairs, in the order they were recorded
}

func (*metricCapture) IncrDelivered(context.Context) error { return nil }
func (*metricCapture) IncrFailed(context.Context) error    { return nil }
func (*metricCapture) IncrDeferred(context.Context) error  { return nil }
func (m *metricCapture) IncrDomainOutcome(_ context.Context, domain, outcome string) error {
	m.domains = append(m.domains, domain+":"+outcome)
	return nil
}
func (m *metricCapture) AddRecentError(_ context.Context, _, _, detail string) error {
	m.recent = append(m.recent, detail)
	return nil
}

func TestRecipientReductionUpdateFailurePreservesEnvelopeAndObservesDuplicateRisk(t *testing.T) {
	base := NewFileStorageBackend(t.TempDir())
	wrapped := &updateFailBackend{StorageBackend: base}
	m := NewManagerWithStorage(wrapped, 24)
	defer m.Stop()
	id, err := m.EnqueueMessage("sender@example.test", []string{"accepted@example.test", "later@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	original, err := m.GetMessage(id)
	if err != nil {
		t.Fatalf("get enqueued message: %v", err)
	}
	wrapped.fail = true
	metrics := &metricCapture{}
	var logs bytes.Buffer
	p := NewProcessor(m, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: original.To[0], Status: RecipientDelivered}, {Recipient: original.To[1], Status: RecipientTemporaryFailure}}}, err: errors.New("451 temporary")})
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	p.SetMetricsRecorder(metrics)
	runMessage(t, p, original)
	got, err := m.GetMessage(id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.To, ",") != strings.Join(original.To, ",") || got.QueueType != original.QueueType || got.RetryCount != original.RetryCount {
		t.Fatalf("original mutated: before=%+v after=%+v", original, got)
	}
	gotAgain, _ := m.GetMessage(id)
	if strings.Join(gotAgain.To, ",") != strings.Join(original.To, ",") {
		t.Fatalf("subsequent retrieval changed: %+v", gotAgain)
	}
	if !strings.Contains(logs.String(), "duplicate_risk=true") || len(metrics.recent) != 1 || !strings.Contains(metrics.recent[0], "duplicate_risk") {
		t.Fatalf("risk not observable: logs=%q metrics=%v", logs.String(), metrics.recent)
	}
}

func TestProcessorBouncesOnlyPermanentRecipientAndDoesNotRetryIt(t *testing.T) {
	manager := NewManager(t.TempDir(), 0)
	defer manager.Stop()
	id, _ := manager.EnqueueMessage("sender@example.test", []string{"ok@example.test", "bad@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	msg, _ := manager.GetMessage(id)
	capture := &bounceCapture{}
	p := NewProcessor(manager, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{Success: true, RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientDelivered}, {Recipient: msg.To[1], Status: RecipientPermanentFailure, EnhancedStatusCode: "5.1.1"}}}, err: errors.New("partial")})
	p.SetBounceEngine(capture)
	runMessage(t, p, msg)
	if len(capture.messages) != 1 || len(capture.messages[0].To) != 1 || capture.messages[0].To[0] != msg.To[1] {
		t.Fatalf("DSN recipients: %+v", capture.messages)
	}
	if _, err := manager.GetMessage(id); err == nil {
		t.Fatal("message remains queued")
	}
}

func TestPermanentRecipientDiagnosticUsedForDSNHandoff(t *testing.T) {
	m := NewManager(t.TempDir(), 0)
	defer m.Stop()
	id, _ := m.EnqueueMessage("sender@example.test", []string{"bad@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	msg, _ := m.GetMessage(id)
	b := &bounceDetailCapture{}
	p := NewProcessor(m, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientPermanentFailure, EnhancedStatusCode: "5.1.1", Diagnostic: "550 5.1.1 user unknown", Route: "mx.example"}}}, err: errors.New("aggregate delivery failure")})
	p.SetBounceEngine(b)
	runMessage(t, p, msg)
	if len(b.reasons) != 1 || b.reasons[0] != "550 5.1.1 user unknown" {
		t.Fatalf("DSN reason=%v", b.reasons)
	}
}

func TestNullReversePathNeverBounces(t *testing.T) {
	manager := NewManager(t.TempDir(), 0)
	defer manager.Stop()
	id, _ := manager.EnqueueMessage("<>", []string{"bad@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	msg, _ := manager.GetMessage(id)
	capture := &bounceCapture{}
	p := NewProcessor(manager, DefaultProcessorConfig(), outcomeHandler{result: &DeliveryResult{RecipientOutcomes: []RecipientOutcome{{Recipient: msg.To[0], Status: RecipientPermanentFailure}}}, err: errors.New("550")})
	p.SetBounceEngine(capture)
	runMessage(t, p, msg)
	if len(capture.messages) != 0 {
		t.Fatal("generated bounce for null reverse path")
	}
}

type idempotentBounceCapture struct{ ids []string }

func (b *idempotentBounceCapture) GenerateBounceIfNeeded(context.Context, Message, string) *BounceResult {
	return &BounceResult{Error: errors.New("non-idempotent path used")}
}
func (b *idempotentBounceCapture) GenerateBounceIdempotent(_ context.Context, _ Message, _ string, id string) *BounceResult {
	b.ids = append(b.ids, id)
	return &BounceResult{BounceGenerated: true, BounceID: id}
}

type countingOutcomeHandler struct{ calls int }

func (h *countingOutcomeHandler) DeliverMessage(context.Context, Message, []byte) error {
	h.calls++
	return nil
}
func (h *countingOutcomeHandler) DeliverMessageWithMetadata(context.Context, Message, []byte) (*DeliveryResult, error) {
	h.calls++
	return &DeliveryResult{Success: true}, nil
}
func (*countingOutcomeHandler) GetFailedQueueRetentionHours() int { return 0 }

func TestPendingDSNHandoffResumesBeforeRemoteDelivery(t *testing.T) {
	m := NewManager(t.TempDir(), 0)
	defer m.Stop()
	id, _ := m.EnqueueMessage("sender@example.test", []string{"bad@example.test", "later@example.test"}, "s", []byte("body"), PriorityNormal, time.Now())
	msg, _ := m.GetMessage(id)
	handoff := dsnHandoff{State: "pending", Permanent: []dsnRecipient{{Occurrence: id + ":0", Address: msg.To[0], Diagnostic: "550 user unknown"}}, Temporary: []dsnRecipient{{Occurrence: id + ":1", Address: msg.To[1]}}}
	sum := sha256.Sum256([]byte(id + "\x00" + occurrenceList(handoff.Permanent)))
	handoff.ID = "dsn-" + hex.EncodeToString(sum[:16])
	encoded, _ := json.Marshal(handoff)
	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}
	msg.Annotations[dsnHandoffAnnotation] = string(encoded)
	if err := m.storageBackend.Update(msg); err != nil {
		t.Fatal(err)
	}
	handler, bounces := &countingOutcomeHandler{}, &idempotentBounceCapture{}
	p := NewProcessor(m, DefaultProcessorConfig(), handler)
	p.SetBounceEngine(bounces)
	runMessage(t, p, msg)
	if handler.calls != 0 {
		t.Fatalf("remote handler called %d times", handler.calls)
	}
	if len(bounces.ids) != 1 || bounces.ids[0] != handoff.ID {
		t.Fatalf("handoffs=%v", bounces.ids)
	}
	stored, err := m.GetMessage(id)
	if err != nil || stored.QueueType != Deferred || len(stored.To) != 1 || stored.To[0] != "later@example.test" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
}

func TestEnqueueMessageWithIDIsIdempotent(t *testing.T) {
	m := NewManager(t.TempDir(), 0)
	defer m.Stop()
	receivedAt := time.Now()
	for i := 0; i < 2; i++ {
		got, err := m.EnqueueMessageWithID("dsn-fixed", "postmaster@example.test", []string{"sender@example.test"}, "dsn", []byte("body"), PriorityHigh, receivedAt)
		if err != nil || got != "dsn-fixed" {
			t.Fatalf("enqueue %d: %q %v", i, got, err)
		}
	}
	messages, _ := m.ListMessages(Active)
	if len(messages) != 1 {
		t.Fatalf("duplicate queue entries: %+v", messages)
	}
}
