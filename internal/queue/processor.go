package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/logging"
	"github.com/google/uuid"
)

// ProcessorConfig holds configuration for the queue processor
type ProcessorConfig struct {
	Enabled       bool          `json:"enabled" yaml:"enabled" toml:"enabled"`
	Interval      time.Duration `json:"interval" yaml:"interval" toml:"interval"`
	MaxConcurrent int           `json:"max_concurrent" yaml:"max_concurrent" toml:"max_concurrent"`
	MaxRetries    int           `json:"max_retries" yaml:"max_retries" toml:"max_retries"`
	RetrySchedule []int         `json:"retry_schedule" yaml:"retry_schedule" toml:"retry_schedule"`
	CleanupAge    time.Duration `json:"cleanup_age" yaml:"cleanup_age" toml:"cleanup_age"`
}

// DefaultProcessorConfig returns sensible defaults
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{
		Enabled:       true,
		Interval:      10 * time.Second,
		MaxConcurrent: 5,
		// MaxRetries spans the extended backoff schedule so a briefly-unreachable
		// or greylisting destination stays queued ~4 days before bouncing, rather
		// than being abandoned after a few hours.
		MaxRetries:    len(defaultRetrySchedule),
		RetrySchedule: defaultRetrySchedule,
		CleanupAge:    24 * time.Hour,
	}
}

// DeliveryHandler defines the interface for actual message delivery
// DeliveryResult contains metadata about a delivery attempt
type DeliveryResult struct {
	Success           bool
	Error             error
	DeliveryIP        string
	DeliveryHost      string
	DeliveryTime      time.Time
	ResponseMessage   string
	RecipientOutcomes []RecipientOutcome
}

type RecipientDeliveryStatus string

const (
	RecipientDelivered        RecipientDeliveryStatus = "delivered"
	RecipientTemporaryFailure RecipientDeliveryStatus = "temporary_failure"
	RecipientPermanentFailure RecipientDeliveryStatus = "permanent_failure"
)

// RecipientOutcome is the protocol-level disposition of one envelope recipient.
type RecipientOutcome struct {
	Recipient          string
	Status             RecipientDeliveryStatus
	EnhancedStatusCode string
	Diagnostic         string
	Route              string
}

// normalizeDeliveryResult enforces a deterministic, panic-free handler contract.
// Missing/malformed recipient entries are conservatively treated as temporary.
func normalizeDeliveryResult(msg Message, result *DeliveryResult, deliveryErr error) (*DeliveryResult, error) {
	if result == nil {
		result = &DeliveryResult{}
	}
	if deliveryErr == nil {
		deliveryErr = result.Error
	}
	if deliveryErr == nil && !result.Success {
		deliveryErr = errors.New("delivery handler returned an unsuccessful result without an error")
	}
	// Match by occurrence, not address. Duplicate envelope recipients are valid.
	byRecipient := make(map[string][]RecipientOutcome, len(result.RecipientOutcomes))
	expected := make(map[string]int, len(msg.To))
	for _, recipient := range msg.To {
		expected[recipient]++
	}
	for _, outcome := range result.RecipientOutcomes {
		if outcome.Recipient == "" || expected[outcome.Recipient] == 0 || len(byRecipient[outcome.Recipient]) >= expected[outcome.Recipient] {
			continue
		}
		switch outcome.Status {
		case RecipientDelivered, RecipientTemporaryFailure, RecipientPermanentFailure:
			byRecipient[outcome.Recipient] = append(byRecipient[outcome.Recipient], outcome)
		}
	}
	normalized := make([]RecipientOutcome, 0, len(msg.To))
	for _, recipient := range msg.To {
		if occurrences := byRecipient[recipient]; len(occurrences) > 0 {
			normalized = append(normalized, occurrences[0])
			byRecipient[recipient] = occurrences[1:]
			continue
		}
		// An absent, unknown, duplicate, or otherwise malformed recipient outcome
		// is never promoted by an aggregate error. Only a valid explicit outcome
		// can permanently fail (or deliver) a recipient.
		normalized = append(normalized, RecipientOutcome{Recipient: recipient, Status: RecipientTemporaryFailure})
	}
	result.RecipientOutcomes = normalized
	result.Error = deliveryErr
	return result, deliveryErr
}

type DeliveryHandler interface {
	DeliverMessage(ctx context.Context, msg Message, content []byte) error
	DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error)
	GetFailedQueueRetentionHours() int
}

// MetricsRecorder interface for recording delivery metrics
type MetricsRecorder interface {
	IncrDelivered(ctx context.Context) error
	IncrFailed(ctx context.Context) error
	IncrDeferred(ctx context.Context) error
	AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error
}

// ClaimingStorageBackend defines optional atomic-claim semantics for distributed queue workers.
type ClaimingStorageBackend interface {
	ClaimMessages(queueType QueueType, limit int, workerID string, leaseUntil time.Time) ([]Message, error)
	ReleaseMessageClaim(id, workerID string) error
}

// BounceEngine defines the interface for generating DSN bounce messages
type BounceEngine interface {
	GenerateBounceIfNeeded(ctx context.Context, msg Message, failureReason string) *BounceResult
}

type idempotentBounceEngine interface {
	GenerateBounceIdempotent(context.Context, Message, string, string) *BounceResult
}

const dsnHandoffAnnotation = "recipient_dsn_handoff_v2"
const recipientOccurrencesAnnotation = "recipient_occurrences_v1"

type dsnRecipient struct {
	Occurrence string `json:"occurrence"`
	Address    string `json:"address"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

type dsnHandoff struct {
	ID        string         `json:"id"`
	State     string         `json:"state"`
	Permanent []dsnRecipient `json:"permanent"`
	Temporary []dsnRecipient `json:"temporary,omitempty"`
	Delivered []dsnRecipient `json:"delivered,omitempty"`
}

// BounceResult contains the result of a bounce generation attempt
type BounceResult struct {
	BounceGenerated bool
	BounceID        string
	Error           error
}

// Processor orchestrates queue processing and delivery
type Processor struct {
	manager      *Manager
	config       ProcessorConfig
	handler      DeliveryHandler
	logger       *slog.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	workerSem    chan struct{}
	bounceEngine BounceEngine

	// Metrics
	metricsLock      sync.RWMutex
	processedCount   int64
	deliveredCount   int64
	failedCount      int64
	retryCount       int64
	metricsRecorders []MetricsRecorder

	// New field for processing messages
	processingMessages map[string]bool

	// Message lifecycle logger
	msgLogger *logging.MessageLogger

	// Distributed claim identity for backends that support atomic claims.
	workerID string
}

// NewProcessor creates a new queue processor
func NewProcessor(manager *Manager, config ProcessorConfig, handler DeliveryHandler) *Processor {
	ctx, cancel := context.WithCancel(context.Background())

	// Honor the operator-configured retry schedule for deferred backoff.
	manager.SetRetrySchedule(config.RetrySchedule)

	baseLogger := slog.Default().With("component", "queue-processor")
	return &Processor{
		manager:            manager,
		config:             config,
		handler:            handler,
		logger:             baseLogger,
		ctx:                ctx,
		cancel:             cancel,
		workerSem:          make(chan struct{}, config.MaxConcurrent),
		processingMessages: make(map[string]bool),
		msgLogger:          logging.NewMessageLogger(baseLogger),
		workerID:           uuid.NewString(),
	}
}

// SetMetricsRecorder replaces the processor's metrics recorders with a single one.
func (p *Processor) SetMetricsRecorder(recorder MetricsRecorder) {
	p.metricsRecorders = []MetricsRecorder{recorder}
}

// AddMetricsRecorder appends an additional metrics recorder; delivery events are
// fanned out to every registered recorder (e.g. Valkey and Prometheus together).
func (p *Processor) AddMetricsRecorder(recorder MetricsRecorder) {
	if recorder != nil {
		p.metricsRecorders = append(p.metricsRecorders, recorder)
	}
}

// recordMetric fans a recorder callback out to all registered recorders.
func (p *Processor) recordMetric(fn func(MetricsRecorder) error) {
	for _, r := range p.metricsRecorders {
		if err := fn(r); err != nil {
			p.logger.Debug("metrics recorder error", "error", err)
		}
	}
}

// SetBounceEngine sets the bounce engine for DSN generation on permanent failures
func (p *Processor) SetBounceEngine(engine BounceEngine) {
	p.bounceEngine = engine
}

// Start begins processing queues
func (p *Processor) Start() error {
	if !p.config.Enabled {
		p.logger.Info("Queue processor disabled, not starting")
		return nil
	}

	p.logger.Info("Starting queue processor",
		"interval", p.config.Interval,
		"max_concurrent", p.config.MaxConcurrent,
		"max_retries", p.config.MaxRetries)

	// Start active queue processor
	p.wg.Add(1)
	go p.processActiveQueue()

	// Start deferred queue processor
	p.wg.Add(1)
	go p.processDeferredQueue()

	// Start cleanup processor
	p.wg.Add(1)
	go p.processCleanup()

	// Start metrics reporter
	p.wg.Add(1)
	go p.reportMetrics()

	return nil
}

// Stop stops the queue processor
func (p *Processor) Stop() error {
	p.logger.Info("Stopping queue processor")
	p.cancel()
	p.wg.Wait()
	p.logger.Info("Queue processor stopped")
	return nil
}

// processActiveQueue continuously processes messages in the active queue
func (p *Processor) processActiveQueue() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.processQueue(Active); err != nil {
				p.logger.Error("Failed to process active queue", "error", err)
			}
		}
	}
}

// processDeferredQueue moves ready deferred messages back to active queue
func (p *Processor) processDeferredQueue() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Interval * 2) // Check less frequently
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.processDeferredMessages(); err != nil {
				p.logger.Error("Failed to process deferred queue", "error", err)
			}
		}
	}
}

// processCleanup periodically cleans up old messages
func (p *Processor) processCleanup() {
	defer p.wg.Done()

	ticker := time.NewTicker(time.Hour) // Cleanup hourly
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			retentionHours := int(p.config.CleanupAge.Hours())
			deleted, err := p.manager.CleanupExpiredMessages(retentionHours)
			if err != nil {
				p.logger.Error("Cleanup failed", "error", err)
			} else if deleted > 0 {
				p.logger.Info("Cleanup completed", "deleted", deleted)
			}
		}
	}
}

// reportMetrics periodically logs processing metrics
func (p *Processor) reportMetrics() {
	defer p.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.logMetrics()
		}
	}
}

// processQueue processes messages in a specific queue
func (p *Processor) processQueue(queueType QueueType) error {
	var (
		messages []Message
		err      error
	)

	if claimer, ok := p.manager.storageBackend.(ClaimingStorageBackend); ok {
		availableWorkers := cap(p.workerSem) - len(p.workerSem)
		if availableWorkers <= 0 {
			return nil
		}
		leaseUntil := time.Now().Add(15 * time.Minute)
		messages, err = claimer.ClaimMessages(queueType, availableWorkers, p.workerID, leaseUntil)
		if err != nil {
			return fmt.Errorf("failed to claim messages: %w", err)
		}
	} else {
		messages, err = p.manager.ListMessages(queueType)
		if err != nil {
			return fmt.Errorf("failed to list messages: %w", err)
		}
	}

	// Process messages with concurrency control
	for _, msg := range messages {
		select {
		case <-p.ctx.Done():
			return nil
		case p.workerSem <- struct{}{}: // Acquire worker
			// Check if we're already processing this message
			p.manager.mutex.Lock()
			if _, exists := p.processingMessages[msg.ID]; exists {
				p.manager.mutex.Unlock()
				<-p.workerSem // Release worker
				continue
			}
			p.processingMessages[msg.ID] = true
			p.manager.mutex.Unlock()

			p.wg.Add(1)
			go p.processMessage(msg)
		}
	}

	return nil
}

// processMessage processes a single message
func (p *Processor) processMessage(msg Message) {
	defer func() {
		<-p.workerSem // Release worker

		// Remove from processing messages
		p.manager.mutex.Lock()
		delete(p.processingMessages, msg.ID)
		p.manager.mutex.Unlock()

		if claimer, ok := p.manager.storageBackend.(ClaimingStorageBackend); ok {
			if err := claimer.ReleaseMessageClaim(msg.ID, p.workerID); err != nil {
				p.logger.Debug("Failed to release message claim", "message_id", msg.ID, "error", err)
			}
		}

		p.wg.Done()
	}()

	// Increment processed count
	p.metricsLock.Lock()
	p.processedCount++
	p.metricsLock.Unlock()

	logger := p.logger.With(
		"message_id", msg.ID,
		"from", msg.From,
		"to", msg.To,
		"retry_count", msg.RetryCount,
	)

	logger.Debug("Processing message")
	startTime := time.Now()
	// A durable DSN intent always wins over another remote delivery attempt.
	if p.resumeDSNHandoff(msg, startTime) {
		return
	}

	// Get message content
	content, err := p.manager.GetMessageContent(msg.ID)
	if err != nil {
		// The listing this message came from is a snapshot, and walking a large
		// queue takes a while. A message delivered and consumed in the meantime
		// is simply gone by the time we reach it.
		//
		// That is a benign race, not a delivery failure. Treating it as one
		// bounces a message that was in fact delivered — moveToFailed emits a
		// DSN to the sender — and records a phantom failure. Only a message
		// still in the queue that has lost its content is a real problem.
		if _, stillQueued := p.manager.GetMessage(msg.ID); stillQueued != nil {
			logger.Debug("Message left the queue before delivery; nothing to do",
				"reason", stillQueued)
			return
		}
		logger.Error("Failed to get message content", "error", err)
		p.moveToFailed(msg, fmt.Sprintf("Failed to read content: %v", err))
		return
	}

	// Attempt delivery
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Minute)
	defer cancel()

	deliveryResult, deliveryErr := p.handler.DeliverMessageWithMetadata(ctx, msg, content)
	deliveryResult, deliveryErr = normalizeDeliveryResult(msg, deliveryResult, deliveryErr)

	if p.handleRecipientOutcomes(msg, deliveryResult, deliveryErr, startTime) {
		return
	}

	if deliveryErr == nil && deliveryResult.Success {
		p.handleDeliverySuccess(msg, deliveryResult)
		return
	}

	p.handleDeliveryFailure(msg, deliveryErr, startTime)
}

// handleRecipientOutcomes persists only retryable recipients before deferral.
func (p *Processor) handleRecipientOutcomes(msg Message, result *DeliveryResult, deliveryErr error, startTime time.Time) bool {
	occurrences := recipientOccurrences(msg)
	var delivered, temporary, permanent []string
	var deliveredR, temporaryR, permanentR []dsnRecipient
	var firstPermanent *RecipientOutcome
	for i, outcome := range result.RecipientOutcomes {
		r := dsnRecipient{Occurrence: occurrences[i], Address: outcome.Recipient, Diagnostic: outcome.Diagnostic}
		switch outcome.Status {
		case RecipientDelivered:
			delivered = append(delivered, outcome.Recipient)
			deliveredR = append(deliveredR, r)
		case RecipientTemporaryFailure:
			temporary = append(temporary, outcome.Recipient)
			temporaryR = append(temporaryR, r)
		case RecipientPermanentFailure:
			// NOTIFY belongs to an occurrence. Prefer its narrow persisted key;
			// address-keyed annotations are only a compatibility fallback.
			if notifyNeverForOccurrence(msg.Annotations, r) {
				deliveredR = append(deliveredR, r) // complete without DSN enqueue
				continue
			}
			permanent = append(permanent, outcome.Recipient)
			permanentR = append(permanentR, r)
			if firstPermanent == nil {
				copy := outcome
				firstPermanent = &copy
			}
		}
	}
	if len(temporary) == 0 && len(permanent) == 0 {
		p.handleDeliverySuccess(msg, result)
		return true
	}
	if len(permanent) > 0 && strings.TrimSpace(msg.From) != "" && strings.TrimSpace(msg.From) != "<>" && p.bounceEngine != nil {
		failed := msg
		failed.To = append([]string(nil), permanent...)
		failed.Annotations = dsnAnnotationsForRecipients(msg.Annotations, permanentR)
		// BounceEngine's current callback accepts only one free-text reason, so it
		// cannot carry enhanced status and route as structured per-recipient DSN
		// fields. Preserve the most useful recipient-specific value: diagnostic,
		// falling back to enhanced status, before the aggregate delivery error.
		reason := "permanent recipient delivery failure"
		if firstPermanent != nil && firstPermanent.Diagnostic != "" {
			reason = firstPermanent.Diagnostic
		} else if firstPermanent != nil && firstPermanent.EnhancedStatusCode != "" {
			reason = firstPermanent.EnhancedStatusCode
		} else if deliveryErr != nil {
			reason = deliveryErr.Error()
		}
		if msg.Annotations == nil {
			msg.Annotations = make(map[string]string)
		}
		h := dsnHandoff{State: "pending", Permanent: permanentR, Temporary: temporaryR, Delivered: deliveredR}
		sum := sha256.Sum256([]byte(msg.ID + "\x00" + occurrenceList(permanentR)))
		h.ID = "dsn-" + hex.EncodeToString(sum[:16])
		encoded, _ := json.Marshal(h)
		msg.Annotations[dsnHandoffAnnotation] = string(encoded)
		if err := p.manager.storageBackend.Update(msg); err != nil {
			p.logger.Error("Failed to persist DSN handoff intent", "message_id", msg.ID, "error", err)
			return true
		}
		bounceResult := p.generateBounce(failed, reason, h.ID)
		if bounceResult == nil || bounceResult.Error != nil {
			p.logger.Warn("DSN bounce handoff failed", "message_id", msg.ID)
			return true
		}
		h.State = "complete"
		encoded, _ = json.Marshal(h)
		msg.Annotations[dsnHandoffAnnotation] = string(encoded)
		if err := p.manager.storageBackend.Update(msg); err != nil {
			p.logger.Error("DSN handed off but marker persistence failed", "message_id", msg.ID, "error", err, "duplicate_risk", true)
			return true
		}
	}
	if len(temporary) == 0 {
		p.observePartial(msg, result, delivered, len(temporary), len(permanent))
		p.finalizeNoTemporary(msg, len(permanent))
		return true
	}
	msg.To = append([]string(nil), temporary...)
	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}
	tempOccurrences := make([]string, len(temporaryR))
	for i := range temporaryR {
		tempOccurrences[i] = temporaryR[i].Occurrence
	}
	encodedOccurrences, _ := json.Marshal(tempOccurrences)
	msg.Annotations[recipientOccurrencesAnnotation] = string(encodedOccurrences)
	delete(msg.Annotations, dsnHandoffAnnotation)
	msg.UpdatedAt = time.Now()
	if err := p.manager.storageBackend.Update(msg); err != nil {
		p.logger.Error("Failed to persist reduced recipient envelope after remote acceptance",
			"message_id", msg.ID, "error", err, "duplicate_risk", true)
		p.recordMetric(func(r MetricsRecorder) error {
			return r.AddRecentError(p.ctx, msg.ID, strings.Join(msg.To, ", "), "duplicate_risk: reduced recipient envelope persistence failed: "+err.Error())
		})
		return true
	}
	if deliveryErr == nil {
		deliveryErr = errors.New("temporary recipient delivery failure")
	}
	p.observePartial(msg, result, delivered, len(temporary), len(permanent))
	p.handleDeliveryFailure(msg, deliveryErr, startTime)
	return true
}

func recipientOccurrences(msg Message) []string {
	var ids []string
	if msg.Annotations != nil {
		_ = json.Unmarshal([]byte(msg.Annotations[recipientOccurrencesAnnotation]), &ids)
	}
	if len(ids) != len(msg.To) {
		ids = make([]string, len(msg.To))
		for i := range ids {
			ids[i] = fmt.Sprintf("%s:%d", msg.ID, i)
		}
	}
	return ids
}

func occurrenceList(recipients []dsnRecipient) string {
	parts := make([]string, len(recipients))
	for i := range recipients {
		parts[i] = recipients[i].Occurrence
	}
	return strings.Join(parts, "\x00")
}

func notifyNeverForOccurrence(annotations map[string]string, recipient dsnRecipient) bool {
	value, ok := annotations["dsn_notify_occurrence:"+recipient.Occurrence]
	if !ok {
		value = annotations["dsn_notify:"+recipient.Address]
	}
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "NEVER") {
			return true
		}
	}
	return false
}

func dsnAnnotationsForRecipients(src map[string]string, recipients []dsnRecipient) map[string]string {
	out := make(map[string]string)
	allowed := make(map[string]bool, len(recipients))
	for _, r := range recipients {
		allowed[r.Address] = true
	}
	for key, value := range src {
		if strings.HasPrefix(key, "dsn_notify:") {
			if allowed[strings.TrimPrefix(key, "dsn_notify:")] {
				out[key] = value
			}
			continue
		}
		if strings.HasPrefix(key, "dsn_orcpt:") {
			if allowed[strings.TrimPrefix(key, "dsn_orcpt:")] {
				out[key] = value
			}
			continue
		}
		out[key] = value
	}
	return out
}

func validateDSNHandoff(msg Message, h dsnHandoff) error {
	if strings.TrimSpace(h.ID) == "" {
		return errors.New("missing handoff ID")
	}
	if h.State != "pending" && h.State != "complete" {
		return fmt.Errorf("unknown handoff state %q", h.State)
	}
	if len(h.Permanent) == 0 {
		return errors.New("empty permanent occurrence set")
	}
	seen := make(map[string]bool)
	expectedIDs := recipientOccurrences(msg)
	expected := make(map[string]string, len(expectedIDs))
	for i, id := range expectedIDs {
		expected[id] = msg.To[i]
	}
	for _, set := range [][]dsnRecipient{h.Permanent, h.Temporary, h.Delivered} {
		for _, r := range set {
			if strings.TrimSpace(r.Occurrence) == "" || strings.TrimSpace(r.Address) == "" || seen[r.Occurrence] {
				return errors.New("malformed or duplicate recipient occurrence")
			}
			if address, ok := expected[r.Occurrence]; !ok || address != r.Address {
				return fmt.Errorf("recipient occurrence %q is not bound to current envelope", r.Occurrence)
			}
			seen[r.Occurrence] = true
		}
	}
	if len(seen) != len(expected) {
		return errors.New("handoff sets do not partition current envelope")
	}
	sum := sha256.Sum256([]byte(msg.ID + "\x00" + occurrenceList(h.Permanent)))
	if h.ID != "dsn-"+hex.EncodeToString(sum[:16]) {
		return errors.New("handoff ID does not match permanent occurrence set")
	}
	return nil
}

func (p *Processor) quarantineInvalidDSNHandoff(msg Message, err error) {
	p.logger.Error("invalid DSN handoff annotation", "event_type", "dsn_handoff_corrupt", "message_id", msg.ID, "error", err)
	if moveErr := p.manager.MoveMessage(msg.ID, Hold, "invalid DSN handoff: "+err.Error()); moveErr != nil {
		p.logger.Error("failed to quarantine invalid DSN handoff", "event_type", "dsn_handoff_quarantine_failed", "message_id", msg.ID, "error", moveErr)
	}
}

func (p *Processor) generateBounce(msg Message, reason, id string) *BounceResult {
	if engine, ok := p.bounceEngine.(idempotentBounceEngine); ok {
		return engine.GenerateBounceIdempotent(p.ctx, msg, reason, id)
	}
	return p.bounceEngine.GenerateBounceIfNeeded(p.ctx, msg, reason)
}

func (p *Processor) resumeDSNHandoff(msg Message, startTime time.Time) bool {
	if msg.Annotations == nil || msg.Annotations[dsnHandoffAnnotation] == "" {
		return false
	}
	var h dsnHandoff
	if err := json.Unmarshal([]byte(msg.Annotations[dsnHandoffAnnotation]), &h); err != nil {
		p.quarantineInvalidDSNHandoff(msg, fmt.Errorf("invalid JSON: %w", err))
		return true
	}
	if err := validateDSNHandoff(msg, h); err != nil {
		p.quarantineInvalidDSNHandoff(msg, err)
		return true
	}
	if h.State == "pending" {
		failed := msg
		failed.To = make([]string, len(h.Permanent))
		failed.Annotations = dsnAnnotationsForRecipients(msg.Annotations, h.Permanent)
		reason := "permanent recipient delivery failure"
		for i := range h.Permanent {
			failed.To[i] = h.Permanent[i].Address
			if i == 0 && h.Permanent[i].Diagnostic != "" {
				reason = h.Permanent[i].Diagnostic
			}
		}
		result := p.generateBounce(failed, reason, h.ID)
		if result == nil || result.Error != nil {
			return true
		}
		h.State = "complete"
		encoded, _ := json.Marshal(h)
		msg.Annotations[dsnHandoffAnnotation] = string(encoded)
		if err := p.manager.storageBackend.Update(msg); err != nil {
			p.logger.Error("DSN resume completion marker update failed", "event_type", "dsn_handoff_resume_update_failed", "message_id", msg.ID, "error", err, "duplicate_risk", true)
			return true
		}
	}
	result := &DeliveryResult{DeliveryTime: time.Now()}
	delivered := make([]string, len(h.Delivered))
	for i := range h.Delivered {
		delivered[i] = h.Delivered[i].Address
	}
	p.observePartial(msg, result, delivered, len(h.Temporary), len(h.Permanent))
	if len(h.Temporary) == 0 {
		p.finalizeNoTemporary(msg, len(h.Permanent))
		return true
	}
	msg.To = make([]string, len(h.Temporary))
	ids := make([]string, len(h.Temporary))
	for i := range h.Temporary {
		msg.To[i], ids[i] = h.Temporary[i].Address, h.Temporary[i].Occurrence
	}
	encoded, _ := json.Marshal(ids)
	msg.Annotations[recipientOccurrencesAnnotation] = string(encoded)
	delete(msg.Annotations, dsnHandoffAnnotation)
	if err := p.manager.storageBackend.Update(msg); err != nil {
		p.logger.Error("DSN resume recipient reduction update failed", "event_type", "dsn_handoff_resume_update_failed", "message_id", msg.ID, "error", err, "duplicate_risk", true)
		return true
	}
	p.handleDeliveryFailure(msg, errors.New("temporary recipient delivery failure"), startTime)
	return true
}

func (p *Processor) observePartial(msg Message, result *DeliveryResult, delivered []string, temporary, permanent int) {
	if len(delivered) == 0 {
		return
	}
	p.msgLogger.LogDelivery(logging.MessageContext{MessageID: msg.ID, QueueID: msg.ID, From: msg.From, To: delivered, Subject: msg.Subject, Size: msg.Size, ReceptionTime: msg.ReceivedAt, ProcessingTime: msg.CreatedAt, DeliveryTime: result.DeliveryTime, DeliveryIP: result.DeliveryIP, DeliveryHost: result.DeliveryHost, RetryCount: msg.RetryCount, DeliveryMethod: "lmtp"})
	if err := p.manager.AddAttempt(msg.ID, "partial", fmt.Sprintf("delivered=%d temporary=%d permanent=%d", len(delivered), temporary, permanent)); err != nil {
		p.logger.Debug("Could not record partial delivery attempt", "message_id", msg.ID, "error", err)
	}
}

func (p *Processor) finalizeNoTemporary(msg Message, permanent int) {
	p.metricsLock.Lock()
	if permanent > 0 {
		p.failedCount++
	} else {
		p.deliveredCount++
	}
	p.metricsLock.Unlock()
	if permanent > 0 {
		p.recordMetric(func(r MetricsRecorder) error { return r.IncrFailed(p.ctx) })
	} else {
		p.recordMetric(func(r MetricsRecorder) error { return r.IncrDelivered(p.ctx) })
	}
	if err := p.manager.DeleteMessage(msg.ID); err != nil {
		p.logger.Error("Failed to finalize recipient delivery outcomes", "message_id", msg.ID, "error", err)
	}
}

// handleDeliverySuccess processes a successful message delivery
func (p *Processor) handleDeliverySuccess(msg Message, result *DeliveryResult) {
	// Log comprehensive delivery success with delivery IP
	p.msgLogger.LogDelivery(logging.MessageContext{
		MessageID:      msg.ID,
		QueueID:        msg.ID,
		From:           msg.From,
		To:             msg.To,
		Subject:        msg.Subject,
		Size:           msg.Size,
		ReceptionTime:  msg.ReceivedAt,
		ProcessingTime: msg.CreatedAt,
		DeliveryTime:   result.DeliveryTime,
		DeliveryIP:     result.DeliveryIP,
		DeliveryHost:   result.DeliveryHost,
		RetryCount:     msg.RetryCount,
		DeliveryMethod: "lmtp",
	})

	p.metricsLock.Lock()
	p.deliveredCount++
	p.metricsLock.Unlock()

	// Record to all metrics recorders (Valkey, Prometheus).
	p.recordMetric(func(r MetricsRecorder) error { return r.IncrDelivered(p.ctx) })

	// Record successful attempt (ignore error if message already deleted)
	if err := p.manager.AddAttempt(msg.ID, "delivered", ""); err != nil {
		p.logger.Debug("Could not record successful attempt (message may already be deleted)", "error", err)
	}

	// Delete successful message
	if err := p.manager.DeleteMessage(msg.ID); err != nil {
		p.logger.Debug("Could not delete delivered message (may already be deleted)", "error", err)
	}
}

// handleDeliveryFailure processes a failed message delivery with retry logic
func (p *Processor) handleDeliveryFailure(msg Message, deliveryErr error, startTime time.Time) {
	logger := p.logger.With("message_id", msg.ID, "from", msg.From, "to", msg.To)

	// Determine if it's a tempfail or permanent failure
	isTemporary := p.isTemporaryFailure(deliveryErr)

	if isTemporary {
		p.msgLogger.LogTempFail(logging.MessageContext{
			MessageID:      msg.ID,
			QueueID:        msg.ID,
			From:           msg.From,
			To:             msg.To,
			Subject:        msg.Subject,
			Size:           msg.Size,
			ReceptionTime:  msg.ReceivedAt,
			ProcessingTime: msg.CreatedAt,
			RetryCount:     msg.RetryCount,
			Error:          deliveryErr.Error(),
			DeliveryMethod: "lmtp",
		})
	} else {
		logger.Error("message_bounced",
			"event_type", "bounce",
			"message_id", msg.ID,
			"from_envelope", msg.From,
			"to_envelope", msg.To,
			"message_subject", msg.Subject,
			"message_size", msg.Size,
			"delivery_method", "lmtp",
			"retry_count", msg.RetryCount,
			"error", deliveryErr.Error(),
			"status", "permanent_failure",
			"processing_time_ms", time.Since(startTime).Milliseconds(),
		)
	}

	p.metricsLock.Lock()
	p.retryCount++
	p.metricsLock.Unlock()

	// Record failed attempt (ignore error if message state changed)
	if err := p.manager.AddAttempt(msg.ID, "failed", deliveryErr.Error()); err != nil {
		logger.Debug("Could not record failed attempt (message may have changed state)", "error", err)
	}

	// Permanent failures go directly to failed queue
	if !isTemporary {
		p.moveToFailed(msg, fmt.Sprintf("Permanent failure: %v", deliveryErr))
		return
	}

	// For temporary failures, check if we should retry or give up
	if msg.RetryCount >= p.config.MaxRetries {
		p.moveToFailed(msg, fmt.Sprintf("Max retries exceeded: %v", deliveryErr))
		return
	}

	// Move to deferred queue for retry (temporary failures only)
	if err := p.manager.MoveMessage(msg.ID, Deferred, deliveryErr.Error()); err != nil {
		logger.Error("Failed to move message to deferred queue", "error", err)
	} else {
		// Record deferred to all metrics recorders (Valkey, Prometheus).
		p.recordMetric(func(r MetricsRecorder) error { return r.IncrDeferred(p.ctx) })
		// Log deferral with timing information
		p.msgLogger.LogDeferral(logging.MessageContext{
			MessageID:      msg.ID,
			QueueID:        msg.ID,
			From:           msg.From,
			To:             msg.To,
			Subject:        msg.Subject,
			Size:           msg.Size,
			ReceptionTime:  msg.ReceivedAt,
			ProcessingTime: msg.CreatedAt,
			NextRetry:      msg.NextRetry,
			RetryCount:     msg.RetryCount,
			Error:          deliveryErr.Error(),
			DeliveryMethod: "lmtp",
		})
	}
}

// processDeferredMessages checks deferred messages and moves ready ones to active
func (p *Processor) processDeferredMessages() error {
	messages, err := p.manager.ListMessages(Deferred)
	if err != nil {
		return fmt.Errorf("failed to list deferred messages: %w", err)
	}

	now := time.Now()
	moved := 0

	for _, msg := range messages {
		if !msg.NextRetry.IsZero() && now.After(msg.NextRetry) {
			if err := p.manager.MoveMessage(msg.ID, Active, "Retry time reached"); err != nil {
				p.logger.Error("Failed to move deferred message to active",
					"message_id", msg.ID,
					"error", err)
			} else {
				moved++
			}
		}
	}

	if moved > 0 {
		p.logger.Info("Moved deferred messages to active queue", "count", moved)
	}

	return nil
}

// moveToFailed moves a message to the failed queue
func (p *Processor) moveToFailed(msg Message, reason string) {
	p.metricsLock.Lock()
	p.failedCount++
	p.metricsLock.Unlock()

	// Generate DSN bounce if the engine is configured and DSN was requested
	if p.bounceEngine != nil {
		bounceResult := p.bounceEngine.GenerateBounceIfNeeded(p.ctx, msg, reason)
		if bounceResult != nil && bounceResult.Error != nil {
			p.logger.Warn("DSN bounce generation failed",
				"original_message_id", msg.ID,
				"error", bounceResult.Error,
			)
		} else if bounceResult != nil && bounceResult.BounceGenerated {
			p.logger.Info("DSN bounce generated for failed message",
				"original_message_id", msg.ID,
				"bounce_id", bounceResult.BounceID,
			)
		}
	}

	// Record to all metrics recorders (Valkey, Prometheus).
	recipient := ""
	if len(msg.To) > 0 {
		recipient = strings.Join(msg.To, ", ")
	}
	p.recordMetric(func(r MetricsRecorder) error { return r.IncrFailed(p.ctx) })
	p.recordMetric(func(r MetricsRecorder) error {
		return r.AddRecentError(p.ctx, msg.ID, recipient, reason)
	})

	// Log comprehensive bounce information
	p.msgLogger.LogBounce(logging.MessageContext{
		MessageID:      msg.ID,
		QueueID:        msg.ID,
		From:           msg.From,
		To:             msg.To,
		Subject:        msg.Subject,
		Size:           msg.Size,
		ReceptionTime:  msg.ReceivedAt,
		ProcessingTime: msg.CreatedAt,
		RetryCount:     msg.RetryCount,
		Error:          reason,
		DeliveryMethod: "lmtp",
	})

	// Check failed queue retention setting
	retentionHours := p.handler.GetFailedQueueRetentionHours()
	if retentionHours == 0 {
		// Immediate deletion - remove message entirely
		if err := p.manager.DeleteMessage(msg.ID); err != nil {
			p.logger.Error("Failed to delete message with permanent failure",
				"message_id", msg.ID,
				"error", err)
		} else {
			p.logger.Info("Message permanently deleted (5xx error)",
				"message_id", msg.ID,
				"reason", reason)
		}
	} else {
		// Move to failed queue with retention
		if err := p.manager.MoveMessage(msg.ID, Failed, reason); err != nil {
			p.logger.Error("Failed to move message to failed queue",
				"message_id", msg.ID,
				"error", err)
		}
	}
}

// isTemporaryFailure determines whether a delivery error should be retried
// (temporary) or bounced (permanent).
//
// Classification order, most authoritative first:
//  1. explicit Temporary() interface,
//  2. typed net.Error / net.OpError / DNS errors — network-layer failures are
//     temporary (a downstream outage must not bounce the whole active queue),
//  3. typed textproto.Error — the real SMTP reply code decides (4xx temporary,
//     5xx permanent), rather than substring-matching digits that may appear in
//     free text,
//  4. substring fallback for errors that carry a code/keyword but no type.
//
// The default is TEMPORARY: an unrecognized error is retried (bounded by the
// max queue lifetime, see calculateNextRetry) instead of silently bouncing
// legitimate mail. Only a clearly-permanent 5xx returns false.
func (p *Processor) isTemporaryFailure(err error) bool {
	if err == nil {
		return false
	}

	// An explicit permanent marker takes precedence over wrapped network errors
	// (notably NXDOMAIN, which net.DNSError also reports as a net.Error).
	var permanent interface{ Permanent() bool }
	if errors.As(err, &permanent) && permanent.Permanent() {
		return false
	}
	// (1) Explicit temporary marker (e.g. TemporaryError).
	var tempErr interface{ Temporary() bool }
	if errors.As(err, &tempErr) && tempErr.Temporary() {
		return true
	}

	// (2) Network-layer failures: dial/timeout/reset/refused/DNS. All temporary.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// (3) SMTP reply code from the server, authoritatively typed.
	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		// 4yz = transient negative completion; 5yz = permanent.
		return protoErr.Code >= 400 && protoErr.Code < 500
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	// (4a) Clearly-permanent 5xx replies stringified into the error chain.
	for _, code := range []string{"550", "551", "552", "553", "554"} {
		if strings.Contains(errStr, code+" ") || strings.HasPrefix(errStr, code) {
			return false
		}
	}

	// (4b) Transient signals in free-text errors, including bare network phrases
	// that don't surface as typed errors once wrapped with fmt.Errorf.
	tempPatterns := []string{
		"450", "451", "452", "421", "454",
		"temporary", "try again", "busy", "throttled", "rate limit",
		"timeout", "timed out", "connection refused", "connection reset",
		"broken pipe", "eof", "no route to host", "network is unreachable",
		"network error", "no such host", "dns", "greylist",
		"insufficient system storage", "mailbox unavailable", "local error",
		"service not available", "i/o timeout",
	}
	for _, pattern := range tempPatterns {
		if strings.Contains(errLower, pattern) {
			return true
		}
	}

	// Default: retry rather than bounce. Bounded by max queue lifetime.
	return true
}

// logMetrics logs current processing metrics
func (p *Processor) logMetrics() {
	p.metricsLock.RLock()
	processed := p.processedCount
	delivered := p.deliveredCount
	failed := p.failedCount
	retries := p.retryCount
	p.metricsLock.RUnlock()

	stats := p.manager.GetStats()

	p.logger.Info("Queue processor metrics",
		"processed_total", processed,
		"delivered_total", delivered,
		"failed_total", failed,
		"retries_total", retries,
		"active_count", stats.ActiveCount,
		"deferred_count", stats.DeferredCount,
		"hold_count", stats.HoldCount,
		"failed_count", stats.FailedCount,
		"total_size_bytes", stats.TotalSize)
}

// GetMetrics returns current processor metrics
func (p *Processor) GetMetrics() ProcessorMetrics {
	p.metricsLock.RLock()
	defer p.metricsLock.RUnlock()

	return ProcessorMetrics{
		ProcessedTotal: p.processedCount,
		DeliveredTotal: p.deliveredCount,
		FailedTotal:    p.failedCount,
		RetryTotal:     p.retryCount,
		QueueStats:     p.manager.GetStats(),
	}
}

// ProcessorMetrics holds processor performance metrics
type ProcessorMetrics struct {
	ProcessedTotal int64      `json:"processed_total"`
	DeliveredTotal int64      `json:"delivered_total"`
	FailedTotal    int64      `json:"failed_total"`
	RetryTotal     int64      `json:"retry_total"`
	QueueStats     QueueStats `json:"queue_stats"`
}
