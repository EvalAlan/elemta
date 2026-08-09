package queue

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// QueueMessageAge identifies the oldest message contributing to an age metric.
type QueueMessageAge struct {
	ID         string    `json:"id"`
	QueueType  QueueType `json:"queue_type"`
	Domain     string    `json:"domain,omitempty"`
	AgeSeconds int64     `json:"age_seconds"`
	CreatedAt  time.Time `json:"created_at"`
	ReceivedAt time.Time `json:"received_at,omitempty"`
	NextRetry  time.Time `json:"next_retry,omitempty"`
	RetryCount int       `json:"retry_count"`
}

// QueueBreakdown summarizes one queue bucket.
type QueueBreakdown struct {
	Count             int              `json:"count"`
	TotalSize         int64            `json:"total_size"`
	ReadyDeferred     int              `json:"ready_deferred,omitempty"`
	RetryingMessages  int              `json:"retrying_messages,omitempty"`
	OldestMessage     *QueueMessageAge `json:"oldest_message,omitempty"`
	OldestAgeSeconds  int64            `json:"oldest_age_seconds"`
	HighestRetryCount int              `json:"highest_retry_count"`
}

// QueueDomainStats summarizes queue pressure by recipient domain.
type QueueDomainStats struct {
	Domain            string `json:"domain"`
	Count             int    `json:"count"`
	ActiveCount       int    `json:"active_count"`
	DeferredCount     int    `json:"deferred_count"`
	HoldCount         int    `json:"hold_count"`
	FailedCount       int    `json:"failed_count"`
	TotalSize         int64  `json:"total_size"`
	OldestAgeSeconds  int64  `json:"oldest_age_seconds"`
	HighestRetryCount int    `json:"highest_retry_count"`
}

// QueueClaimInfo reports an active backend claim, when supported by the storage backend.
type QueueClaimInfo struct {
	MessageID        string    `json:"message_id"`
	QueueType        QueueType `json:"queue_type"`
	ClaimedBy        string    `json:"claimed_by"`
	ClaimUntil       time.Time `json:"claim_until"`
	Expired          bool      `json:"expired"`
	SecondsRemaining int64     `json:"seconds_remaining"`
}

// QueueObservabilitySnapshot is a compact operational view of queue health.
type QueueObservabilitySnapshot struct {
	Backend         string                    `json:"backend"`
	GeneratedAt     time.Time                 `json:"generated_at"`
	Totals          QueueStats                `json:"totals"`
	TotalMessages   int                       `json:"total_messages"`
	ByQueue         map[string]QueueBreakdown `json:"by_queue"`
	ByDomain        []QueueDomainStats        `json:"by_domain"`
	OldestMessage   *QueueMessageAge          `json:"oldest_message,omitempty"`
	Claims          []QueueClaimInfo          `json:"claims,omitempty"`
	ClaimsSupported bool                      `json:"claims_supported"`
	Storage         StorageInfo               `json:"storage"`
}

type claimInfoProvider interface {
	ListClaims(now time.Time) ([]QueueClaimInfo, error)
}

type claimReleaseBackend interface {
	ReleaseMessageClaim(id, workerID string) error
}

// GetObservabilitySnapshot builds a backend-agnostic queue health snapshot.
func (m *Manager) GetObservabilitySnapshot() (QueueObservabilitySnapshot, error) {
	now := time.Now().UTC()

	// This used to call UpdateStats first, which lists and decodes every message
	// in all four queues — and then the loop below lists them all again. The
	// snapshot is polled by every open dashboard, so that was two full passes
	// over the whole spool per poll. Totals are now derived from the single pass
	// below, and the cached stats refreshed from the same numbers.
	storageInfo, err := m.GetStorageInfo()
	if err != nil {
		return QueueObservabilitySnapshot{}, err
	}

	snapshot := QueueObservabilitySnapshot{
		Backend:     m.BackendType(),
		GeneratedAt: now,
		ByQueue:     make(map[string]QueueBreakdown),
		Storage:     storageInfo,
		ByDomain:    []QueueDomainStats{},
	}
	totals := QueueStats{LastUpdated: now}

	domainStats := make(map[string]*QueueDomainStats)
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}

	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			return snapshot, fmt.Errorf("failed to list %s queue: %w", qType, err)
		}

		breakdown := QueueBreakdown{Count: len(messages)}
		for _, msg := range messages {
			snapshot.TotalMessages++
			breakdown.TotalSize += msg.Size
			if msg.RetryCount > 0 {
				breakdown.RetryingMessages++
			}
			if msg.RetryCount > breakdown.HighestRetryCount {
				breakdown.HighestRetryCount = msg.RetryCount
			}
			if qType == Deferred && (msg.NextRetry.IsZero() || !msg.NextRetry.After(now)) {
				breakdown.ReadyDeferred++
			}

			age := messageAge(msg, now)
			if breakdown.OldestMessage == nil || age.AgeSeconds > breakdown.OldestAgeSeconds {
				breakdown.OldestMessage = age
				breakdown.OldestAgeSeconds = age.AgeSeconds
			}
			if snapshot.OldestMessage == nil || age.AgeSeconds > snapshot.OldestMessage.AgeSeconds {
				snapshot.OldestMessage = age
			}

			domain := normalizeQueueDomain(msg)
			dStat := domainStats[domain]
			if dStat == nil {
				dStat = &QueueDomainStats{Domain: domain}
				domainStats[domain] = dStat
			}
			dStat.Count++
			dStat.TotalSize += msg.Size
			if age.AgeSeconds > dStat.OldestAgeSeconds {
				dStat.OldestAgeSeconds = age.AgeSeconds
			}
			if msg.RetryCount > dStat.HighestRetryCount {
				dStat.HighestRetryCount = msg.RetryCount
			}
			switch qType {
			case Active:
				dStat.ActiveCount++
			case Deferred:
				dStat.DeferredCount++
			case Hold:
				dStat.HoldCount++
			case Failed:
				dStat.FailedCount++
			}
		}

		snapshot.ByQueue[string(qType)] = breakdown

		totals.TotalSize += breakdown.TotalSize
		switch qType {
		case Active:
			totals.ActiveCount = breakdown.Count
		case Deferred:
			totals.DeferredCount = breakdown.Count
		case Hold:
			totals.HoldCount = breakdown.Count
		case Failed:
			totals.FailedCount = breakdown.Count
		}
	}

	// Publish the freshly computed totals both into the snapshot and the
	// manager's cache, so this poll doubles as the stats refresh UpdateStats
	// used to provide.
	snapshot.Totals = totals
	m.statsLock.Lock()
	m.queueStats = totals
	m.statsLock.Unlock()

	for _, stat := range domainStats {
		snapshot.ByDomain = append(snapshot.ByDomain, *stat)
	}
	sort.Slice(snapshot.ByDomain, func(i, j int) bool {
		if snapshot.ByDomain[i].Count != snapshot.ByDomain[j].Count {
			return snapshot.ByDomain[i].Count > snapshot.ByDomain[j].Count
		}
		return snapshot.ByDomain[i].Domain < snapshot.ByDomain[j].Domain
	})

	if provider, ok := m.storageBackend.(claimInfoProvider); ok {
		snapshot.ClaimsSupported = true
		claims, err := provider.ListClaims(now)
		if err != nil {
			return snapshot, fmt.Errorf("failed to list message claims: %w", err)
		}
		snapshot.Claims = claims
	}

	return snapshot, nil
}

// RequeueMessage resets a queued message for another delivery attempt.
func (m *Manager) RequeueMessage(id, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}

	sourceQueue := msg.QueueType
	msg.QueueType = Active
	msg.RetryCount = 0
	msg.LastError = ""
	msg.HoldReason = ""
	msg.NextRetry = time.Time{}
	msg.UpdatedAt = time.Now().UTC()
	setAdminAnnotation(&msg, "requeued", reason)

	if sourceQueue != Active {
		if err := m.storageBackend.Move(id, sourceQueue, Active); err != nil {
			return fmt.Errorf("failed to move message to active queue: %w", err)
		}
	}
	if releaser, ok := m.storageBackend.(claimReleaseBackend); ok {
		if err := releaser.ReleaseMessageClaim(id, ""); err != nil {
			return fmt.Errorf("failed to release message claim: %w", err)
		}
	}
	if err := m.storageBackend.Update(msg); err != nil {
		return fmt.Errorf("failed to update message metadata: %w", err)
	}
	return m.UpdateStats()
}

// HoldMessage moves a message to the hold queue with an operator reason.
func (m *Manager) HoldMessage(id, reason string) error {
	if strings.TrimSpace(reason) == "" {
		reason = "held by operator"
	}
	return m.MoveMessage(id, Hold, reason)
}

// ReleaseMessageClaim clears a backend claim for a message when supported.
func (m *Manager) ReleaseMessageClaim(id, workerID string) error {
	releaser, ok := m.storageBackend.(claimReleaseBackend)
	if !ok {
		return fmt.Errorf("queue backend %s does not support message claims", m.BackendType())
	}
	return releaser.ReleaseMessageClaim(id, workerID)
}

func messageAge(msg Message, now time.Time) *QueueMessageAge {
	createdAt := msg.CreatedAt
	if createdAt.IsZero() {
		createdAt = msg.ReceivedAt
	}
	if createdAt.IsZero() {
		createdAt = msg.UpdatedAt
	}
	age := int64(0)
	if !createdAt.IsZero() {
		age = int64(now.Sub(createdAt.UTC()).Seconds())
		if age < 0 {
			age = 0
		}
	}
	return &QueueMessageAge{
		ID:         msg.ID,
		QueueType:  msg.QueueType,
		Domain:     normalizeQueueDomain(msg),
		AgeSeconds: age,
		CreatedAt:  msg.CreatedAt,
		ReceivedAt: msg.ReceivedAt,
		NextRetry:  msg.NextRetry,
		RetryCount: msg.RetryCount,
	}
}

func normalizeQueueDomain(msg Message) string {
	domain := strings.TrimSpace(strings.ToLower(msg.Domain))
	if domain != "" {
		return domain
	}
	for _, recipient := range msg.To {
		if d := extractDomain(recipient); d != "" {
			return d
		}
	}
	return "unknown"
}

// RequeueQueue requeues every message in a queue for immediate delivery and
// returns how many were moved. It exists so the dashboard's "retry" actions
// can trigger redelivery instead of deleting the queue — the flush endpoint
// they used to call removed messages outright.
//
// Requeuing the active queue is a no-op that still resets retry state, which
// is the sensible reading of "process the active queue now".
func (m *Manager) RequeueQueue(queueType QueueType, reason string) (int, error) {
	messages, err := m.ListMessages(queueType)
	if err != nil {
		return 0, fmt.Errorf("failed to list %s queue: %w", queueType, err)
	}

	requeued := 0
	var firstErr error
	for i := range messages {
		if err := m.RequeueMessage(messages[i].ID, reason); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.logger.Warn("Failed to requeue message during bulk retry",
				"id", messages[i].ID, "queue", queueType, "error", err)
			continue
		}
		requeued++
	}
	return requeued, firstErr
}

func setAdminAnnotation(msg *Message, action, reason string) {
	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}
	msg.Annotations["admin_action"] = action
	msg.Annotations["admin_action_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if strings.TrimSpace(reason) != "" {
		msg.Annotations["admin_reason"] = reason
	}
}
