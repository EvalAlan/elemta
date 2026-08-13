package queue

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Manager handles queue operations and implements the QueueManager interface
type Manager struct {
	queueDir                  string
	failedQueueRetentionHours int
	mutex                     sync.RWMutex
	logger                    *slog.Logger
	queueStats                QueueStats
	statsLock                 sync.RWMutex
	stopCh                    chan struct{}
	storageBackend            StorageBackend
	retrySchedule             []int // per-attempt backoff in seconds; last entry repeats
}

// defaultRetrySchedule backs off from 1 minute to 6 hours and, with the default
// MaxRetries, keeps a message queued for roughly four days before it is bounced —
// matching the common 4–5 day norm for MTAs rather than giving up after hours.
var defaultRetrySchedule = []int{
	60,    // 1m
	300,   // 5m
	900,   // 15m
	3600,  // 1h
	10800, // 3h
	21600, // 6h
	21600, // 6h
	21600, // 6h
	21600, // 6h
	43200, // 12h
	43200, // 12h
	43200, // 12h
	43200, // 12h
}

// SetRetrySchedule overrides the per-attempt backoff schedule (seconds). Called
// by the processor so the operator-configured schedule is actually honored;
// empty input keeps the current schedule.
func (m *Manager) SetRetrySchedule(schedule []int) {
	if len(schedule) == 0 {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.retrySchedule = append([]int(nil), schedule...)
}

// Ensure Manager implements QueueManager interface
var _ QueueManager = (*Manager)(nil)

// QueueType represents the type of queue
type QueueType string

const (
	// Active queue for messages ready to be delivered
	Active QueueType = "active"
	// Deferred queue for messages that will be retried later
	Deferred QueueType = "deferred"
	// Hold queue for messages that are manually held
	Hold QueueType = "hold"
	// Failed queue for messages that failed delivery
	Failed QueueType = "failed"
)

// Priority represents message priority
type Priority int

const (
	// PriorityLow is for low priority messages
	PriorityLow Priority = 1
	// PriorityNormal is for normal priority messages
	PriorityNormal Priority = 2
	// PriorityHigh is for high priority messages
	PriorityHigh Priority = 3
	// PriorityCritical is for critical messages
	PriorityCritical Priority = 4
)

// QueueStats represents statistics about the queue
type QueueStats struct {
	ActiveCount   int       `json:"active_count"`
	DeferredCount int       `json:"deferred_count"`
	HoldCount     int       `json:"hold_count"`
	FailedCount   int       `json:"failed_count"`
	TotalSize     int64     `json:"total_size"`
	LastUpdated   time.Time `json:"last_updated"`
}

// Message represents an email message in the queue
type Message struct {
	ID          string            `json:"id"`
	QueueType   QueueType         `json:"queue_type"`
	FilePath    string            `json:"file_path"`
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Domain      string            `json:"domain,omitempty"`
	Subject     string            `json:"subject"`
	Size        int64             `json:"size"`
	Priority    Priority          `json:"priority"`
	ReceivedAt  time.Time         `json:"received_at"` // When message was received via SMTP
	CreatedAt   time.Time         `json:"created_at"`  // When message was queued
	UpdatedAt   time.Time         `json:"updated_at"`
	NextRetry   time.Time         `json:"next_retry,omitempty"`
	RetryCount  int               `json:"retry_count"`
	LastError   string            `json:"last_error,omitempty"`
	HoldReason  string            `json:"hold_reason,omitempty"`
	Attempts    []Attempt         `json:"attempts,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Attempt represents a delivery attempt
type Attempt struct {
	Time   time.Time `json:"time"`
	Result string    `json:"result"`
	Error  string    `json:"error,omitempty"`
}

// NewManager creates a new queue manager using file storage
func NewManager(queueDir string, failedQueueRetentionHours int) *Manager {
	storage := NewFileStorageBackend(queueDir)
	return NewManagerWithStorage(storage, failedQueueRetentionHours)
}

// NewManagerWithStorage creates a new queue manager with a custom storage backend
func NewManagerWithStorage(storage StorageBackend, failedQueueRetentionHours int) *Manager {
	m := &Manager{
		queueDir:                  extractQueueDir(storage),
		failedQueueRetentionHours: failedQueueRetentionHours,
		logger:                    slog.Default().With("component", "queue"),
		queueStats:                QueueStats{LastUpdated: time.Now()},
		stopCh:                    make(chan struct{}),
		storageBackend:            storage,
	}

	// Ensure directories exist if using file storage
	if fileStorage, ok := storage.(*FileStorageBackend); ok {
		_ = fileStorage.EnsureDirectories() // Best effort, will fail on first operation if needed
	}

	// Start background stats updater
	go m.updateStatsLoop()

	// Start background maintenance loop for backends that support it
	if _, ok := storage.(*IndexedFSStorageBackend); ok {
		go m.maintenanceLoop()
	}

	return m
}

// maintenanceLoop periodically runs index housekeeping (compaction + orphan pruning)
// for indexedfs backends. Runs every 5 minutes; stops via stopCh.
func (m *Manager) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if idx, ok := m.storageBackend.(*IndexedFSStorageBackend); ok {
				if pruned, err := idx.Maintenance(); err != nil {
					m.logger.Warn("index maintenance failed", "error", err)
				} else if pruned > 0 {
					m.logger.Info("index maintenance pruned entries", "count", pruned)
				}
			}
		case <-m.stopCh:
			return
		}
	}
}

// extractQueueDir tries to extract queue directory from storage backend
func extractQueueDir(storage StorageBackend) string {
	if fileStorage, ok := storage.(*FileStorageBackend); ok {
		return fileStorage.queueDir
	}
	if sqliteStorage, ok := storage.(*SQLiteStorageBackend); ok {
		return filepath.Dir(sqliteStorage.dbPath)
	}
	return "" // Unknown storage type
}

// updateStatsLoop periodically refreshes queue statistics.
//
// The frequent tick only refreshes the four queue counts via the storage
// backend's Count() (a directory listing / indexed count — no per-message read
// or JSON unmarshal), which is what makes this cheap at high queue depth. A
// full reconcile (which also recomputes TotalSize by reading every message) runs
// far less often to correct any drift in the incrementally-maintained size.
func (m *Manager) updateStatsLoop() {
	countTicker := time.NewTicker(5 * time.Second)
	defer countTicker.Stop()
	reconcileTicker := time.NewTicker(5 * time.Minute)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-countTicker.C:
			if err := m.refreshCounts(); err != nil {
				m.logger.Error("Failed to refresh queue counts", "error", err)
			}
		case <-reconcileTicker.C:
			if err := m.UpdateStats(); err != nil {
				m.logger.Error("Failed to update queue stats", "error", err)
			}
		case <-m.stopCh:
			m.logger.Debug("Stats updater stopped")
			return
		}
	}
}

// refreshCounts updates only the per-queue counts using the backend's cheap
// Count(), preserving the incrementally-maintained TotalSize. O(1) unmarshals.
func (m *Manager) refreshCounts() error {
	active, err := m.storageBackend.Count(Active)
	if err != nil {
		return fmt.Errorf("failed to count active queue: %w", err)
	}
	deferred, err := m.storageBackend.Count(Deferred)
	if err != nil {
		return fmt.Errorf("failed to count deferred queue: %w", err)
	}
	hold, err := m.storageBackend.Count(Hold)
	if err != nil {
		return fmt.Errorf("failed to count hold queue: %w", err)
	}
	failed, err := m.storageBackend.Count(Failed)
	if err != nil {
		return fmt.Errorf("failed to count failed queue: %w", err)
	}

	m.statsLock.Lock()
	m.queueStats.ActiveCount = active
	m.queueStats.DeferredCount = deferred
	m.queueStats.HoldCount = hold
	m.queueStats.FailedCount = failed
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()
	return nil
}

// UpdateStats updates the queue statistics
func (m *Manager) UpdateStats() error {
	stats := QueueStats{
		LastUpdated: time.Now(),
	}

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	var totalSize int64

	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			return fmt.Errorf("failed to list %s queue: %w", qType, err)
		}

		// Update count based on queue type
		switch qType {
		case Active:
			stats.ActiveCount = len(messages)
		case Deferred:
			stats.DeferredCount = len(messages)
		case Hold:
			stats.HoldCount = len(messages)
		case Failed:
			stats.FailedCount = len(messages)
		}

		// Sum message sizes
		for _, msg := range messages {
			totalSize += msg.Size
		}
	}

	stats.TotalSize = totalSize

	// Update stats atomically
	m.statsLock.Lock()
	m.queueStats = stats
	m.statsLock.Unlock()

	return nil
}

// GetStats returns the current queue statistics
func (m *Manager) GetStats() QueueStats {
	m.statsLock.RLock()
	defer m.statsLock.RUnlock()
	return m.queueStats
}

// ListMessages lists all messages in the specified queue
func (m *Manager) ListMessages(queueType QueueType) ([]Message, error) {
	messages, err := m.storageBackend.List(queueType)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
	}

	// Sort messages by priority (higher priority first) and then by creation time
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Priority != messages[j].Priority {
			return messages[i].Priority > messages[j].Priority
		}
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})

	return messages, nil
}

// GetAllMessages lists all messages across all queue types
func (m *Manager) GetAllMessages() ([]Message, error) {
	var allMessages []Message

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			m.logger.Warn("Failed to list queue", "type", qType, "error", err)
			continue
		}

		allMessages = append(allMessages, messages...)
	}

	return allMessages, nil
}

// GetMessage gets a single message by ID
func (m *Manager) GetMessage(id string) (Message, error) {
	return m.storageBackend.Retrieve(id)
}

// EnqueueMessage adds a new message to the queue
func (m *Manager) EnqueueMessage(from string, to []string, subject string, data []byte, priority Priority, receivedAt time.Time) (string, error) {
	return m.enqueueMessageWithID(generateUniqueID(), from, to, subject, data, priority, receivedAt)
}

// EnqueueMessageWithID atomically creates or verifies a complete caller-named
// queue entry. Conflicting reuse of an ID fails loudly.
func (m *Manager) EnqueueMessageWithID(id, from string, to []string, subject string, data []byte, priority Priority, receivedAt time.Time) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("message ID is required")
	}
	return m.enqueueMessageWithID(id, from, to, subject, data, priority, receivedAt)
}

// EnqueueMessageStream adds a message whose body is held in a seekable reader
// rather than in memory.
//
// Backends that implement AtomicEnqueueStreamStorage never materialise it. The
// rest fall back to reading it in, which is no worse than the caller having
// passed bytes to begin with, so a backend that cannot stream is a performance
// limit rather than an incompatibility.
func (m *Manager) EnqueueMessageStream(from string, to []string, subject string, open ContentOpener, size int64, priority Priority, receivedAt time.Time) (string, error) {
	return m.enqueueMessageStreamWithID(generateUniqueID(), from, to, subject, open, size, priority, receivedAt)
}

func (m *Manager) enqueueMessageStreamWithID(id, from string, to []string, subject string, open ContentOpener, size int64, priority Priority, receivedAt time.Time) (string, error) {
	streamer, ok := m.storageBackend.(AtomicEnqueueStreamStorage)
	if !ok {
		r, err := open()
		if err != nil {
			return "", fmt.Errorf("open message body: %w", err)
		}
		defer func() { _ = r.Close() }()
		data, err := io.ReadAll(r)
		if err != nil {
			return "", fmt.Errorf("read message body: %w", err)
		}
		return m.enqueueMessageWithID(id, from, to, subject, data, priority, receivedAt)
	}

	msg := m.newEnqueueMessage(id, from, to, subject, size, priority, receivedAt)

	created, err := streamer.CreateMessageIfAbsentStream(msg, open)
	if err != nil {
		return "", fmt.Errorf("idempotent enqueue failed: %w", err)
	}
	if !created {
		return id, nil
	}

	m.recordEnqueued(msg)
	return id, nil
}

func (m *Manager) enqueueMessageWithID(id, from string, to []string, subject string, data []byte, priority Priority, receivedAt time.Time) (string, error) {

	msg := m.newEnqueueMessage(id, from, to, subject, int64(len(data)), priority, receivedAt)

	if atomic, ok := m.storageBackend.(AtomicEnqueueStorage); ok {
		created, err := atomic.CreateMessageIfAbsent(msg, data)
		if err != nil {
			return "", fmt.Errorf("idempotent enqueue failed: %w", err)
		}
		if !created {
			return id, nil
		}
	} else {
		// Legacy custom backends retain the historical two-step behavior.
		if err := m.storageBackend.Store(msg); err != nil {
			return "", fmt.Errorf("failed to store message metadata: %w", err)
		}
		if err := m.storageBackend.StoreContent(id, data); err != nil {
			_ = m.storageBackend.Delete(id)
			return "", fmt.Errorf("failed to store message content: %w", err)
		}
	}

	m.recordEnqueued(msg)
	return id, nil
}

// newEnqueueMessage builds the metadata for a newly accepted message. Shared by
// the byte and streaming enqueue paths so they cannot drift.
func (m *Manager) newEnqueueMessage(id, from string, to []string, subject string, size int64, priority Priority, receivedAt time.Time) Message {
	var domain string
	if len(to) > 0 {
		domain = extractDomain(to[0])
	}

	now := time.Now()
	msg := Message{
		ID:          id,
		QueueType:   Active,
		From:        from,
		To:          to,
		Domain:      domain,
		Subject:     subject,
		Size:        size,
		Priority:    priority,
		ReceivedAt:  receivedAt,
		CreatedAt:   now,
		UpdatedAt:   now,
		RetryCount:  0,
		Annotations: make(map[string]string),
		Attempts:    make([]Attempt, 0),
	}
	msg.FilePath = filepath.Join(m.queueDir, "data", id)
	return msg
}

// recordEnqueued updates queue statistics for an accepted message, and reports
// the acceptance.
//
// The report lives here because this is where the two enqueue paths converge.
// It used to live at the top of enqueueMessageWithID, which meant a backend
// that streams — the file backend does — never emitted it at all: "message
// accepted" appeared or vanished depending on which storage was configured,
// and the throughput panel simply went blank. It also fired before the message
// was stored, so it announced an acceptance that could still fail.
func (m *Manager) recordEnqueued(msg Message) {
	m.statsLock.Lock()
	m.queueStats.ActiveCount++
	m.queueStats.LastUpdated = time.Now()
	m.queueStats.TotalSize += msg.Size
	activeCount := m.queueStats.ActiveCount
	m.statsLock.Unlock()

	m.logger.Info("message_accepted",
		"event_type", "message_accepted",
		"message_id", msg.ID,
		"from_envelope", msg.From,
		"to_envelope", msg.To,
		"to_count", len(msg.To),
		"message_size", msg.Size,
		"priority", msg.Priority,
		"queue_type", Active,
		"active_count", activeCount,
		"enqueue_time", time.Now().Format(time.RFC3339),
	)
}

// GetMessageContent retrieves the content data for a message
func (m *Manager) GetMessageContent(id string) ([]byte, error) {
	return m.storageBackend.RetrieveContent(id)
}

// DeleteMessage removes a message from the queue
func (m *Manager) DeleteMessage(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get message first to determine queue type for stats
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}

	content, contentErr := m.storageBackend.RetrieveContent(id)
	if contentErr != nil {
		return fmt.Errorf("failed to read content for idempotency tombstone: %w", contentErr)
	}
	if atomic, ok := m.storageBackend.(AtomicTombstoneDeleteStorage); ok {
		if err := atomic.DeleteMessageWithTombstone(msg, content); err != nil {
			return fmt.Errorf("failed to atomically consume message: %w", err)
		}
	} else {
		// Filesystem backends serialize this ledger write with enqueue's per-ID lock.
		if ledger, ok := m.storageBackend.(IdempotencyLedgerStorage); ok {
			if err := ledger.RecordEnqueueTombstone(msg, content); err != nil {
				return fmt.Errorf("failed to record idempotency tombstone: %w", err)
			}
		}
		if err := m.storageBackend.Delete(id); err != nil {
			return fmt.Errorf("failed to delete message: %w", err)
		}
		if err := m.storageBackend.DeleteContent(id); err != nil {
			m.logger.Warn("Failed to delete message content", "id", id, "error", err)
		}
	}

	// Update stats
	m.statsLock.Lock()
	switch msg.QueueType {
	case Active:
		m.queueStats.ActiveCount--
	case Deferred:
		m.queueStats.DeferredCount--
	case Hold:
		m.queueStats.HoldCount--
	case Failed:
		m.queueStats.FailedCount--
	}
	m.queueStats.TotalSize -= msg.Size
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// MoveMessage moves a message to a different queue
func (m *Manager) MoveMessage(id string, targetQueue QueueType, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get current message
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}

	sourceQueue := msg.QueueType

	// Update message properties
	msg.QueueType = targetQueue
	msg.UpdatedAt = time.Now()

	if reason != "" {
		switch targetQueue {
		case Failed:
			msg.LastError = reason
		case Hold:
			msg.HoldReason = reason
		case Deferred:
			msg.LastError = reason
			msg.RetryCount++ // Increment retry count when moving to deferred queue
			msg.NextRetry = m.calculateNextRetry(msg.RetryCount)
		}
	}

	// Move in storage
	if err := m.storageBackend.Move(id, sourceQueue, targetQueue); err != nil {
		return fmt.Errorf("failed to move message: %w", err)
	}

	// Update message metadata
	if err := m.storageBackend.Update(msg); err != nil {
		return fmt.Errorf("failed to update message metadata: %w", err)
	}

	// Update stats
	m.statsLock.Lock()
	switch sourceQueue {
	case Active:
		m.queueStats.ActiveCount--
	case Deferred:
		m.queueStats.DeferredCount--
	case Hold:
		m.queueStats.HoldCount--
	case Failed:
		m.queueStats.FailedCount--
	}

	switch targetQueue {
	case Active:
		m.queueStats.ActiveCount++
	case Deferred:
		m.queueStats.DeferredCount++
	case Hold:
		m.queueStats.HoldCount++
	case Failed:
		m.queueStats.FailedCount++
	}
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// AddAttempt adds a delivery attempt record to a message
func (m *Manager) AddAttempt(id string, result string, errorMsg string) error {
	// Get the message
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return err
	}

	// Add the attempt
	attempt := Attempt{
		Time:   time.Now(),
		Result: result,
		Error:  errorMsg,
	}

	msg.Attempts = append(msg.Attempts, attempt)
	msg.UpdatedAt = time.Now()

	if errorMsg != "" {
		msg.LastError = errorMsg
	}

	// Update the message
	return m.storageBackend.Update(msg)
}

// FlushQueue removes all messages from the specified queue
func (m *Manager) FlushQueue(queueType QueueType) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get messages to capture count before deletion
	messages, err := m.storageBackend.List(queueType)
	if err != nil {
		return fmt.Errorf("failed to list messages: %w", err)
	}

	// Delete all messages and their content
	for _, msg := range messages {
		if err := m.storageBackend.Delete(msg.ID); err != nil {
			m.logger.Warn("Failed to delete message", "id", msg.ID, "error", err)
		}
		if err := m.storageBackend.DeleteContent(msg.ID); err != nil {
			m.logger.Warn("Failed to delete message content", "id", msg.ID, "error", err)
		}
	}

	// Update stats
	m.statsLock.Lock()
	switch queueType {
	case Active:
		m.queueStats.ActiveCount = 0
	case Deferred:
		m.queueStats.DeferredCount = 0
	case Hold:
		m.queueStats.HoldCount = 0
	case Failed:
		m.queueStats.FailedCount = 0
	}
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// FlushAllQueues removes all messages from all queues
func (m *Manager) FlushAllQueues() error {
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		if err := m.FlushQueue(qType); err != nil {
			m.logger.Warn("Failed to flush queue", "type", qType, "error", err)
		}
	}

	// Reset all stats
	m.statsLock.Lock()
	m.queueStats = QueueStats{
		LastUpdated: time.Now(),
	}
	m.statsLock.Unlock()

	return nil
}

// CleanupExpiredMessages removes messages that are older than the retention period
func (m *Manager) CleanupExpiredMessages(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention period must be positive")
	}

	m.logger.Info("Starting queue cleanup", "retention_hours", retentionHours)

	deletedCount, err := m.storageBackend.Cleanup(retentionHours)
	if err != nil {
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	m.logger.Info("Queue cleanup completed", "deleted", deletedCount)
	return deletedCount, nil
}

// SetAnnotation adds or updates an annotation for a message
func (m *Manager) SetAnnotation(id string, key, value string) error {
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return err
	}

	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}

	msg.Annotations[key] = value
	msg.UpdatedAt = time.Now()

	return m.storageBackend.Update(msg)
}

// Helper functions

// generateUniqueID creates a unique message ID.
//
// Format: <unix-nanos>-<uuidv4>. The timestamp prefix keeps on-disk files
// roughly time-ordered for operators, while the 122-bit random UUID suffix
// guarantees collision-freedom under concurrent enqueue (a purely time-derived
// ID collides on coarse-clock hosts and silently overwrites a queued message)
// and makes IDs unguessable, closing the /api/queue/message/{id} enumeration
// vector.
func generateUniqueID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), uuid.NewString())
}

// extractDomain returns the domain portion of an email address, or empty string if invalid
func extractDomain(addr string) string {
	if addr == "" {
		return ""
	}
	at := strings.LastIndex(addr, "@")
	if at == -1 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// calculateNextRetry determines when to retry a message based on retry count,
// using the configured (or default) backoff schedule with ±10% jitter. Attempts
// beyond the schedule length repeat the final interval.
func (m *Manager) calculateNextRetry(retryCount int) time.Time {
	if retryCount <= 0 {
		retryCount = 1
	}

	schedule := m.retrySchedule
	if len(schedule) == 0 {
		schedule = defaultRetrySchedule
	}

	idx := retryCount - 1
	if idx >= len(schedule) {
		idx = len(schedule) - 1
	}
	delaySeconds := schedule[idx]

	// Add some randomness (±10%) to avoid retry stampedes against a shared destination.
	jitter := float64(delaySeconds) * 0.1
	// #nosec G404 -- jitter for retry delay does not require cryptographic randomness
	delaySeconds = delaySeconds + int(jitter*(2.0*rand.Float64()-1.0))

	return time.Now().Add(time.Duration(delaySeconds) * time.Second)
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (m *Manager) GetFailedQueueRetentionHours() int {
	return m.failedQueueRetentionHours
}

// Stop stops the queue manager and cleans up resources
func (m *Manager) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.stopCh != nil {
		close(m.stopCh)
	}
}
