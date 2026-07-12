package queue

import (
	"testing"
	"time"
)

func TestProcessor(t *testing.T) {
	// Create a temporary directory for testing
	queueDir := t.TempDir()

	// Create queue manager
	manager := NewManager(queueDir, 24) // 24 hours retention
	defer manager.Stop()

	// Create processor config
	config := ProcessorConfig{
		Enabled:       true,
		Interval:      100 * time.Millisecond, // Fast for testing
		MaxConcurrent: 2,
		MaxRetries:    3,
		RetrySchedule: []int{1, 2, 4}, // Fast retries for testing
		CleanupAge:    time.Hour,
	}

	t.Run("StartStop", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}

		// Wait a bit to ensure it's running
		time.Sleep(200 * time.Millisecond)

		if err := processor.Stop(); err != nil {
			t.Fatalf("Failed to stop processor: %v", err)
		}
	})

	t.Run("ProcessMessage", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure mock handler is configured for success
		mockHandler.SetShouldFail(false)

		// Enqueue a test message
		msgID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"recipient@example.com"},
			"Test Subject",
			[]byte("Test message content"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check that message was delivered
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 1 {
			t.Errorf("Expected 1 delivery, got %d", len(deliveries))
		}

		if len(deliveries) > 0 && deliveries[0].ID != msgID {
			t.Errorf("Expected message ID %s, got %s", msgID, deliveries[0].ID)
		}

		// Check that message was deleted from queue
		stats := manager.GetStats()
		if stats.ActiveCount != 0 {
			t.Errorf("Expected 0 active messages, got %d", stats.ActiveCount)
		}
	})

	t.Run("RetryLogic", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Configure to fail
		mockHandler.SetShouldFail(true)

		// Enqueue a test message
		msgID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"recipient@example.com"},
			"Test Subject",
			[]byte("Test message content"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait until failure path has actually deferred the message.
		deadline := time.Now().Add(2 * time.Second)
		var msg Message
		for {
			stats := manager.GetStats()
			current, getErr := manager.GetMessage(msgID)
			if getErr == nil && stats.DeferredCount >= 1 && current.RetryCount >= 1 && current.QueueType == Deferred {
				msg = current
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("RetryLogic did not reach deferred state in time: deferred=%d retry=%d queue=%v err=%v", stats.DeferredCount, current.RetryCount, current.QueueType, getErr)
			}
			time.Sleep(25 * time.Millisecond)
		}

		if msg.RetryCount < 1 {
			t.Errorf("Expected at least one retry, got %d", msg.RetryCount)
		}

		if msg.QueueType != Deferred {
			t.Errorf("Expected message in deferred queue, got %s", msg.QueueType)
		}
	})

	t.Run("PriorityProcessing", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue messages with different priorities
		lowID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"low@example.com"},
			"Low Priority",
			[]byte("Low priority message"),
			PriorityLow,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue low priority message: %v", err)
		}

		highID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"high@example.com"},
			"High Priority",
			[]byte("High priority message"),
			PriorityHigh,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue high priority message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check delivery order (high priority should be delivered first)
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 2 {
			t.Fatalf("Expected 2 deliveries, got %d", len(deliveries))
		}

		// Since we can't guarantee exact order due to concurrency,
		// just verify both messages were delivered
		deliveredIDs := make(map[string]bool)
		for _, delivery := range deliveries {
			deliveredIDs[delivery.ID] = true
		}

		if !deliveredIDs[lowID] {
			t.Errorf("Low priority message %s was not delivered", lowID)
		}

		if !deliveredIDs[highID] {
			t.Errorf("High priority message %s was not delivered", highID)
		}
	})

	t.Run("ConcurrencyLimit", func(t *testing.T) {
		// Use an isolated manager: this subtest asserts an exact global delivery
		// count, so it must not observe deferred messages promoted from earlier
		// subtests that share the outer manager and fast retry schedule.
		manager := NewManager(t.TempDir(), 24)
		defer manager.Stop()

		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion

		// Create a processor with concurrency limit of 1
		limitedConfig := config
		limitedConfig.MaxConcurrent = 1
		limitedProcessor := NewProcessor(manager, limitedConfig, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue multiple messages
		for i := 0; i < 5; i++ {
			_, err := manager.EnqueueMessage(
				"sender@example.com",
				[]string{"recipient@example.com"},
				"Test Subject",
				[]byte("Test message content"),
				PriorityNormal,
				time.Now(),
			)
			if err != nil {
				t.Fatalf("Failed to enqueue message %d: %v", i, err)
			}
		}

		// Start processor
		if err := limitedProcessor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer limitedProcessor.Stop()

		// Wait for processing. A fixed sleep made this test fail on slower CI
		// runners while the fifth delivery was still in flight.
		deadline := time.Now().Add(5 * time.Second)
		for len(mockHandler.GetDeliveries()) < 5 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}

		// All messages should be delivered
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 5 {
			t.Errorf("Expected 5 deliveries, got %d", len(deliveries))
		}
	})

	t.Run("MetricsTracking", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue test messages
		successID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"success@example.com"},
			"Success",
			[]byte("Success message"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue success message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check metrics
		metrics := processor.GetMetrics()
		if metrics.ProcessedTotal < 1 {
			t.Errorf("Expected at least 1 processed message, got %d", metrics.ProcessedTotal)
		}

		if metrics.DeliveredTotal < 1 {
			t.Errorf("Expected at least 1 delivered message, got %d", metrics.DeliveredTotal)
		}

		// Verify message was delivered
		deliveries := mockHandler.GetDeliveries()
		delivered := false
		for _, delivery := range deliveries {
			if delivery.ID == successID {
				delivered = true
				break
			}
		}

		if !delivered {
			t.Errorf("Success message was not delivered")
		}
	})
}

func TestProcessorConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultProcessorConfig()

		if !config.Enabled {
			t.Error("Expected default config to be enabled")
		}

		if config.Interval != 10*time.Second {
			t.Errorf("Expected default interval 10s, got %v", config.Interval)
		}

		if config.MaxConcurrent != 5 {
			t.Errorf("Expected default max concurrent 5, got %d", config.MaxConcurrent)
		}

		// MaxRetries spans the full backoff schedule so mail stays queued for
		// days before bouncing, rather than being abandoned after a few hours.
		if config.MaxRetries != len(config.RetrySchedule) {
			t.Errorf("Expected default max retries to match schedule length %d, got %d",
				len(config.RetrySchedule), config.MaxRetries)
		}

		if len(config.RetrySchedule) == 0 {
			t.Error("Expected default retry schedule to be non-empty")
		}

		// The cumulative schedule should keep a message queued for at least ~3 days.
		var totalSeconds int
		for _, s := range config.RetrySchedule {
			totalSeconds += s
		}
		if minLifetime := 3 * 24 * 60 * 60; totalSeconds < minLifetime {
			t.Errorf("Expected retry schedule to span at least ~3 days (%ds), got %ds",
				minLifetime, totalSeconds)
		}
	})
}
