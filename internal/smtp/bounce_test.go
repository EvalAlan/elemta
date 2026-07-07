// internal/smtp/bounce_test.go
package smtp

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBounceEngine creates a bounce engine with a real file-backed queue for testing
func newTestBounceEngine(t *testing.T) (*BounceEngine, *queue.Manager) {
	t.Helper()
	queueDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := queue.NewManager(queueDir, 0)
	engine := NewBounceEngine(mgr, "test.example.com", logger)
	return engine, mgr
}

func TestBounceEngine_NoDSNNoBounce(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message without DSN annotations - no bounce should be generated
	msg := queue.Message{
		ID:        "test-no-dsn",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Subject:   "Test message",
		CreatedAt: time.Now(),
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	assert.False(t, result.BounceGenerated, "No bounce should be generated without DSN")
	assert.NoError(t, result.Error)
}

func TestBounceEngine_NEVERNoBounce(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with NOTIFY=NEVER - no bounce should be generated
	msg := queue.Message{
		ID:        "test-never",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Subject:   "Test message",
		CreatedAt: time.Now(),
		Annotations: map[string]string{
			"dsn_return":                       "FULL",
			"dsn_notify:recipient@example.com": "NEVER",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	assert.False(t, result.BounceGenerated, "No bounce should be generated with NOTIFY=NEVER")
	assert.NoError(t, result.Error)
}

func TestBounceEngine_GeneratesBounce(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with DSN FULL - bounce should be generated
	msg := queue.Message{
		ID:         "test-bounce-full",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Test message",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now().Add(-5 * time.Minute),
		Annotations: map[string]string{
			"dsn_return":                       "FULL",
			"dsn_notify:recipient@example.com": "FAILURE",
			"dsn_orcpt:recipient@example.com":  "rfc822;recipient@example.com",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "550 5.1.1 User unknown")
	assert.True(t, result.BounceGenerated, "Bounce should be generated with DSN FULL")
	assert.NoError(t, result.Error)
	assert.NotEmpty(t, result.BounceID)
}

func TestBounceEngine_GeneratesBounceHDRS(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with DSN HDRS - bounce should be generated
	msg := queue.Message{
		ID:         "test-bounce-hdrs",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Test message",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now().Add(-5 * time.Minute),
		Annotations: map[string]string{
			"dsn_return":                       "HDRS",
			"dsn_notify:recipient@example.com": "FAILURE",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "Connection refused")
	assert.True(t, result.BounceGenerated, "Bounce should be generated with DSN HDRS")
	assert.NoError(t, result.Error)
	assert.NotEmpty(t, result.BounceID)
}

func TestBounceEngine_MultipleRecipients(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	msg := queue.Message{
		ID:         "test-multi-rcpt",
		From:       "sender@example.com",
		To:         []string{"rcpt1@example.com", "rcpt2@example.com"},
		Subject:    "Test message",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now().Add(-5 * time.Minute),
		Annotations: map[string]string{
			"dsn_return":                   "FULL",
			"dsn_notify:rcpt1@example.com": "FAILURE",
			"dsn_notify:rcpt2@example.com": "FAILURE,SUCCESS",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "550 Mailbox unavailable")
	assert.True(t, result.BounceGenerated)
	assert.NotEmpty(t, result.BounceID)
}

func TestBounceEngine_NEVERWithOtherNotify(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// If one recipient has NEVER and another has FAILURE, no bounce should be sent
	// because NEVER takes precedence for that recipient
	msg := queue.Message{
		ID:        "test-mixed-notify",
		From:      "sender@example.com",
		To:        []string{"rcpt1@example.com", "rcpt2@example.com"},
		Subject:   "Test message",
		CreatedAt: time.Now(),
		Annotations: map[string]string{
			"dsn_return":                   "FULL",
			"dsn_notify:rcpt1@example.com": "FAILURE",
			"dsn_notify:rcpt2@example.com": "NEVER",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	// When any recipient has NEVER, we skip the bounce entirely
	assert.False(t, result.BounceGenerated)
}

func TestMapFailureToDSNStatus(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	tests := []struct {
		reason   string
		expected BounceDSNStatus
	}{
		{"connection refused", DSNStatusConnectionRefused},
		{"Connection reset by peer", DSNStatusConnectionRefused},
		{"network unreachable", DSNStatusConnectionRefused},
		{"mailbox unavailable", DSNStatusMailboxUnavailable},
		{"user unknown", DSNStatusBadDestinationAddress},
		{"no such user here", DSNStatusBadDestinationAddress},
		{"recipient address rejected", DSNStatusBadDestinationAddress},
		{"mailbox full", DSNStatusMailboxUnavailable},
		{"quota exceeded", DSNStatusMailboxUnavailable},
		{"host not found", DSNStatusSystemNotAccepting},
		{"name resolution failed", DSNStatusSystemNotAccepting},
		{"dns lookup failed", DSNStatusSystemNotAccepting},
		{"no mx records", DSNStatusSystemNotAccepting},
		{"550 5.1.1 not found", DSNStatusPermanentFailure},
		{"551 user not local", DSNStatusPermanentFailure},
		{"552 message size exceeded", DSNStatusPermanentFailure},
		{"553 mailbox name not allowed", DSNStatusPermanentFailure},
		{"554 transaction failed", DSNStatusPermanentFailure},
		{"some random error", DSNStatusGeneralFailure},
		{"", DSNStatusGeneralFailure},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			result := engine.mapFailureToDSNStatus(tt.reason)
			assert.Equal(t, tt.expected, result, "reason: %q", tt.reason)
		})
	}
}

func TestSanitizeDiagnosticCode(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal error",
			input:    "550 5.1.1 User unknown",
			expected: "550 5.1.1 User unknown",
		},
		{
			name:     "with newlines",
			input:    "error\nwith\r\nnewlines",
			expected: "error with  newlines",
		},
		{
			name:     "with null bytes",
			input:    "error\x00with\x00nulls",
			expected: "errorwithnulls",
		},
		{
			name:     "very long error gets truncated",
			input:    strings.Repeat("x", 2000),
			expected: strings.Repeat("x", 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.sanitizeDiagnosticCode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildDSNBounceStructure(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	msg := queue.Message{
		ID:         "test-123",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Original subject",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now().Add(-5 * time.Minute),
		Annotations: map[string]string{
			"dsn_return":                       "FULL",
			"dsn_notify:recipient@example.com": "FAILURE,SUCCESS",
			"dsn_orcpt:recipient@example.com":  "rfc822;recipient@example.com",
			"dsn_envid":                        "test-env-123",
		},
	}

	content, err := engine.buildDSNBounce(msg, "550 5.1.1 User unknown")
	require.NoError(t, err)

	contentStr := string(content)

	// Check required DSN structure elements
	assert.Contains(t, contentStr, "multipart/report", "Should have multipart/report content type")
	assert.Contains(t, contentStr, "report-type=delivery-status", "Should specify delivery-status report type")
	assert.Contains(t, contentStr, "message/delivery-status", "Should have delivery-status part")
	assert.Contains(t, contentStr, "text/plain", "Should have human-readable text part")

	// Check DSN per-recipient fields (ORCPT preserves the original format "rfc822;addr")
	assert.Contains(t, contentStr, "Final-Recipient: rfc822;recipient@example.com")
	assert.Contains(t, contentStr, "Action: failed")
	assert.Contains(t, contentStr, "Status: 5.1.1")
	assert.Contains(t, contentStr, "Diagnostic-Code: smtp; 550 5.1.1 User unknown")
	assert.Contains(t, contentStr, "Reporting-MTA: dns; test.example.com")

	// Check human-readable part
	assert.Contains(t, contentStr, "Delivery Status Notification (Failure)")
	assert.Contains(t, contentStr, "sender@example.com")
	assert.Contains(t, contentStr, "recipient@example.com")
	assert.Contains(t, contentStr, "Original subject")

	// Check headers
	assert.Contains(t, contentStr, "From: <postmaster@test.example.com>")
	assert.Contains(t, contentStr, "To: <sender@example.com>")
	assert.Contains(t, contentStr, "Subject: Delivery Status Notification (Failure)")
}

func TestBuildDSNBounceNoOriginalRecipient(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	// Message without ORCPT - should use the final recipient address
	msg := queue.Message{
		ID:         "test-456",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Test",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now(),
		Annotations: map[string]string{
			"dsn_return":                       "FULL",
			"dsn_notify:recipient@example.com": "FAILURE",
		},
	}

	content, err := engine.buildDSNBounce(msg, "connection refused")
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "Final-Recipient: rfc822; recipient@example.com")
}

func TestBuildDSNBounceHDRSNoMessagePart(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	// HDRS mode should not include the original message content
	msg := queue.Message{
		ID:         "test-hdrs",
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Test",
		CreatedAt:  time.Now(),
		ReceivedAt: time.Now(),
		Annotations: map[string]string{
			"dsn_return":                       "HDRS",
			"dsn_notify:recipient@example.com": "FAILURE",
		},
	}

	content, err := engine.buildDSNBounce(msg, "connection refused")
	require.NoError(t, err)

	contentStr := string(content)
	// Should not have message/rfc822 part for HDRS
	assert.NotContains(t, contentStr, "Content-Type: message/rfc822")
	// Should still have delivery-status
	assert.Contains(t, contentStr, "message/delivery-status")
}

func TestBounceEngineEmptyAnnotations(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with empty annotations map - no bounce
	msg := queue.Message{
		ID:          "test-empty-annotations",
		From:        "sender@example.com",
		To:          []string{"recipient@example.com"},
		Subject:     "Test",
		CreatedAt:   time.Now(),
		Annotations: map[string]string{},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	assert.False(t, result.BounceGenerated)
}

func TestBounceEngineNilAnnotations(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with nil annotations - no bounce
	msg := queue.Message{
		ID:        "test-nil-annotations",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Subject:   "Test",
		CreatedAt: time.Now(),
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	assert.False(t, result.BounceGenerated)
}

func TestBounceEngineDSNEmptyReturn(t *testing.T) {
	engine, _ := newTestBounceEngine(t)
	ctx := context.Background()

	// Message with empty dsn_return - no bounce
	msg := queue.Message{
		ID:        "test-empty-return",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Subject:   "Test",
		CreatedAt: time.Now(),
		Annotations: map[string]string{
			"dsn_return": "",
		},
	}

	result := engine.GenerateBounceIfNeeded(ctx, msg, "connection refused")
	assert.False(t, result.BounceGenerated)
}

func TestGetRecipientDSNParams(t *testing.T) {
	engine, _ := newTestBounceEngine(t)

	msg := queue.Message{
		Annotations: map[string]string{
			"dsn_notify:rcpt1@example.com": "FAILURE,SUCCESS",
			"dsn_orcpt:rcpt1@example.com":  "rfc822;rcpt1@example.com",
			"dsn_notify:rcpt2@example.com": "DELAY",
		},
	}

	// Test recipient with both notify and orcpt
	notify, orcpt := engine.getRecipientDSNParams(msg, "rcpt1@example.com")
	assert.Equal(t, []string{"FAILURE", "SUCCESS"}, notify)
	assert.Equal(t, "rfc822;rcpt1@example.com", orcpt)

	// Test recipient with only notify
	notify, orcpt = engine.getRecipientDSNParams(msg, "rcpt2@example.com")
	assert.Equal(t, []string{"DELAY"}, notify)
	assert.Empty(t, orcpt)

	// Test recipient with no DSN params
	notify, orcpt = engine.getRecipientDSNParams(msg, "rcpt3@example.com")
	assert.Empty(t, notify)
	assert.Empty(t, orcpt)
}
