// internal/smtp/bounce.go
package smtp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/logging"
	"github.com/EvalAlan/elemta/internal/queue"
)

// BounceEngine generates RFC 3462 DSN bounce messages from failed queue entries.
type BounceEngine struct {
	logger       *slog.Logger
	queueManager queue.QueueManager
	hostname     string
	msgLogger    *logging.MessageLogger
}

// NewBounceEngine creates a new bounce engine.
func NewBounceEngine(queueManager queue.QueueManager, hostname string, logger *slog.Logger) *BounceEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &BounceEngine{
		logger:       logger.With("component", "bounce-engine"),
		queueManager: queueManager,
		hostname:     hostname,
		msgLogger:    logging.NewMessageLogger(logger),
	}
}

// BounceDSNStatus represents the DSN status code for a failed delivery (RFC 3464 Section 2.3.3)
type BounceDSNStatus string

const (
	// DSNStatusPermanentFailure is the DSN status for a permanent failure the
	// remote server gave no detail for. It was 5.1.7, which means "bad sender
	// mailbox syntax" and told every sender their own address was malformed.
	DSNStatusPermanentFailure BounceDSNStatus = "5.0.0"
	// DSNStatusGeneralFailure is a general delivery failure (X.1.0 / 5.0.0)
	DSNStatusGeneralFailure BounceDSNStatus = "5.0.0"
	// DSNStatusMailboxUnavailable is for mailbox unavailable (X.1.2 / 5.2.0)
	DSNStatusMailboxUnavailable BounceDSNStatus = "5.2.0"
	// DSNStatusSystemNotAccepting is for system not accepting messages (X.1.3 / 5.3.0)
	DSNStatusSystemNotAccepting BounceDSNStatus = "5.3.0"
	// DSNStatusBadDestinationAddress is for bad destination address (X.1.1 / 5.1.1)
	DSNStatusBadDestinationAddress BounceDSNStatus = "5.1.1"
	// DSNStatusConnectionRefused is for connection refused (X.1.6 / 5.4.2)
	DSNStatusConnectionRefused BounceDSNStatus = "5.4.2"
)

// BounceResult aliases queue.BounceResult for external consumers.
// The canonical definition lives in the queue package so both the
// bounce engine and processor can reference the same type.
type BounceResult = queue.BounceResult

// GenerateBounceIfNeeded checks if a bounce is needed for a failed message and generates it.
// Returns nil if no bounce was needed (e.g., DSN not requested or NOTIFY=NEVER).
// Returns a BounceResult with the bounce ID if a bounce was successfully queued.
func (be *BounceEngine) GenerateBounceIfNeeded(ctx context.Context, msg queue.Message, failureReason string) *BounceResult {
	return be.generateBounce(ctx, msg, failureReason, "")
}

// GenerateBounceIdempotent uses a stable queue ID to close the enqueue/marker crash gap.
func (be *BounceEngine) GenerateBounceIdempotent(ctx context.Context, msg queue.Message, failureReason, handoffID string) *BounceResult {
	return be.generateBounce(ctx, msg, failureReason, handoffID)
}

func (be *BounceEngine) generateBounce(ctx context.Context, msg queue.Message, failureReason, handoffID string) *BounceResult {
	// RFC 5321 §6.1: once a message is accepted, a delivery failure MUST be
	// reported to the sender. This used to happen only when the sender had
	// asked for DSNs with RET=, which almost no client does, so a message that
	// failed after acceptance usually vanished without anyone being told.
	//
	// Never to a null sender: that is a bounce already, and answering it is
	// how bounce loops start.
	from := strings.TrimSpace(msg.From)
	if from == "" || from == "<>" {
		return &BounceResult{BounceGenerated: false}
	}
	// Per recipient, NOTIFY decides (RFC 3461 §4.1): absent means the default,
	// which includes FAILURE; NEVER or a list without FAILURE means the
	// sender asked not to hear about this one.
	reported := be.recipientsToNotify(msg)
	if len(reported) == 0 {
		be.logger.DebugContext(ctx, "Skipping bounce: NOTIFY excludes FAILURE for every failed recipient",
			"message_id", msg.ID,
		)
		return &BounceResult{BounceGenerated: false}
	}
	msg.To = reported
	dsnReturn := strings.ToUpper(msg.Annotations["dsn_return"])
	if dsnReturn == "" {
		dsnReturn = "HDRS"
	}

	bounceTime := time.Now()
	if handoffID != "" {
		bounceTime = msg.UpdatedAt
		if bounceTime.IsZero() {
			bounceTime = msg.CreatedAt
		}
	}
	bounceContent, err := be.buildDSNBounceAt(msg, failureReason, bounceTime)
	if err != nil {
		be.logger.ErrorContext(ctx, "Failed to build DSN bounce",
			"message_id", msg.ID,
			"error", err,
		)
		return &BounceResult{BounceGenerated: false, Error: err}
	}

	// Queue the bounce message
	// Bounces go to the original sender (msg.From) from the postmaster
	var bounceID string
	if handoffID != "" {
		if manager, ok := be.queueManager.(interface {
			EnqueueMessageWithID(string, string, []string, string, []byte, queue.Priority, time.Time) (string, error)
		}); ok {
			receivedAt := time.Now()
			if handoffID != "" {
				receivedAt = bounceTime
			}
			bounceID, err = manager.EnqueueMessageWithID(handoffID, "", []string{msg.From}, "Delivery Status Notification (Failure)", bounceContent, queue.PriorityHigh, receivedAt)
		} else {
			err = fmt.Errorf("queue manager does not support idempotent enqueue")
		}
	} else {
		// Null envelope sender (RFC 5321 §4.5.5): a bounce that itself fails
		// must not generate another one.
		bounceID, err = be.queueManager.EnqueueMessage(
			"",
			[]string{msg.From},
			"Delivery Status Notification (Failure)",
			bounceContent,
			queue.PriorityHigh,
			time.Now(),
		)
	}
	if err != nil {
		be.logger.ErrorContext(ctx, "Failed to queue bounce message",
			"message_id", msg.ID,
			"bounce_recipient", msg.From,
			"error", err,
		)
		return &BounceResult{BounceGenerated: false, Error: err}
	}

	be.logger.InfoContext(ctx, "DSN bounce generated and queued",
		"original_message_id", msg.ID,
		"bounce_id", bounceID,
		"bounce_recipient", msg.From,
		"dsn_return", dsnReturn,
	)

	// Log bounce generation event
	be.msgLogger.LogBounce(logging.MessageContext{
		MessageID:      bounceID,
		QueueID:        bounceID,
		From:           "<>",
		To:             []string{msg.From},
		Subject:        "Delivery Status Notification (Failure)",
		Size:           int64(len(bounceContent)),
		ReceptionTime:  time.Now(),
		ProcessingTime: time.Now(),
		RetryCount:     0,
		Error:          failureReason,
		DeliveryMethod: "dsn",
	})

	return &BounceResult{BounceGenerated: true, BounceID: bounceID}
}

// enhancedStatusPattern finds a permanent RFC 3463 status such as 5.1.1 in a
// server's reply text.
var enhancedStatusPattern = regexp.MustCompile(`\b5\.[0-7]\.[0-9]{1,3}\b`)

// maxReturnedMessage caps how much of an original message a RET=FULL bounce
// carries back. Past it the bounce returns headers only, rather than sending a
// large attachment back to a sender who already has it.
const maxReturnedMessage = 1 << 20

// originalContent fetches the failed message for the bounce, best effort: a
// bounce without the original is still a bounce.
func (be *BounceEngine) originalContent(id string) []byte {
	if be.queueManager == nil || id == "" {
		return nil
	}
	content, err := be.queueManager.GetMessageContent(id)
	if err != nil {
		return nil
	}
	return content
}

// recipientsToNotify returns the failed recipients the sender wants to hear
// about.
func (be *BounceEngine) recipientsToNotify(msg queue.Message) []string {
	out := make([]string, 0, len(msg.To))
	for _, rcpt := range msg.To {
		notify, ok := msg.Annotations["dsn_notify:"+rcpt]
		if !ok || strings.TrimSpace(notify) == "" {
			out = append(out, rcpt)
			continue
		}
		if strings.Contains(strings.ToUpper(notify), "FAILURE") {
			out = append(out, rcpt)
		}
	}
	return out
}

//nolint:unused // retained for package tests and compatibility
func (be *BounceEngine) buildDSNBounce(msg queue.Message, failureReason string) ([]byte, error) {
	return be.buildDSNBounceAt(msg, failureReason, time.Now())
}

func (be *BounceEngine) buildDSNBounceAt(msg queue.Message, failureReason string, now time.Time) ([]byte, error) {
	if now.IsZero() {
		now = time.Unix(0, 0).UTC()
	}
	boundary := fmt.Sprintf("elemta-boundary-%d", now.UnixNano())
	messageID := fmt.Sprintf("<bounce-%s@%s>", msg.ID, be.hostname)

	var buf bytes.Buffer

	// RFC 3462 Section 3.1 - The message part headers
	buf.WriteString("Content-Type: multipart/report; report-type=delivery-status;\r\n")
	fmt.Fprintf(&buf, "\tboundary=\"%s\"\r\n", boundary)
	buf.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Message-ID: %s\r\n", messageID)
	fmt.Fprintf(&buf, "Date: %s\r\n", now.Format(time.RFC1123Z))
	buf.WriteString("From: <postmaster@" + be.hostname + ">\r\n")
	fmt.Fprintf(&buf, "To: <%s>\r\n", sanitizeEmailForHeader(msg.From))
	buf.WriteString("Subject: Delivery Status Notification (Failure)\r\n")
	// RFC 3834: marks this as machine-generated, so vacation responders and
	// other automatic replies do not answer it.
	buf.WriteString("Auto-Submitted: auto-replied\r\n")
	buf.WriteString("\r\n")

	// Part 1: Human-readable text explanation (RFC 3462 Section 3.1)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("This is a MIME-formatted message containing a Delivery Status Notification.\r\n")
	buf.WriteString("\r\n")
	fmt.Fprintf(&buf, "Your message to the following recipients could not be delivered:\r\n")
	for _, recipient := range msg.To {
		fmt.Fprintf(&buf, "  - %s\r\n", sanitizeEmailForHeader(recipient))
	}
	buf.WriteString("\r\n")
	fmt.Fprintf(&buf, "Reason: %s\r\n", failureReason)
	buf.WriteString("\r\n")
	fmt.Fprintf(&buf, "Original message ID: %s\r\n", msg.ID)
	fmt.Fprintf(&buf, "Original subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&buf, "Original sender: %s\r\n", sanitizeEmailForHeader(msg.From))
	fmt.Fprintf(&buf, "Failed at: %s\r\n", now.Format(time.RFC1123Z))
	buf.WriteString("\r\n")
	buf.WriteString("If you believe this is an error, please contact your mail administrator.\r\n")
	buf.WriteString("\r\n")

	// Part 2: Machine-readable DSN per-recipient report (RFC 3462 Section 3.2)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	buf.WriteString("Content-Type: message/delivery-status\r\n")
	buf.WriteString("\r\n")

	// Per-message fields, once (RFC 3464 §2.2), then one block per recipient,
	// each preceded by a blank line. Repeating the per-message fields for
	// every recipient made each repeat look like a recipient block with no
	// Final-Recipient, which parsers reject.
	buf.WriteString("Reporting-MTA: dns; " + be.hostname + "\r\n")
	if envid := msg.Annotations["dsn_envid"]; envid != "" {
		fmt.Fprintf(&buf, "Original-Envelope-Id: %s\r\n", sanitizeEmailForHeader(envid))
	}
	fmt.Fprintf(&buf, "Arrival-Date: %s\r\n", msg.ReceivedAt.Format(time.RFC1123Z))

	// Per-recipient DSN fields
	for _, recipient := range msg.To {
		// Get per-recipient DSN params if available
		notifyValues, orcpt := be.getRecipientDSNParams(msg, recipient)

		// Final-Recipient: use ORCPT if available, otherwise the final address
		// RFC 3462 requires the format "Final-Recipient: <type>; <addr>"
		// ORCPT format is "rfc822;addr" or "dns;addr" per RFC 3461
		finalRecipient := "rfc822; " + sanitizeEmailForHeader(recipient)
		if orcpt != "" {
			finalRecipient = sanitizeEmailForHeader(orcpt)
		}

		buf.WriteString("\r\n")

		// Per-recipient fields
		fmt.Fprintf(&buf, "Final-Recipient: %s\r\n", finalRecipient)
		fmt.Fprintf(&buf, "Action: failed\r\n")
		fmt.Fprintf(&buf, "Status: %s\r\n", be.mapFailureToDSNStatus(failureReason))
		fmt.Fprintf(&buf, "Diagnostic-Code: smtp; %s\r\n", be.sanitizeDiagnosticCode(failureReason))
		fmt.Fprintf(&buf, "Last-Attempt-Date: %s\r\n", now.Format(time.RFC1123Z))

		// Include original notify conditions for reference
		if len(notifyValues) > 0 {
			fmt.Fprintf(&buf, "Original-Notify: %s\r\n", strings.Join(notifyValues, ","))
		}
	}
	buf.WriteString("\r\n")

	// Part 3: the original message. RET=FULL returns all of it; otherwise,
	// and when the full message is too large to send back, its header block
	// (RFC 3462 §3.3, text/rfc822-headers). The text used to be a made-up
	// header block and a note that retrieval was not implemented.
	if original := be.originalContent(msg.ID); len(original) > 0 {
		headers := original
		if i := bytes.Index(original, []byte("\r\n\r\n")); i >= 0 {
			headers = original[:i+2]
		} else if i := bytes.Index(original, []byte("\n\n")); i >= 0 {
			headers = original[:i+1]
		}
		fmt.Fprintf(&buf, "--%s\r\n", boundary)
		if strings.ToUpper(msg.Annotations["dsn_return"]) == "FULL" && len(original) <= maxReturnedMessage {
			buf.WriteString("Content-Type: message/rfc822\r\n\r\n")
			buf.Write(original)
		} else {
			buf.WriteString("Content-Type: text/rfc822-headers\r\n\r\n")
			buf.Write(headers)
		}
		if !bytes.HasSuffix(buf.Bytes(), []byte("\r\n")) {
			buf.WriteString("\r\n")
		}
	}

	// Close boundary
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)

	return buf.Bytes(), nil
}

// getRecipientDSNParams retrieves DSN parameters for a specific recipient
func (be *BounceEngine) getRecipientDSNParams(msg queue.Message, recipient string) (notifyValues []string, orcpt string) {
	notifyKey := "dsn_notify:" + recipient
	orcptKey := "dsn_orcpt:" + recipient

	if val, ok := msg.Annotations[notifyKey]; ok {
		notifyValues = strings.Split(val, ",")
	}
	if val, ok := msg.Annotations[orcptKey]; ok {
		orcpt = val
	}
	return
}

// mapFailureToDSNStatus maps a failure reason string to a DSN status code
func (be *BounceEngine) mapFailureToDSNStatus(reason string) BounceDSNStatus {
	// The receiving server's own enhanced status code (RFC 3463) is the most
	// precise answer there is; the keyword matching below is for failures
	// that never reached a server, or a server that gave no code.
	if code := enhancedStatusPattern.FindString(reason); code != "" {
		return BounceDSNStatus(code)
	}
	reasonLower := strings.ToLower(reason)

	switch {
	case strings.Contains(reasonLower, "connection refused"),
		strings.Contains(reasonLower, "connection reset"),
		strings.Contains(reasonLower, "network unreachable"):
		return DSNStatusConnectionRefused
	case strings.Contains(reasonLower, "mailbox unavailable"),
		strings.Contains(reasonLower, "mailbox full"),
		strings.Contains(reasonLower, "quota exceeded"),
		strings.Contains(reasonLower, "insufficient storage"):
		return DSNStatusMailboxUnavailable
	case strings.Contains(reasonLower, "user unknown"),
		strings.Contains(reasonLower, "no such user"),
		strings.Contains(reasonLower, "recipient address rejected"):
		return DSNStatusBadDestinationAddress
	case strings.Contains(reasonLower, "host not found"),
		strings.Contains(reasonLower, "name resolution"),
		strings.Contains(reasonLower, "dns lookup failed"),
		strings.Contains(reasonLower, "no mx records"):
		return DSNStatusSystemNotAccepting
	case strings.Contains(reasonLower, "permanent failure"),
		strings.Contains(reasonLower, "550"),
		strings.Contains(reasonLower, "551"),
		strings.Contains(reasonLower, "552"),
		strings.Contains(reasonLower, "553"),
		strings.Contains(reasonLower, "554"):
		return DSNStatusPermanentFailure
	default:
		return DSNStatusGeneralFailure
	}
}

// sanitizeDiagnosticCode ensures the diagnostic code is safe for inclusion in a DSN
func (be *BounceEngine) sanitizeDiagnosticCode(reason string) string {
	// Truncate to reasonable length (RFC 3464 suggests 1024 max)
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	// Replace newlines and control characters
	reason = strings.ReplaceAll(reason, "\r", " ")
	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\x00", "")
	return reason
}
