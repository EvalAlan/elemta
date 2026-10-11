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
	// A non-null sender that is itself a bounce identity means a DSN was
	// re-injected with a real reverse-path; answering it lets two MTAs bounce
	// at each other forever.
	if be.isBounceIdentity(from) {
		be.logger.InfoContext(ctx, "Skipping bounce to a mailer-daemon address",
			"message_id", msg.ID,
			"sender", from,
		)
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
// server's reply text. The neighbours must not be digits or dots, or the
// first three octets of an address like 5.6.7.8 read as status 5.6.7.
var enhancedStatusPattern = regexp.MustCompile(`(?:^|[^0-9.])(5\.[0-7]\.[0-9]{1,3})(?:\.?[^0-9.]|\.?$)`)

// smtpReplyPattern recognises text that starts with an SMTP reply code, the
// only kind of diagnostic RFC 3464 lets us label "smtp".
var smtpReplyPattern = regexp.MustCompile(`^[245][0-9]{2}(?:[ -]|$)`)

// maxDSNLine keeps folded DSN lines well under RFC 5322's 998-octet limit,
// which a 1024-byte diagnostic on one line used to exceed.
const maxDSNLine = 78

// maxReturnedMessage caps how much of an original message a RET=FULL bounce
// carries back. Past it the bounce returns headers only, rather than sending a
// large attachment back to a sender who already has it.
const maxReturnedMessage = 1 << 20

// maxReturnedHeaders caps the text/rfc822-headers part for the same reason.
const maxReturnedHeaders = 64 << 10

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

// isBounceIdentity reports whether sender is an address bounces come from:
// any MAILER-DAEMON, or this host's own postmaster, which is the From of the
// bounces it writes.
func (be *BounceEngine) isBounceIdentity(sender string) bool {
	sender = strings.Trim(sender, "<>")
	local, domain, ok := strings.Cut(sender, "@")
	if !ok {
		local = sender
	}
	if strings.EqualFold(local, "mailer-daemon") {
		return true
	}
	return ok && strings.EqualFold(local, "postmaster") && strings.EqualFold(domain, be.hostname)
}

// decodeXText reverses RFC 3461 xtext, which ENVID and ORCPT arrive in; the
// DSN fields carry the decoded value. Malformed escapes are left as they are.
func decodeXText(s string) string {
	if !strings.Contains(s, "+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '+' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			var v byte
			for _, c := range []byte{s[i+1], s[i+2]} {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= c - '0'
				case c >= 'a' && c <= 'f':
					v |= c - 'a' + 10
				default:
					v |= c - 'A' + 10
				}
			}
			b.WriteByte(v)
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// foldField writes "name: value" folded at spaces so lines stay near
// maxDSNLine, and hard-breaks a single run too long to fit under the
// RFC 5322 line limit at all.
func foldField(buf *bytes.Buffer, name, value string) {
	line := name + ":"
	for _, word := range strings.Fields(value) {
		for len(word) > 900 {
			buf.WriteString(line + "\r\n")
			line = " " + word[:900]
			word = word[900:]
		}
		if len(line) > len(name)+1 && len(line)+1+len(word) > maxDSNLine {
			buf.WriteString(line + "\r\n")
			line = ""
		}
		line += " " + word
	}
	buf.WriteString(line + "\r\n")
}

// headerBlock returns the original's header section, capped so a message
// with no body separator, or an enormous header, cannot ride back whole in a
// "headers only" bounce.
func headerBlock(original []byte) []byte {
	headers := original
	if i := bytes.Index(original, []byte("\r\n\r\n")); i >= 0 {
		headers = original[:i+2]
	} else if i := bytes.Index(original, []byte("\n\n")); i >= 0 {
		headers = original[:i+1]
	}
	if len(headers) > maxReturnedHeaders {
		headers = headers[:maxReturnedHeaders]
		if i := bytes.LastIndexByte(headers, '\n'); i >= 0 {
			headers = headers[:i+1]
		}
	}
	return headers
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
	// The time is part of the ID because one message can produce several
	// bounces (a partial failure now, the rest after retries run out), and
	// receivers that de-duplicate on Message-ID would drop the later ones.
	// The idempotent path passes a stable time, so its retries still match.
	messageID := fmt.Sprintf("<bounce-%s.%d@%s>", msg.ID, now.UnixNano(), be.hostname)

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
	// Remote reply text is multi-line and arbitrary bytes; written raw it put
	// bare LFs and 8-bit data into a part declared 7bit.
	foldField(&buf, "Reason", be.sanitizeDiagnosticCode(failureReason))
	buf.WriteString("\r\n")
	fmt.Fprintf(&buf, "Original message ID: %s\r\n", msg.ID)
	fmt.Fprintf(&buf, "Original subject: %s\r\n", be.sanitizeDiagnosticCode(msg.Subject))
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
		// Decoded per RFC 3461 §4.4, and sanitised after decoding because
		// "+0D+0A" is valid xtext for CRLF.
		fmt.Fprintf(&buf, "Original-Envelope-Id: %s\r\n", be.sanitizeDiagnosticCode(decodeXText(envid)))
	}
	// Optional field; a zero time printed as year 1.
	if !msg.ReceivedAt.IsZero() {
		fmt.Fprintf(&buf, "Arrival-Date: %s\r\n", msg.ReceivedAt.Format(time.RFC1123Z))
	}
	diagnosticType := "X-Elemta"
	if smtpReplyPattern.MatchString(strings.TrimSpace(failureReason)) {
		diagnosticType = "smtp"
	}

	// Per-recipient DSN fields
	for _, recipient := range msg.To {
		// Get per-recipient DSN params if available
		notifyValues, orcpt := be.getRecipientDSNParams(msg, recipient)

		buf.WriteString("\r\n")

		// RFC 3464 §2.3: Final-Recipient is the address this MTA tried, and
		// ORCPT goes in Original-Recipient. Putting ORCPT in Final-Recipient
		// hid which address actually failed after aliasing or forwarding.
		if orcpt != "" {
			fmt.Fprintf(&buf, "Original-Recipient: %s\r\n", be.sanitizeDiagnosticCode(decodeXText(orcpt)))
		}
		fmt.Fprintf(&buf, "Final-Recipient: rfc822; %s\r\n", sanitizeEmailForHeader(recipient))
		fmt.Fprintf(&buf, "Action: failed\r\n")
		fmt.Fprintf(&buf, "Status: %s\r\n", be.mapFailureToDSNStatus(failureReason))
		// "smtp" is only for an SMTP reply (RFC 3464 §2.3.6); a local error
		// such as "connection refused" labelled smtp misleads bounce parsers.
		foldField(&buf, "Diagnostic-Code", diagnosticType+"; "+be.sanitizeDiagnosticCode(failureReason))
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
		headers := headerBlock(original)
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
	if m := enhancedStatusPattern.FindStringSubmatch(reason); m != nil {
		return BounceDSNStatus(m[1])
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
	// message/delivery-status is 7-bit text (RFC 3464 §2.1). CR and LF
	// become spaces so a multi-line reply stays readable; other control
	// characters go, and non-ASCII becomes '?' rather than raw 8-bit bytes.
	var b strings.Builder
	for _, r := range reason {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
		case r > 0x7f:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
