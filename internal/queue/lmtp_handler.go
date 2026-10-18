package queue

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// LMTPDeliveryHandler implements DeliveryHandler for LMTP delivery (e.g., to Dovecot)
type LMTPDeliveryHandler struct {
	logger                    *slog.Logger
	timeout                   time.Duration
	host                      string
	port                      int
	limiter                   *domainLimiter
	maxInFly                  int
	failedQueueRetentionHours int
	// tlsConfig, when set, makes every session STARTTLS before MAIL FROM,
	// and a server that doesn't offer it is a temporary failure, never a
	// silent downgrade to plaintext.
	tlsConfig *tls.Config

	poolMu sync.Mutex
	pool   []*lmtpSession
}

// SetTLS requires STARTTLS with this configuration; nil turns it off.
func (h *LMTPDeliveryHandler) SetTLS(cfg *tls.Config) { h.tlsConfig = cfg }

// NewLMTPDeliveryHandler creates a new LMTP delivery handler
func NewLMTPDeliveryHandler(host string, port int, maxPerDomain int, failedQueueRetentionHours int) *LMTPDeliveryHandler {
	if port == 0 {
		port = 2424 // Default LMTP port (common for Dovecot)
	}
	if maxPerDomain <= 0 {
		maxPerDomain = 10
	}

	return &LMTPDeliveryHandler{
		logger:                    slog.Default().With("component", "lmtp-delivery"),
		timeout:                   30 * time.Second,
		host:                      host,
		port:                      port,
		limiter:                   newDomainLimiter(maxPerDomain),
		maxInFly:                  maxPerDomain,
		failedQueueRetentionHours: failedQueueRetentionHours,
	}
}

// DeliverMessage attempts to deliver a message via LMTP
func (h *LMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata attempts to deliver a message via LMTP and returns delivery metadata.
//
// The transport is stamped here rather than at each of the dozen places a
// result is built, because that is exactly how every one of them ended up
// hardcoding the same string.
func (h *LMTPDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	result, err := h.deliverWithMetadata(ctx, msg, content)
	// A handler that failed before it could build a result still knows which
	// transport it was: "which route failed" is the first thing an operator
	// asks, and a connection refused at the first hop is exactly when they ask.
	if result == nil {
		result = &DeliveryResult{Error: err}
	}
	if result.DeliveryMethod == "" {
		result.DeliveryMethod = DeliveryMethodLMTP
	}
	return result, err
}

func (h *LMTPDeliveryHandler) deliverWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	h.logger.Info("Attempting LMTP delivery",
		"message_id", msg.ID,
		"from", msg.From,
		"to", msg.To,
		"server", fmt.Sprintf("%s:%d", h.host, h.port))

	// Determine routing domain for per-domain limiting
	domain := msg.Domain
	if domain == "" && len(msg.To) > 0 {
		domain = extractDomain(msg.To[0])
	}

	// Apply simple per-domain in-flight limiter
	if domain != "" && h.limiter != nil {
		if !h.limiter.TryAcquire(domain) {
			return nil, fmt.Errorf("temporary failure: domain %s is over concurrent delivery limit", domain)
		}
		defer h.limiter.Release(domain)
	}

	// Create context with timeout
	deliveryCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	addr := net.JoinHostPort(h.host, fmt.Sprintf("%d", h.port))
	sess, err := h.acquire(deliveryCtx)
	if err != nil {
		if errors.Is(err, errLMTPSetup) {
			return lmtpPreFinalFailure(msg, addr, err.Error(), RecipientTemporaryFailure)
		}
		return &DeliveryResult{}, err
	}
	// The session goes back to the pool only after a clean transaction;
	// any other exit closes it.
	reusable := false
	defer func() {
		if reusable {
			h.release(sess)
		} else {
			_ = sess.conn.Close()
		}
	}()
	conn := sess.conn
	reader, writer := sess.r, sess.w
	sendCommand := sess.command
	canEnvelopeID := sess.exts["DSN"]

	// Send MAIL FROM - extract clean email address from the stored From field
	// The From field might contain: "<test@example.com> size=237" or "test@example.com" or "<test@example.com>"
	sender := msg.From

	// If it starts with <, extract the address between < and >
	if strings.HasPrefix(sender, "<") {
		if endIdx := strings.Index(sender, ">"); endIdx > 1 {
			sender = sender[1:endIdx]
		} else {
			sender = strings.TrimPrefix(sender, "<")
		}
	}

	// Strip any remaining angle brackets
	sender = strings.Trim(sender, "<>")

	// Strip any trailing parameters (shouldn't happen after above, but just in case)
	if spaceIdx := strings.Index(sender, " "); spaceIdx > 0 {
		h.logger.Warn("MAIL FROM still contains extra parameters after cleanup, stripping",
			"raw_from", msg.From,
			"sender_before_strip", sender)
		sender = sender[:spaceIdx]
	}

	h.logger.Debug("Sending MAIL FROM", "raw_from", msg.From, "cleaned_sender", sender)
	mailCommand := fmt.Sprintf("MAIL FROM:<%s>", sender)
	// A stable queue ID lets a trusted mailbox backend recognize retries
	// after an ambiguous disconnect. Never forward a sender-chosen token.
	if canEnvelopeID && msg.ID != "" {
		sum := sha256.Sum256([]byte(msg.ID))
		mailCommand += fmt.Sprintf(" ENVID=%x", sum)
	}
	mailFromResp, err := sendCommand(mailCommand + "\r\n")
	if err != nil {
		return lmtpPreFinalFailure(msg, addr, "MAIL FROM failed: "+err.Error(), RecipientTemporaryFailure)
	}
	if !strings.HasPrefix(mailFromResp, "250 ") {
		return lmtpPreFinalFailure(msg, addr, mailFromResp, statusForResponse(mailFromResp))
	}

	// Send RCPT TO for each recipient
	var acceptedRecipients []string
	var acceptedIndexes []int
	var failedRecipients []string
	outcomes := make([]RecipientOutcome, len(msg.To))

	for i, recipient := range msg.To {
		outcomes[i] = RecipientOutcome{Recipient: recipient, Route: addr}
		rcptResp, err := sendCommand(fmt.Sprintf("RCPT TO:<%s>\r\n", recipient))
		if err != nil {
			h.logger.Error("RCPT TO command failed", "recipient", recipient, "error", err)
			failedRecipients = append(failedRecipients, recipient)
			outcomes[i].Status, outcomes[i].Diagnostic = RecipientTemporaryFailure, err.Error()
			continue
		}

		if strings.HasPrefix(rcptResp, "250 ") {
			acceptedRecipients = append(acceptedRecipients, recipient)
			acceptedIndexes = append(acceptedIndexes, i)
			h.logger.Debug("Recipient accepted", "recipient", recipient)
		} else {
			h.logger.Error("Recipient rejected", "recipient", recipient, "response", rcptResp)
			failedRecipients = append(failedRecipients, recipient)
			status := RecipientTemporaryFailure
			if strings.HasPrefix(rcptResp, "5") {
				status = RecipientPermanentFailure
			}
			outcomes[i].Status, outcomes[i].EnhancedStatusCode, outcomes[i].Diagnostic = status, enhancedStatus(rcptResp), rcptResp
		}
	}

	// Check if any recipients were accepted
	if len(acceptedRecipients) == 0 {
		err := fmt.Errorf("all recipients rejected: %v", failedRecipients)
		return &DeliveryResult{RecipientOutcomes: outcomes, Error: err, DeliveryTime: time.Now()}, err
	}

	// Send DATA
	dataResp, err := sendCommand("DATA\r\n")
	if err != nil {
		return lmtpOutcomesFailure(msg, addr, outcomes, acceptedRecipients, err.Error(), RecipientTemporaryFailure)
	}
	if !strings.HasPrefix(dataResp, "354 ") {
		return lmtpOutcomesFailure(msg, addr, outcomes, acceptedRecipients, dataResp, statusForResponse(dataResp))
	}

	// Send message content
	h.logger.Debug("Sending message content", "size", len(content))
	dotWriter := textproto.NewWriter(writer).DotWriter()
	if _, err := dotWriter.Write(content); err != nil {
		return &DeliveryResult{}, fmt.Errorf("failed to write message data: %w", err)
	}

	// Send end-of-data marker
	if err := dotWriter.Close(); err != nil {
		return &DeliveryResult{}, fmt.Errorf("failed to send end-of-data marker: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return &DeliveryResult{}, fmt.Errorf("failed to flush message data: %w", err)
	}

	// Read response for each accepted recipient (LMTP returns per-recipient responses)
	deliveredCount := 0
	readAll := true
	for acceptedPosition, recipient := range acceptedRecipients {
		outcomeIndex := acceptedIndexes[acceptedPosition]
		resp, err := reader.ReadString('\n')
		if err != nil {
			readAll = false
			outcomes[outcomeIndex].Status, outcomes[outcomeIndex].Diagnostic = RecipientTemporaryFailure, err.Error()
			continue
		}
		resp = strings.TrimSpace(resp)
		h.logger.Debug("Delivery response", "response", resp)

		status := RecipientTemporaryFailure
		if strings.HasPrefix(resp, "2") {
			status = RecipientDelivered
			deliveredCount++
		} else {
			if strings.HasPrefix(resp, "5") {
				status = RecipientPermanentFailure
			}
			failedRecipients = append(failedRecipients, recipient)
			h.logger.Error("Delivery failed for recipient", "recipient", recipient, "response", resp)
		}
		outcomes[outcomeIndex].Status, outcomes[outcomeIndex].EnhancedStatusCode, outcomes[outcomeIndex].Diagnostic = status, enhancedStatus(resp), resp
	}

	// Every recipient's reply was read, so the session is at a clean
	// boundary and can carry the next message.
	reusable = readAll

	// Check delivery success
	if deliveredCount == 0 {
		deliveryErr := fmt.Errorf("delivery failed for all accepted recipients")
		return &DeliveryResult{
			Success:           false,
			Error:             deliveryErr,
			DeliveryTime:      time.Now(),
			ResponseMessage:   "Delivered to 0 recipients",
			RecipientOutcomes: outcomes,
		}, deliveryErr
	} else if deliveredCount < len(acceptedRecipients) {
		h.logger.Warn("Partial delivery success",
			"delivered", deliveredCount,
			"total", len(acceptedRecipients))
	}

	h.logger.Info("LMTP delivery successful",
		"message_id", msg.ID,
		"delivered", deliveredCount,
		"total_recipients", len(msg.To),
		"failed_recipients", len(failedRecipients))

	// Capture delivery IP and host from connection
	deliveryIP := ""
	deliveryHost := ""
	if conn != nil {
		remoteAddr := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			deliveryIP = host
			deliveryHost = host
		} else {
			deliveryIP = remoteAddr
			deliveryHost = remoteAddr
		}
	}

	// Create delivery result
	result := &DeliveryResult{
		Success:           deliveredCount > 0,
		DeliveryIP:        deliveryIP,
		DeliveryHost:      deliveryHost,
		DeliveryTime:      time.Now(),
		ResponseMessage:   fmt.Sprintf("Delivered to %d/%d recipients", deliveredCount, len(msg.To)),
		RecipientOutcomes: outcomes,
	}

	// Return error if some recipients failed but we had partial success
	if len(failedRecipients) > 0 {
		result.Error = fmt.Errorf("partial delivery: %d/%d recipients delivered, failed: %v",
			deliveredCount, len(msg.To), failedRecipients)
		return result, result.Error
	}

	return result, nil
}

func enhancedStatus(response string) string {
	fields := strings.Fields(response)
	for _, field := range fields[1:] {
		parts := strings.Split(field, ".")
		if len(parts) == 3 && (parts[0] == "2" || parts[0] == "4" || parts[0] == "5") && allDigits(parts[1]) && allDigits(parts[2]) {
			return field
		}
	}
	return ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func statusForResponse(response string) RecipientDeliveryStatus {
	if strings.HasPrefix(strings.TrimSpace(response), "5") {
		return RecipientPermanentFailure
	}
	return RecipientTemporaryFailure
}

func lmtpPreFinalFailure(msg Message, route, diagnostic string, status RecipientDeliveryStatus) (*DeliveryResult, error) {
	return lmtpOutcomesFailure(msg, route, nil, msg.To, diagnostic, status)
}

func lmtpOutcomesFailure(msg Message, route string, prior []RecipientOutcome, pending []string, diagnostic string, status RecipientDeliveryStatus) (*DeliveryResult, error) {
	outcomes := append([]RecipientOutcome(nil), prior...)
	if len(outcomes) == 0 {
		outcomes = make([]RecipientOutcome, len(pending))
		for i, recipient := range pending {
			outcomes[i] = RecipientOutcome{Recipient: recipient, Status: status, EnhancedStatusCode: enhancedStatus(diagnostic), Diagnostic: diagnostic, Route: route}
		}
	} else {
		// Accepted recipients already have occurrence slots. Resolve those slots
		// rather than appending duplicates and leaving zero-status placeholders.
		for _, recipient := range pending {
			for i := range outcomes {
				if outcomes[i].Recipient == recipient && outcomes[i].Status == "" {
					outcomes[i].Status = status
					outcomes[i].EnhancedStatusCode = enhancedStatus(diagnostic)
					outcomes[i].Diagnostic = diagnostic
					outcomes[i].Route = route
					break
				}
			}
		}
	}
	err := errors.New(diagnostic)
	return &DeliveryResult{Error: err, DeliveryTime: time.Now(), RecipientOutcomes: outcomes}, err
}

// domainLimiter implements a simple in-memory per-domain in-flight limiter
type domainLimiter struct {
	maxPerDomain int
	mu           sync.Mutex
	inFlight     map[string]int
}

func newDomainLimiter(max int) *domainLimiter {
	if max <= 0 {
		max = 1
	}
	return &domainLimiter{
		maxPerDomain: max,
		inFlight:     make(map[string]int),
	}
}

func (l *domainLimiter) TryAcquire(domain string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.inFlight[domain] >= l.maxPerDomain {
		return false
	}
	l.inFlight[domain]++
	return true
}

func (l *domainLimiter) Release(domain string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if current, ok := l.inFlight[domain]; ok {
		if current <= 1 {
			delete(l.inFlight, domain)
		} else {
			l.inFlight[domain] = current - 1
		}
	}
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (h *LMTPDeliveryHandler) GetFailedQueueRetentionHours() int {
	return h.failedQueueRetentionHours
}
