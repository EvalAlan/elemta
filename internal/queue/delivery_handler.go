package queue

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/delivery"
)

// mtastsEnforcer checks outbound delivery against a domain's MTA-STS policy.
// Satisfied by *delivery.MTASTSManager; abstracted so tests can inject a stub
// instead of making real DNS/HTTPS lookups.
type mtastsEnforcer interface {
	EnforcePolicy(ctx context.Context, domain, mxHost string, tlsUsed bool) error
}

// SMTPDeliveryHandler implements DeliveryHandler for SMTP delivery
type SMTPDeliveryHandler struct {
	logger                    *slog.Logger
	timeout                   time.Duration
	retryDNS                  bool
	maxMXLookups              int
	failedQueueRetentionHours int
	tlsConfig                 *tls.Config // optional template for outbound STARTTLS; nil = secure defaults
	mtastsManager             mtastsEnforcer
}

// NewSMTPDeliveryHandler creates a new SMTP delivery handler
func NewSMTPDeliveryHandler(failedQueueRetentionHours int) *SMTPDeliveryHandler {
	return &SMTPDeliveryHandler{
		logger:                    slog.Default().With("component", "smtp-delivery"),
		timeout:                   30 * time.Second,
		retryDNS:                  true,
		maxMXLookups:              3,
		failedQueueRetentionHours: failedQueueRetentionHours,
		mtastsManager:             delivery.NewMTASTSManager(&delivery.Config{MTASTSEnabled: true}),
	}
}

// DeliverMessage attempts to deliver a message via SMTP
func (h *SMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata attempts to deliver a message via SMTP and returns delivery metadata
func (h *SMTPDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	requireTLS := messageRequiresTLS(msg)

	// Group recipients by domain for efficient delivery
	domainGroups := h.groupRecipientsByDomain(msg.To)

	var lastError error
	delivered := 0
	var firstSuccessfulIP string
	var firstSuccessfulHost string

	for domain, recipients := range domainGroups {
		ip, host, err := h.deliverToDomainWithMetadata(ctx, msg, domain, recipients, content, requireTLS)
		if err != nil {
			h.logger.Error("Failed to deliver to domain",
				"domain", domain,
				"recipients", recipients,
				"error", err)
			lastError = err
		} else {
			delivered += len(recipients)
			h.logger.Info("Successfully delivered to domain",
				"domain", domain,
				"recipients", len(recipients))

			// Capture first successful delivery IP
			if firstSuccessfulIP == "" && ip != "" {
				firstSuccessfulIP = ip
				firstSuccessfulHost = host
			}
		}
	}

	return h.buildDeliveryResult(msg.To, delivered, firstSuccessfulIP, firstSuccessfulHost, lastError)
}

// buildDeliveryResult constructs a DeliveryResult from delivery statistics
func (h *SMTPDeliveryHandler) buildDeliveryResult(recipients []string, delivered int, ip, host string, lastError error) (*DeliveryResult, error) {
	result := &DeliveryResult{
		Success:         delivered > 0,
		DeliveryIP:      ip,
		DeliveryHost:    host,
		DeliveryTime:    time.Now(),
		ResponseMessage: fmt.Sprintf("Delivered to %d/%d recipients", delivered, len(recipients)),
	}

	switch {
	case delivered > 0 && delivered < len(recipients):
		result.Error = fmt.Errorf("partial delivery: %d/%d recipients delivered, last error: %v",
			delivered, len(recipients), lastError)
		return result, result.Error
	case delivered == 0:
		if lastError != nil {
			result.Error = lastError
			return result, lastError
		}
		result.Error = fmt.Errorf("delivery failed for all recipients")
		return result, result.Error
	default:
		return result, nil
	}
}

func messageRequiresTLS(msg Message) bool {
	if msg.Annotations == nil {
		return false
	}

	requireTLS := strings.TrimSpace(strings.ToLower(msg.Annotations["require_tls"]))
	switch requireTLS {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// groupRecipientsByDomain groups email recipients by their domain
func (h *SMTPDeliveryHandler) groupRecipientsByDomain(recipients []string) map[string][]string {
	groups := make(map[string][]string)

	for _, recipient := range recipients {
		parts := strings.Split(recipient, "@")
		if len(parts) != 2 {
			h.logger.Warn("Invalid email address", "recipient", recipient)
			continue
		}

		domain := strings.ToLower(parts[1])
		groups[domain] = append(groups[domain], recipient)
	}

	return groups
}

// deliverToDomainWithMetadata delivers messages to all recipients in a specific domain and returns delivery metadata
func (h *SMTPDeliveryHandler) deliverToDomainWithMetadata(ctx context.Context, msg Message, domain string, recipients []string, content []byte, requireTLS bool) (string, string, error) {
	// Look up MX records for the domain
	mxRecords, err := h.lookupMX(ctx, domain)
	if err != nil {
		return "", "", fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return "", "", fmt.Errorf("no MX records found for domain %s", domain)
	}

	// Try each MX record in order of preference
	var lastError error
	for _, mx := range mxRecords {
		ip, host, err := h.attemptDeliveryToHostWithMetadata(ctx, mx.Host, msg, recipients, content, requireTLS, domain)
		if err != nil {
			h.logger.Warn("Delivery failed to MX host",
				"host", mx.Host,
				"priority", mx.Pref,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, host, nil
	}

	return "", "", fmt.Errorf("delivery failed to all MX hosts for domain %s: %w", domain, lastError)
}

// lookupMX performs MX record lookup with retries
func (h *SMTPDeliveryHandler) lookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	var mxRecords []*net.MX
	var err error

	for attempt := 0; attempt < h.maxMXLookups; attempt++ {
		mxRecords, err = net.LookupMX(domain)
		if err == nil {
			break
		}

		h.logger.Debug("MX lookup attempt failed",
			"domain", domain,
			"attempt", attempt+1,
			"error", err)

		// Wait before retry (with context cancellation check)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
			// Continue to next attempt
		}
	}

	return mxRecords, err
}

// attemptDeliveryToHostWithMetadata attempts delivery to a specific SMTP host and returns delivery metadata
func (h *SMTPDeliveryHandler) attemptDeliveryToHostWithMetadata(ctx context.Context, host string, msg Message, recipients []string, content []byte, requireTLS bool, domain string) (string, string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Determine port (try 25, fallback ports)
	ports := []string{"25", "587", "2525"}

	var lastError error
	for _, port := range ports {
		address := net.JoinHostPort(host, port)

		ip, hostIP, err := h.deliverToAddressWithMetadata(ctx, address, msg, recipients, content, requireTLS, domain, host)
		if err != nil {
			h.logger.Debug("Delivery attempt failed",
				"address", address,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, hostIP, nil
	}

	return "", "", fmt.Errorf("delivery failed to all ports for host %s: %w", host, lastError)
}

// deliverToAddressWithMetadata performs the actual SMTP delivery to a specific address and returns delivery metadata
func (h *SMTPDeliveryHandler) deliverToAddressWithMetadata(ctx context.Context, address string, msg Message, recipients []string, content []byte, requireTLS bool, domain string, mxHost string) (string, string, error) {
	h.logger.Debug("Attempting SMTP delivery",
		"address", address,
		"from", msg.From,
		"recipients", recipients,
		"require_tls", requireTLS)

	// Connect to SMTP server and capture connection info
	client, conn, tlsUsed, err := h.connectSMTPWithMetadata(ctx, address, requireTLS)
	if err != nil {
		return "", "", fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() { _ = client.Close() }()

	// Enforce the domain's MTA-STS policy (if any) now that we know whether TLS was used
	if err := h.mtastsManager.EnforcePolicy(ctx, domain, mxHost, tlsUsed); err != nil {
		return "", "", fmt.Errorf("MTA-STS policy check failed for %s: %w", domain, err)
	}

	// Set sender (strip angle brackets if present to avoid parameter issues)
	sender := strings.Trim(msg.From, "<>")

	// Use the Text() method to get the underlying textproto connection
	// and send raw MAIL FROM without ESMTP extensions
	text := client.Text
	if text == nil {
		// Fallback to standard Mail() if we can't get the text connection
		if err := client.Mail(sender); err != nil {
			return "", "", fmt.Errorf("MAIL FROM failed: %w", err)
		}
	} else {
		// Send raw MAIL FROM command without SIZE or other extensions
		id, err := text.Cmd("MAIL FROM:<%s>", sender)
		if err != nil {
			return "", "", fmt.Errorf("MAIL FROM command failed: %w", err)
		}
		text.StartResponse(id)
		_, _, err = text.ReadResponse(250)
		text.EndResponse(id)
		if err != nil {
			return "", "", fmt.Errorf("MAIL FROM failed: %w", err)
		}
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return "", "", fmt.Errorf("RCPT TO failed for %s: %w", recipient, err)
		}
	}

	// Send message data
	writer, err := client.Data()
	if err != nil {
		return "", "", fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err := writer.Write(content); err != nil {
		return "", "", fmt.Errorf("failed to write message data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close data writer: %w", err)
	}

	// Quit gracefully
	if err := client.Quit(); err != nil {
		h.logger.Warn("QUIT command failed", "error", err)
	}

	h.logger.Info("SMTP delivery successful",
		"address", address,
		"from", msg.From,
		"recipients", len(recipients),
		"tls_used", tlsUsed)

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

	return deliveryIP, deliveryHost, nil
}

// connectSMTPWithMetadata establishes a connection to the SMTP server and returns connection metadata
// along with whether the connection is protected by TLS.
func (h *SMTPDeliveryHandler) connectSMTPWithMetadata(ctx context.Context, address string, requireTLS bool) (*smtp.Client, net.Conn, bool, error) {
	// Create dialer with context support
	dialer := &net.Dialer{
		Timeout: h.timeout,
	}

	// Dial with context
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	// Extract hostname for TLS verification
	host := strings.Split(address, ":")[0]

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // Ignore error on cleanup in error path
		return nil, nil, false, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send EHLO/HELO
	hostname := "localhost"
	if err := client.Hello(hostname); err != nil {
		_ = client.Close() // Ignore error on cleanup in error path
		return nil, nil, false, fmt.Errorf("HELLO command failed: %w", err)
	}

	// Always attempt STARTTLS opportunistically; requireTLS additionally makes it mandatory.
	tlsUsed := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(h.outboundTLSConfig(host)); err != nil {
			if requireTLS {
				_ = client.Close()
				return nil, nil, false, fmt.Errorf("STARTTLS required but failed: %w", err)
			}
			// For opportunistic TLS, log the failure but continue in plaintext
			h.logger.Warn("Opportunistic STARTTLS failed, continuing in plaintext",
				"address", address,
				"error", err)
		} else {
			// smtp.Client.StartTLS already re-sends EHLO internally per RFC 3207;
			// calling client.Hello again here would always fail since Hello was
			// already called above.
			tlsUsed = true
			h.logger.Debug("STARTTLS negotiated successfully", "address", address)
		}
	} else if requireTLS {
		_ = client.Close()
		return nil, nil, false, fmt.Errorf("STARTTLS required but not supported by server")
	}

	return client, conn, tlsUsed, nil
}

// outboundTLSConfig builds the TLS config for STARTTLS with the given server name.
// If a template was injected (e.g. by tests or future operator config), it is cloned
// and given the per-host ServerName; otherwise secure defaults are used.
func (h *SMTPDeliveryHandler) outboundTLSConfig(host string) *tls.Config {
	if h.tlsConfig != nil {
		cfg := h.tlsConfig.Clone()
		cfg.ServerName = host
		return cfg
	}
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (h *SMTPDeliveryHandler) GetFailedQueueRetentionHours() int {
	return h.failedQueueRetentionHours
}

// MockDeliveryHandler implements DeliveryHandler for testing
type MockDeliveryHandler struct {
	logger                    *slog.Logger
	shouldFail                bool
	deliveries                []Message
	mutex                     sync.Mutex
	failedQueueRetentionHours int
}

// NewMockDeliveryHandler creates a new mock delivery handler for testing
func NewMockDeliveryHandler(failedQueueRetentionHours int) *MockDeliveryHandler {
	return &MockDeliveryHandler{
		logger:                    slog.Default().With("component", "mock-delivery"),
		deliveries:                make([]Message, 0),
		failedQueueRetentionHours: failedQueueRetentionHours,
	}
}

// TemporaryError represents a temporary failure that should be retried
type TemporaryError struct {
	msg string
}

func (e *TemporaryError) Error() string {
	return e.msg
}

func (e *TemporaryError) Temporary() bool {
	return true
}

// DeliverMessage simulates message delivery
func (m *MockDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := m.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata simulates message delivery and returns delivery metadata
func (m *MockDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.shouldFail {
		return &DeliveryResult{
			Success:         false,
			Error:           &TemporaryError{msg: "mock delivery failure"},
			DeliveryTime:    time.Now(),
			ResponseMessage: "mock delivery failed",
		}, &TemporaryError{msg: "mock delivery failure"}
	}

	// Simulate network delay
	select {
	case <-ctx.Done():
		return &DeliveryResult{
			Success:         false,
			Error:           ctx.Err(),
			DeliveryTime:    time.Now(),
			ResponseMessage: "context cancelled",
		}, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	m.deliveries = append(m.deliveries, msg)
	m.logger.Info("Mock delivery successful", "message_id", msg.ID)

	return &DeliveryResult{
		Success:         true,
		Error:           nil,
		DeliveryIP:      "127.0.0.1",
		DeliveryHost:    "localhost",
		DeliveryTime:    time.Now(),
		ResponseMessage: "mock delivery successful",
	}, nil
}

// SetShouldFail configures the mock to fail deliveries
func (m *MockDeliveryHandler) SetShouldFail(fail bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldFail = fail
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (m *MockDeliveryHandler) GetFailedQueueRetentionHours() int {
	return m.failedQueueRetentionHours
}

// GetDeliveries returns all delivered messages
func (m *MockDeliveryHandler) GetDeliveries() []Message {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	result := make([]Message, len(m.deliveries))
	copy(result, m.deliveries)
	return result
}

// Reset clears all delivery history
func (m *MockDeliveryHandler) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.deliveries = m.deliveries[:0]
}
