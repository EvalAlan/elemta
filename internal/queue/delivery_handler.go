package queue

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"sort"
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

type mxResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// PermanentError marks a delivery failure that must not be retried.
type PermanentError struct {
	msg string
	err error
}

func (e *PermanentError) Error() string   { return e.msg }
func (e *PermanentError) Unwrap() error   { return e.err }
func (e *PermanentError) Permanent() bool { return true }

// newRequireTLSError reports an RFC 8689 delivery failure as permanent so the
// processor bounces it rather than retrying insecurely.
func newRequireTLSError(format string, args ...interface{}) *PermanentError {
	return &PermanentError{msg: "550 5.7.30 REQUIRETLS: " + fmt.Sprintf(format, args...)}
}

func smtpFailureOutcome(err error) (RecipientDeliveryStatus, string, string) {
	status := RecipientTemporaryFailure
	var smtpErr *textproto.Error
	if errors.As(err, &smtpErr) && smtpErr.Code >= 500 && smtpErr.Code < 600 {
		status = RecipientPermanentFailure
	}
	diagnostic := err.Error()
	enhanced := enhancedStatus(diagnostic)
	return status, enhanced, diagnostic
}

type domainFailure struct {
	domain string
	err    error
}

// domainFailuresError preserves the aggregate retry classification without
// exposing individual permanent errors through Unwrap. A mixed aggregate must
// remain temporary even when one of its constituent failures is permanent.
type domainFailuresError struct {
	message   string
	permanent bool
}

func (e *domainFailuresError) Error() string   { return e.message }
func (e *domainFailuresError) Permanent() bool { return e.permanent }
func (e *domainFailuresError) Temporary() bool { return !e.permanent }

func aggregateDomainFailures(failures []domainFailure) error {
	if len(failures) == 0 {
		return nil
	}
	ordered := append([]domainFailure(nil), failures...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].domain < ordered[j].domain })

	allPermanent := true
	parts := make([]string, 0, len(ordered))
	classifier := &Processor{}
	for _, failure := range ordered {
		parts = append(parts, fmt.Sprintf("%s: %v", failure.domain, failure.err))
		if classifier.isTemporaryFailure(failure.err) {
			allPermanent = false
		}
	}
	return &domainFailuresError{
		message:   "delivery failures: " + strings.Join(parts, "; "),
		permanent: allPermanent,
	}
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
	resolver                  mxResolver
	dialContext               func(context.Context, string, string) (net.Conn, error)
	mxRetrySleep              func(context.Context, time.Duration) error
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
		resolver:                  net.DefaultResolver,
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

	domains := make([]string, 0, len(domainGroups))
	for domain := range domainGroups {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	var failures []domainFailure
	delivered := 0
	var outcomes []RecipientOutcome
	var firstSuccessfulIP string
	var firstSuccessfulHost string

	for _, domain := range domains {
		recipients := domainGroups[domain]
		ip, host, domainOutcomes, err := h.deliverToDomainWithMetadata(ctx, msg, domain, recipients, content, requireTLS)
		if len(domainOutcomes) > 0 {
			outcomes = append(outcomes, domainOutcomes...)
			for _, outcome := range domainOutcomes {
				if outcome.Status == RecipientDelivered {
					delivered++
				}
			}
		}
		if err != nil {
			h.logger.Error("Failed to deliver to domain",
				"domain", domain,
				"recipients", recipients,
				"error", err)
			failures = append(failures, domainFailure{domain: domain, err: err})
			status := RecipientTemporaryFailure
			if !(&Processor{}).isTemporaryFailure(err) {
				status = RecipientPermanentFailure
			}
			for _, recipient := range recipients[len(domainOutcomes):] {
				outcomes = append(outcomes, RecipientOutcome{Recipient: recipient, Status: status, Diagnostic: err.Error(), Route: domain})
			}
		} else {
			if len(domainOutcomes) == 0 {
				delivered += len(recipients)
			}
			for _, recipient := range recipients[len(domainOutcomes):] {
				outcomes = append(outcomes, RecipientOutcome{Recipient: recipient, Status: RecipientDelivered, Route: host})
			}
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

	result, err := h.buildDeliveryResult(msg.To, delivered, firstSuccessfulIP, firstSuccessfulHost, aggregateDomainFailures(failures))
	result.RecipientOutcomes = outcomes
	return result, err
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
		result.Error = fmt.Errorf("partial delivery: %d/%d recipients delivered: %w",
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
func (h *SMTPDeliveryHandler) deliverToDomainWithMetadata(ctx context.Context, msg Message, domain string, recipients []string, content []byte, requireTLS bool) (string, string, []RecipientOutcome, error) {
	// Look up MX records for the domain
	mxRecords, err := h.lookupMX(ctx, domain)
	if err != nil {
		return "", "", nil, fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return "", "", nil, fmt.Errorf("no MX records found for domain %s", domain)
	}

	// Try each MX record in order of preference
	var lastError error
	for _, mx := range mxRecords {
		ip, host, hostOutcomes, err := h.attemptDeliveryToHostWithMetadata(ctx, mx.Host, msg, recipients, content, requireTLS, domain)
		if len(hostOutcomes) > 0 {
			return ip, host, hostOutcomes, err
		}
		if err != nil {
			h.logger.Warn("Delivery failed to MX host",
				"host", mx.Host,
				"priority", mx.Pref,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, host, nil, nil
	}

	return "", "", nil, fmt.Errorf("delivery failed to all MX hosts for domain %s: %w", domain, lastError)
}

// lookupMX performs MX record lookup with retries
func (h *SMTPDeliveryHandler) lookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	var mxRecords []*net.MX
	var err error

	for attempt := 0; attempt < h.maxMXLookups; attempt++ {
		resolver := h.resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		mxRecords, err = resolver.LookupMX(ctx, domain)
		if err == nil {
			break
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, &PermanentError{msg: fmt.Sprintf("domain %s does not exist: %v", domain, err), err: err}
		}

		h.logger.Debug("MX lookup attempt failed",
			"domain", domain,
			"attempt", attempt+1,
			"error", err)
		if attempt+1 == h.maxMXLookups {
			break
		}

		// Wait before retry (with an injectable seam for deterministic tests).
		sleep := h.mxRetrySleep
		if sleep == nil {
			sleep = func(ctx context.Context, delay time.Duration) error {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			}
		}
		if sleepErr := sleep(ctx, time.Duration(attempt+1)*time.Second); sleepErr != nil {
			return nil, sleepErr
		}
	}

	if err != nil {
		return nil, err
	}
	// RFC 5321 section 5.1: an empty, successful answer means the domain
	// itself is the implicit MX. It is not equivalent to NXDOMAIN.
	if len(mxRecords) == 0 {
		return []*net.MX{{Host: domain, Pref: 0}}, nil
	}
	// Copy resolver-owned storage before filtering or sorting it.
	mxRecords = append([]*net.MX(nil), mxRecords...)
	if len(mxRecords) == 1 && mxRecords[0].Host == "." && mxRecords[0].Pref == 0 {
		return nil, &PermanentError{msg: fmt.Sprintf("domain %s accepts no mail (Null MX)", domain)}
	}

	// A dot is only authoritative as the sole preference-zero record. Ignore it
	// when usable MX records exist. If it is the only malformed record, defer
	// rather than permanently rejecting mail or attempting to dial the root.
	usable := mxRecords[:0]
	for _, mx := range mxRecords {
		if mx.Host != "." {
			usable = append(usable, mx)
		}
	}
	if len(usable) == 0 {
		return nil, &TemporaryError{msg: fmt.Sprintf("domain %s returned malformed Null MX", domain)}
	}
	sort.SliceStable(usable, func(i, j int) bool { return usable[i].Pref < usable[j].Pref })
	return usable, nil
}

// attemptDeliveryToHostWithMetadata attempts delivery to a specific SMTP host and returns delivery metadata
func (h *SMTPDeliveryHandler) attemptDeliveryToHostWithMetadata(ctx context.Context, host string, msg Message, recipients []string, content []byte, requireTLS bool, domain string) (string, string, []RecipientOutcome, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Determine port (try 25, fallback ports)
	ports := []string{"25", "587", "2525"}

	var lastError error
	for _, port := range ports {
		address := net.JoinHostPort(host, port)

		ip, hostIP, outcomes, err := h.deliverToAddressWithMetadata(ctx, address, msg, recipients, content, requireTLS, domain, host)
		if len(outcomes) > 0 {
			return ip, hostIP, outcomes, err
		}
		if err != nil {
			h.logger.Debug("Delivery attempt failed",
				"address", address,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, hostIP, nil, nil
	}

	return "", "", nil, fmt.Errorf("delivery failed to all ports for host %s: %w", host, lastError)
}

// deliverToAddressWithMetadata performs the actual SMTP delivery to a specific address and returns delivery metadata
func (h *SMTPDeliveryHandler) deliverToAddressWithMetadata(ctx context.Context, address string, msg Message, recipients []string, content []byte, requireTLS bool, domain string, mxHost string) (string, string, []RecipientOutcome, error) {
	h.logger.Debug("Attempting SMTP delivery",
		"address", address,
		"from", msg.From,
		"recipients", recipients,
		"require_tls", requireTLS)

	client, conn, tlsUsed, nextHopRequireTLS, err := h.connectSMTPWithRequireTLS(ctx, address, requireTLS)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() { _ = client.Close() }()

	// REQUIRETLS is stricter than MTA-STS: it already mandates verified TLS and
	// next-hop support, so do not apply the overlapping policy a second time.
	if !requireTLS {
		if err := h.mtastsManager.EnforcePolicy(ctx, domain, mxHost, tlsUsed); err != nil {
			return "", "", nil, fmt.Errorf("MTA-STS policy check failed for %s: %w", domain, err)
		}
	}

	sender := strings.Trim(msg.From, "<>")
	text := client.Text
	if text == nil {
		if requireTLS {
			return "", "", nil, newRequireTLSError("cannot send MAIL FROM with REQUIRETLS parameter: no text connection available")
		}
		if err := client.Mail(sender); err != nil {
			return "", "", nil, fmt.Errorf("MAIL FROM failed: %w", err)
		}
	} else {
		mailFromCmd := "MAIL FROM:<%s>"
		if requireTLS && nextHopRequireTLS {
			mailFromCmd += " REQUIRETLS"
		}
		id, err := text.Cmd(mailFromCmd, sender)
		if err != nil {
			return "", "", nil, fmt.Errorf("MAIL FROM command failed: %w", err)
		}
		text.StartResponse(id)
		_, _, err = text.ReadResponse(250)
		text.EndResponse(id)
		if err != nil {
			return "", "", nil, fmt.Errorf("MAIL FROM failed: %w", err)
		}
	}

	outcomes := make([]RecipientOutcome, 0, len(recipients))
	accepted := make([]int, 0, len(recipients))
	for _, recipient := range recipients {
		outcome := RecipientOutcome{Recipient: recipient, Route: mxHost}
		if err := client.Rcpt(recipient); err != nil {
			outcome.Status, outcome.EnhancedStatusCode, outcome.Diagnostic = smtpFailureOutcome(err)
		} else {
			outcome.Status = RecipientDelivered // provisional until DATA completes
			accepted = append(accepted, len(outcomes))
		}
		outcomes = append(outcomes, outcome)
	}

	var dataErr error
	if len(accepted) > 0 {
		writer, err := client.Data()
		if err == nil {
			_, err = writer.Write(content)
			if err == nil {
				err = writer.Close()
			}
		}
		dataErr = err
		if dataErr != nil {
			status, enhanced, diagnostic := smtpFailureOutcome(dataErr)
			for _, i := range accepted {
				outcomes[i].Status = status
				outcomes[i].EnhancedStatusCode = enhanced
				outcomes[i].Diagnostic = diagnostic
			}
		}
	}

	_ = client.Quit()
	deliveryIP, deliveryHost := "", ""
	if conn != nil {
		remoteAddr := conn.RemoteAddr().String()
		deliveryIP = remoteAddr
		if host, _, splitErr := net.SplitHostPort(remoteAddr); splitErr == nil {
			deliveryIP, deliveryHost = host, host
		} else {
			deliveryHost = remoteAddr
		}
	}

	var temporary, permanent int
	for _, outcome := range outcomes {
		switch outcome.Status {
		case RecipientTemporaryFailure:
			temporary++
		case RecipientPermanentFailure:
			permanent++
		}
	}
	if temporary+permanent > 0 {
		err := error(&TemporaryError{msg: "one or more SMTP recipients temporarily failed"})
		if temporary == 0 {
			err = &PermanentError{msg: "all SMTP recipients permanently failed"}
		}
		return deliveryIP, deliveryHost, outcomes, err
	}
	return deliveryIP, deliveryHost, outcomes, nil
}

// connectSMTPWithRequireTLS establishes an SMTP connection and reports whether
// the next hop advertised REQUIRETLS after STARTTLS.
func (h *SMTPDeliveryHandler) connectSMTPWithRequireTLS(ctx context.Context, address string, requireTLS bool) (*smtp.Client, net.Conn, bool, bool, error) {
	// Use an injected dial function in tests; production uses a bounded net.Dialer.
	dial := h.dialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: h.timeout}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	// Extract hostname for TLS verification
	host := strings.Split(address, ":")[0]

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // Ignore error on cleanup in error path
		return nil, nil, false, false, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send EHLO/HELO
	hostname := "localhost"
	if err := client.Hello(hostname); err != nil {
		_ = client.Close() // Ignore error on cleanup in error path
		return nil, nil, false, false, fmt.Errorf("HELLO command failed: %w", err)
	}

	// Always attempt STARTTLS opportunistically; requireTLS additionally makes it mandatory.
	tlsUsed := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(h.outboundTLSConfig(host)); err != nil {
			if requireTLS {
				_ = client.Close()
				return nil, nil, false, false, newRequireTLSError("STARTTLS required but failed against %s: %v", address, err)
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
		return nil, nil, false, false, newRequireTLSError("STARTTLS required but not supported by server %s", address)
	}

	nextHopSupportsRequireTLS, _ := client.Extension("REQUIRETLS")
	if requireTLS && !nextHopSupportsRequireTLS {
		_ = client.Close()
		return nil, nil, false, false, newRequireTLSError("next-hop %s does not advertise REQUIRETLS", address)
	}

	return client, conn, tlsUsed, nextHopSupportsRequireTLS, nil
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
		outcomes := make([]RecipientOutcome, 0, len(msg.To))
		for _, recipient := range msg.To {
			outcomes = append(outcomes, RecipientOutcome{Recipient: recipient, Status: RecipientTemporaryFailure, Diagnostic: "mock delivery failure"})
		}
		return &DeliveryResult{
			Success:           false,
			Error:             &TemporaryError{msg: "mock delivery failure"},
			DeliveryTime:      time.Now(),
			ResponseMessage:   "mock delivery failed",
			RecipientOutcomes: outcomes,
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

	outcomes := make([]RecipientOutcome, 0, len(msg.To))
	for _, recipient := range msg.To {
		outcomes = append(outcomes, RecipientOutcome{Recipient: recipient, Status: RecipientDelivered, Route: "localhost"})
	}
	return &DeliveryResult{
		Success:           true,
		Error:             nil,
		DeliveryIP:        "127.0.0.1",
		DeliveryHost:      "localhost",
		DeliveryTime:      time.Now(),
		ResponseMessage:   "mock delivery successful",
		RecipientOutcomes: outcomes,
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
