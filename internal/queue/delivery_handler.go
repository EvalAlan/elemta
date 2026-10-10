package queue

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/delivery"
	"github.com/EvalAlan/elemta/internal/dkim"
	"github.com/EvalAlan/elemta/internal/tlsrpt"
)

// messageSigner signs outbound message content for a given signing domain.
// Satisfied by *dkim.Signer; abstracted so tests can inject a stub. A nil
// signer means signing is disabled and content passes through unchanged.
type messageSigner interface {
	Sign(content []byte, signingDomain string) ([]byte, error)
}

// ARCSealer adds an RFC 8617 set after DKIM signing and before remote SMTP
// delivery. Exported so the SMTP server can attach the built-in plugin while
// tests can supply a stub.
type ARCSealer interface {
	Seal(ctx context.Context, message []byte, authResults string) ([]byte, error)
}

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
	// shaper applies per-destination connection and rate limits, and the
	// backoff a destination asks for by deferring. Nil means unshaped.
	shaper       *Shaper
	mxRetrySleep func(context.Context, time.Duration) error
	signerMu     sync.RWMutex
	signer       messageSigner // optional DKIM signer; nil = signing disabled. Guarded by signerMu: config reload swaps it during deliveries.
	arcSealer    ARCSealer     // optional ARC sealer; nil = sealing disabled

	// heloName is the name sent in EHLO; see SetHeloHostname.
	heloName string
	// mxPort is the port MX hosts are contacted on. Always 25 in production
	// (RFC 5321 §4.5.4.2 has no fallback); tests point it elsewhere.
	mxPort string
	// sessions parks finished outbound sessions for the next message to the
	// same MX address; see session_cache.go. Nil disables reuse.
	sessions *sessionCache
	// tlsReports counts TLS outcomes per recipient domain for TLS-RPT
	// (RFC 8460). Nil disables counting.
	tlsReports TLSReportRecorder
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
		// MX lookups go through a short-lived cache. Draining a queue to one
		// domain used to re-resolve for every message.
		resolver: newCachingMXResolver(net.DefaultResolver, defaultMXCacheTTL, defaultMXCacheSize),
		sessions: newSessionCache(),
	}
}

// SetHeloHostname sets the name announced in EHLO. It should be this server's
// public hostname, with forward and reverse DNS that agree: receivers score
// "EHLO localhost" as a spam signal (Rspamd's HFILTER_HELO_* and Spamhaus
// policy both do), and some refuse it outright.
func (h *SMTPDeliveryHandler) SetHeloHostname(name string) {
	h.heloName = strings.TrimSpace(name)
}

func (h *SMTPDeliveryHandler) ehloName() string {
	if h.heloName != "" {
		return h.heloName
	}
	if name, err := os.Hostname(); err == nil && strings.Contains(name, ".") {
		return name
	}
	return "localhost"
}

// SetDKIMSigner attaches a DKIM signer to the handler. A nil signer leaves
// signing disabled. Kept as an explicit setter so signing can be wired in from
// the server without changing the constructor signature.
func (h *SMTPDeliveryHandler) SetDKIMSigner(s *dkim.Signer) {
	// Store as nil interface when the concrete pointer is nil so the interface
	// comparison `h.signer == nil` in signContent works correctly.
	h.signerMu.Lock()
	defer h.signerMu.Unlock()
	if s == nil {
		h.signer = nil
		return
	}
	h.signer = s
}

func (h *SMTPDeliveryHandler) currentSigner() messageSigner {
	h.signerMu.RLock()
	defer h.signerMu.RUnlock()
	return h.signer
}

// SetARCSealer attaches the built-in ARC plugin to remote SMTP delivery.
func (h *SMTPDeliveryHandler) SetARCSealer(sealer ARCSealer) {
	h.arcSealer = sealer
}

// authenticationResultsValue returns the unfolded value of the first
// Authentication-Results header, which is what this hop records in the ARC set
// it adds. Only that header counts: ARC-Authentication-Results carries an
// earlier hop's opinion, and sealing it as our own would launder somebody
// else's verdict into ours.
func authenticationResultsValue(content []byte) string {
	headerEnd := bytes.Index(content, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return ""
	}
	lines := strings.Split(string(content[:headerEnd]), "\r\n")
	var value strings.Builder
	found := false
	for _, line := range lines {
		if !found {
			if strings.HasPrefix(strings.ToLower(line), "authentication-results:") {
				value.WriteString(strings.TrimSpace(line[len("Authentication-Results:"):]))
				found = true
			}
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			value.WriteByte(' ')
			value.WriteString(strings.TrimSpace(line))
			continue
		}
		break
	}
	return value.String()
}

// signContent applies DKIM signing to the message before delivery. Signing
// happens once here — before recipients are grouped by domain — so the same
// signed bytes are delivered to every MX and a message is never signed
// per-domain. The signing domain is the envelope-from domain, falling back to
// the From header domain when the envelope-from is empty (e.g. bounces).
//
// Each queue attempt starts from the original stored content, so retries receive
// one fresh signature without trusting message-supplied DKIM headers. If signing
// is configured for the message domain, a signing error fails the delivery
// attempt rather than silently downgrading it to unsigned mail.
func (h *SMTPDeliveryHandler) signContent(msg Message, content []byte) ([]byte, error) {
	signer := h.currentSigner()
	if signer == nil {
		return content, nil
	}

	signingDomain := dkim.DomainFromAddress(msg.From)
	if signingDomain == "" {
		signingDomain = dkim.FromHeaderDomain(content)
	}
	if signingDomain == "" {
		h.logger.Debug("No signing domain resolved for message, delivering unsigned", "message_id", msg.ID)
		return content, nil
	}

	signed, err := signer.Sign(content, signingDomain)
	if err != nil {
		return nil, fmt.Errorf("dkim signing failed for message %q and domain %q: %w", msg.ID, signingDomain, err)
	}
	return signed, nil
}

// DeliverMessage attempts to deliver a message via SMTP
func (h *SMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata attempts to deliver a message via SMTP and returns delivery metadata.
//
// See the LMTP handler: the transport is stamped once here rather than at every
// place a result is constructed.
func (h *SMTPDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	result, err := h.deliverWithMetadata(ctx, msg, content)
	// A handler that failed before it could build a result still knows which
	// transport it was: "which route failed" is the first thing an operator
	// asks, and a connection refused at the first hop is exactly when they ask.
	if result == nil {
		result = &DeliveryResult{Error: err}
	}
	if result.DeliveryMethod == "" {
		result.DeliveryMethod = DeliveryMethodSMTP
	}
	return result, err
}

func (h *SMTPDeliveryHandler) deliverWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	requireTLS := messageRequiresTLS(msg)

	// DKIM-sign once per delivery attempt, before recipients are grouped, so
	// identical signed bytes go to every MX. A configured-domain signing failure
	// aborts this attempt; the queue processor treats unknown delivery errors as
	// temporary and retries from the original stored content.
	var err error
	content, err = h.signContent(msg, content)
	if err != nil {
		return nil, err
	}
	// Sealing happens after signing: the ARC-Message-Signature must cover the
	// DKIM-Signature this hop just added, or a downstream verifier would see a
	// signature the chain does not account for.
	if h.arcSealer != nil {
		content, err = h.arcSealer.Seal(ctx, content, authenticationResultsValue(content))
		if err != nil {
			return nil, err
		}
	}

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
			// A temporary failure is the destination asking us to slow down, so
			// back off from it — and only from it. A permanent one is about the
			// message or the recipient and says nothing about pace; backing off
			// on those would slow a queue because one address does not exist.
			// A refusal we caused ourselves by backing off is not new news.
			if h.shaper != nil && status == RecipientTemporaryFailure && !errors.Is(err, ErrDestinationBackingOff) {
				backoff := h.shaper.ReportDeferral(domain)
				h.logger.Info("Backing off from a destination that deferred",
					"event_type", "traffic_shaping",
					"domain", domain, "backoff", backoff.String())
			}
			// Counted but never a reason to slow down: a domain that accepts
			// everything and bounces most of it is a deliverability problem,
			// not a pace problem.
			if h.shaper != nil && status == RecipientPermanentFailure {
				h.shaper.ReportPermanentFailure(domain)
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
			// One delivery is enough to clear a backoff: the destination is
			// evidently willing again, and holding the pause after that slows
			// the queue for no reason.
			if h.shaper != nil {
				h.shaper.ReportSuccess(domain)
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
// SetShaper attaches per-destination traffic shaping.
func (h *SMTPDeliveryHandler) SetShaper(shaper *Shaper) {
	h.shaper = shaper
}

func (h *SMTPDeliveryHandler) deliverToDomainWithMetadata(ctx context.Context, msg Message, domain string, recipients []string, content []byte, requireTLS bool) (string, string, []RecipientOutcome, error) {
	// Take a slot for this destination first. A destination that is backing off
	// refuses here and the message is deferred, rather than a worker sleeping
	// until the destination is ready — one slow receiver would otherwise stall
	// the whole queue behind it.
	if h.shaper != nil {
		release, err := h.shaper.Acquire(ctx, domain)
		if err != nil {
			return "", "", nil, err
		}
		defer release()
	}

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

	// MX delivery is port 25 only. Trying 587 or 2525 when 25 fails reached
	// submission services that require authentication, or something else
	// entirely, and turned a clear "port 25 blocked" into a misleading error.
	port := h.mxPort
	if port == "" {
		port = "25"
	}
	ports := []string{port}

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

	// The session goes back to the cache only if every command in the
	// transaction got a reply. A network error or timeout part way through
	// leaves the protocol state unknown, and the next message must not inherit it.
	var sess *outboundSession
	reusable, clean := false, false
	defer func() {
		if sess == nil {
			return
		}
		if reusable && h.sessions != nil {
			h.sessions.put(address, sess, clean)
			return
		}
		closeSession(sess)
	}()

	sender := strings.Trim(msg.From, "<>")
	// A parked session is not probed before use; probing costs a round trip
	// on every reuse to catch the rare session the receiver dropped. Instead,
	// if MAIL FROM on a reused session gets no reply or a 421 (the receiver
	// closing on us), that session is discarded and the message is tried
	// once more on a new connection.
	for attempt := 0; ; attempt++ {
		var reused bool
		var err error
		sess, reused, err = h.acquireSession(ctx, address, requireTLS, attempt == 0)
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to connect to %s: %w", address, err)
		}

		// REQUIRETLS is stricter than MTA-STS: it already mandates verified TLS and
		// next-hop support, so do not apply the overlapping policy a second time.
		// MTA-STS requires a certificate that validates for the MX host, so only
		// verified TLS counts; an encrypted-but-unverified session does not.
		if !reused {
			h.reportTLS(ctx, domain, mxHost, sess)
		}
		if !requireTLS {
			if err := h.mtastsManager.EnforcePolicy(ctx, domain, mxHost, sess.tls == tlsVerified); err != nil {
				return "", "", nil, fmt.Errorf("MTA-STS policy check failed for %s: %w", domain, err)
			}
		}

		err = sendMailFrom(sess, sender, requireTLS)
		if err == nil {
			break
		}
		if reused && sessionGone(err) {
			h.logger.Debug("Parked SMTP session was closed by the receiver; reconnecting",
				"address", address, "error", err)
			closeSession(sess)
			sess = nil
			continue
		}
		var permErr *PermanentError
		if errors.As(err, &permErr) {
			return "", "", nil, err
		}
		return "", "", nil, fmt.Errorf("MAIL FROM failed: %w", err)
	}
	client, conn := sess.client, sess.conn

	outcomes := make([]RecipientOutcome, 0, len(recipients))
	accepted := make([]int, 0, len(recipients))
	broken := false // a command got no reply; the session cannot be reused
	for _, recipient := range recipients {
		outcome := RecipientOutcome{Recipient: recipient, Route: mxHost}
		if err := client.Rcpt(recipient); err != nil {
			if !isSMTPReply(err) {
				broken = true
			}
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

	reusable = !broken && (dataErr == nil || isSMTPReply(dataErr))
	// After a 250 to the end of data the transaction is over and the session
	// is ready for the next MAIL FROM (RFC 5321 §4.1.1.4). Anything else (no
	// recipient accepted, DATA refused) may leave it open, so it needs RSET.
	clean = len(accepted) > 0 && dataErr == nil
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

// acquireSession returns a parked session to address when one is available
// and allowCached is set, otherwise a newly connected one. reused says which.
func (h *SMTPDeliveryHandler) acquireSession(ctx context.Context, address string, requireTLS, allowCached bool) (*outboundSession, bool, error) {
	if allowCached && h.sessions != nil {
		if s := h.sessions.get(address, requireTLS); s != nil {
			h.logger.Debug("Reusing outbound SMTP session", "address", address, "uses", s.uses)
			return s, true, nil
		}
	}
	var info tlsAttemptInfo
	client, conn, tlsState, nextHopRequireTLS, err := h.connectSMTP(ctx, address, requireTLS, &info)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	return &outboundSession{client: client, conn: conn, tls: tlsState, requireTLS: nextHopRequireTLS,
		starttlsOffered: info.starttlsOffered, verifyErr: info.verifyErr, created: now, idleSince: now}, false, nil
}

// sendMailFrom opens a transaction, adding the REQUIRETLS parameter when the
// message requires it and the next hop supports it.
func sendMailFrom(sess *outboundSession, sender string, requireTLS bool) error {
	text := sess.client.Text
	if text == nil {
		if requireTLS {
			return newRequireTLSError("cannot send MAIL FROM with REQUIRETLS parameter: no text connection available")
		}
		return sess.client.Mail(sender)
	}
	mailFromCmd := "MAIL FROM:<%s>"
	if requireTLS && sess.requireTLS {
		mailFromCmd += " REQUIRETLS"
	}
	id, err := text.Cmd(mailFromCmd, sender)
	if err != nil {
		return err
	}
	text.StartResponse(id)
	defer text.EndResponse(id)
	_, _, err = text.ReadResponse(250)
	return err
}

// sessionGone reports whether err means the receiver has closed the session:
// no reply at all, or 421 (RFC 5321 §3.8, service closing).
func sessionGone(err error) bool {
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		return tpErr.Code == 421
	}
	return true
}

// isSMTPReply reports whether err is the server's reply to a command, as
// opposed to a failure to get one. After a reply, the session is still in
// step and can carry another transaction.
func isSMTPReply(err error) bool {
	var tpErr *textproto.Error
	return errors.As(err, &tpErr)
}

// SetConnectionReuse turns outbound session reuse on or off. It is on by
// default; turning it off closes any parked sessions.
func (h *SMTPDeliveryHandler) SetConnectionReuse(enabled bool) {
	if enabled {
		if h.sessions == nil {
			h.sessions = newSessionCache()
		}
		return
	}
	if h.sessions != nil {
		h.sessions.closeAll()
		h.sessions = nil
	}
}

// CloseIdleSessions closes every parked outbound session. Call at shutdown so
// receivers see a QUIT rather than a dropped connection.
func (h *SMTPDeliveryHandler) CloseIdleSessions() {
	if h.sessions != nil {
		h.sessions.closeAll()
	}
}

// SessionCacheStats reports outbound session reuse; ok is false when reuse is off.
func (h *SMTPDeliveryHandler) SessionCacheStats() (stats SessionCacheStats, ok bool) {
	if h.sessions == nil {
		return SessionCacheStats{}, false
	}
	return h.sessions.stats(), true
}

// TLSReportRecorder receives the TLS outcome of each new outbound session.
type TLSReportRecorder interface {
	Record(tlsrpt.Session)
}

// SetTLSReportRecorder enables TLS-RPT counting.
func (h *SMTPDeliveryHandler) SetTLSReportRecorder(r TLSReportRecorder) {
	h.tlsReports = r
}

// stsPolicySource is implemented by the MTA-STS manager; reporting needs the
// policy itself, not just the enforcement verdict.
type stsPolicySource interface {
	GetPolicy(ctx context.Context, domain string) (*delivery.MTASTSPolicy, error)
}

// reportTLS records a newly negotiated session against the recipient
// domain's policy. Sessions are counted once, when they are set up: a reused
// session carries the same TLS as when it was counted.
func (h *SMTPDeliveryHandler) reportTLS(ctx context.Context, domain, mxHost string, sess *outboundSession) {
	if h.tlsReports == nil {
		return
	}
	rec := tlsrpt.Session{
		Policy:      tlsrpt.Policy{Type: tlsrpt.PolicyTypeNoPolicy, Domain: domain},
		ReceivingMX: strings.TrimSuffix(mxHost, "."),
	}
	if sess.conn != nil {
		rec.SendingIP = addrIP(sess.conn.LocalAddr())
		rec.ReceivingIP = addrIP(sess.conn.RemoteAddr())
	}

	var policy *delivery.MTASTSPolicy
	if src, ok := h.mtastsManager.(stsPolicySource); ok {
		policy, _ = src.GetPolicy(ctx, domain)
	}
	if policy != nil && policy.Mode != "none" {
		rec.Policy = tlsrpt.Policy{
			Type:    tlsrpt.PolicyTypeSTS,
			Domain:  domain,
			Strings: stsPolicyStrings(policy),
			MXHosts: append([]string(nil), policy.MX...),
		}
	}

	switch {
	case sess.tls == tlsNone && !sess.starttlsOffered:
		rec.ResultType = tlsrpt.ResultStartTLSNotSupported
	case sess.tls == tlsNone:
		// Offered STARTTLS, but no handshake succeeded even unverified.
		rec.ResultType = tlsrpt.ResultValidationFailure
		if sess.verifyErr != nil {
			rec.FailureReason = sess.verifyErr.Error()
		}
	case rec.Policy.Type == tlsrpt.PolicyTypeNoPolicy:
		// Without a policy, any encryption is what was asked for.
		rec.Success = true
	case !policy.MatchesMX(mxHost):
		rec.ResultType = tlsrpt.ResultValidationFailure
		rec.FailureReason = "mx host not listed in MTA-STS policy"
	case sess.tls == tlsVerified:
		rec.Success = true
	default:
		rec.ResultType = tlsrpt.ClassifyCertError(sess.verifyErr)
	}
	h.tlsReports.Record(rec)
}

// stsPolicyStrings renders a policy as the lines it was published as.
func stsPolicyStrings(p *delivery.MTASTSPolicy) []string {
	out := []string{"version: " + p.Version, "mode: " + p.Mode}
	for _, mx := range p.MX {
		out = append(out, "mx: "+mx)
	}
	return append(out, fmt.Sprintf("max_age: %d", p.MaxAge))
}

func addrIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}

// outboundTLS records what protection a delivery connection ended up with.
type outboundTLS int

const (
	tlsNone       outboundTLS = iota // plaintext
	tlsUnverified                    // encrypted, certificate not validated
	tlsVerified                      // encrypted, certificate valid for the MX host
)

// tlsAttemptInfo records how TLS negotiation went, for TLS reporting: whether
// the receiver offered STARTTLS, and why a verified handshake failed.
type tlsAttemptInfo struct {
	starttlsOffered bool
	verifyErr       error
}

// connectSMTP connects to address and negotiates the best TLS it can.
//
// Opportunistic TLS (RFC 7435) tries, in order: STARTTLS with a certificate
// that validates for the MX host; STARTTLS without validation; plaintext.
// Each fallback is a fresh connection. A failed TLS handshake leaves the
// session unusable, so the old code's "continue in plaintext" on the same
// connection could never deliver, and since most MX certificates do not
// validate for the MX name, that turned into deferring mail to a large share
// of the internet. Unverified encryption still defeats passive interception,
// which is what opportunistic TLS is for; MTA-STS and REQUIRETLS, which need
// validation, are told which one was achieved.
//
// info, when non-nil, is filled with what TLS reporting needs to know.
func (h *SMTPDeliveryHandler) connectSMTP(ctx context.Context, address string, requireTLS bool, info *tlsAttemptInfo) (*smtp.Client, net.Conn, outboundTLS, bool, error) {
	if info == nil {
		info = &tlsAttemptInfo{}
	}
	host := address
	if hostOnly, _, err := net.SplitHostPort(address); err == nil {
		host = hostOnly
	}

	client, conn, err := h.dialAndGreet(ctx, address)
	if err != nil {
		return nil, nil, tlsNone, false, err
	}

	state := tlsNone
	if ok, _ := client.Extension("STARTTLS"); ok {
		info.starttlsOffered = true
		if err := client.StartTLS(h.outboundTLSConfig(host)); err == nil {
			state = tlsVerified
			h.logger.Debug("STARTTLS negotiated with a verified certificate", "address", address)
		} else {
			info.verifyErr = err
			_ = client.Close()
			if requireTLS {
				return nil, nil, tlsNone, false, newRequireTLSError("STARTTLS required but failed against %s: %v", address, err)
			}
			h.logger.Info("MX certificate did not validate; retrying with unverified TLS",
				"address", address, "error", err)
			client, conn, state, err = h.reconnectOpportunistic(ctx, address, host, !requireTLS)
			if err != nil {
				return nil, nil, tlsNone, false, err
			}
		}
	} else if requireTLS {
		_ = client.Close()
		return nil, nil, tlsNone, false, newRequireTLSError("STARTTLS required but not supported by server %s", address)
	}

	nextHopSupportsRequireTLS, _ := client.Extension("REQUIRETLS")
	if requireTLS && !nextHopSupportsRequireTLS {
		_ = client.Close()
		return nil, nil, tlsNone, false, newRequireTLSError("next-hop %s does not advertise REQUIRETLS", address)
	}

	return client, conn, state, nextHopSupportsRequireTLS, nil
}

// reconnectOpportunistic is the fallback after a certificate failed to
// validate: unverified TLS on a new connection, then plaintext on another.
//
// allowUnverified is false whenever the message requires TLS (REQUIRETLS);
// the caller never reaches here in that case, and the guard keeps it so.
func (h *SMTPDeliveryHandler) reconnectOpportunistic(ctx context.Context, address, host string, allowUnverified bool) (*smtp.Client, net.Conn, outboundTLS, error) {
	client, conn, err := h.dialAndGreet(ctx, address)
	if err != nil {
		return nil, nil, tlsNone, err
	}
	if ok, _ := client.Extension("STARTTLS"); ok && allowUnverified {
		cfg := h.outboundTLSConfig(host)
		// #nosec G402 -- opportunistic TLS (RFC 7435): encryption without
		// authentication still defeats passive interception. Callers that need
		// a validated certificate (MTA-STS, REQUIRETLS) are told it is unverified.
		cfg.InsecureSkipVerify = allowUnverified
		if err := client.StartTLS(cfg); err == nil {
			return client, conn, tlsUnverified, nil
		}
		_ = client.Close()
		h.logger.Warn("STARTTLS failed even without certificate validation; delivering in plaintext",
			"address", address, "error", err)
		client, conn, err = h.dialAndGreet(ctx, address)
		if err != nil {
			return nil, nil, tlsNone, err
		}
	}
	return client, conn, tlsNone, nil
}

// dialAndGreet opens a connection and sends EHLO.
func (h *SMTPDeliveryHandler) dialAndGreet(ctx context.Context, address string) (*smtp.Client, net.Conn, error) {
	// Use an injected dial function in tests; production uses a bounded net.Dialer.
	dial := h.dialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: h.timeout}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	host := address
	if hostOnly, _, err := net.SplitHostPort(address); err == nil {
		host = hostOnly
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // Ignore error on cleanup in error path
		return nil, nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}
	if err := client.Hello(h.ehloName()); err != nil {
		_ = client.Close() // Ignore error on cleanup in error path
		return nil, nil, fmt.Errorf("HELLO command failed: %w", err)
	}
	return client, conn, nil
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
