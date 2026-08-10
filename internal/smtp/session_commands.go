// internal/smtp/session_commands.go
package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	Success  bool
	Response string
	Error    error
	Duration time.Duration
	Command  string
}

// CommandHandler manages SMTP command processing for a session
type CommandHandler struct {
	session         *Session
	state           *SessionState
	authHandler     *AuthHandler
	logger          *slog.Logger
	conn            net.Conn
	config          *Config
	tlsManager      TLSHandler
	securityManager *CommandSecurityManager
}

// NewCommandHandler creates a new command handler
func NewCommandHandler(session *Session, state *SessionState, authHandler *AuthHandler,
	conn net.Conn, config *Config, tlsManager TLSHandler, logger *slog.Logger) *CommandHandler {
	return &CommandHandler{
		session:         session,
		state:           state,
		authHandler:     authHandler,
		logger:          logger.With("component", "session-commands"),
		conn:            conn,
		config:          config,
		tlsManager:      tlsManager,
		securityManager: NewCommandSecurityManager(logger),
	}
}

// ProcessCommand processes an SMTP command with comprehensive validation and logging
func (ch *CommandHandler) ProcessCommand(ctx context.Context, line string) error {
	startTime := time.Now()

	// Update activity
	ch.state.UpdateActivity(ctx)

	// Validate input with comprehensive security checks
	if err := ch.securityManager.ValidateCommand(ctx, line); err != nil {
		ch.logCommandResult(ctx, line, false, err.Error(), time.Since(startTime))
		return err
	}

	// Parse command
	cmd, args := ch.parseCommand(line)

	// Check if command is allowed in current phase
	if !ch.state.CanAcceptCommand(ctx, cmd) {
		err := fmt.Errorf("503 5.5.1 Bad sequence of commands")
		ch.logCommandResult(ctx, line, false, err.Error(), time.Since(startTime))
		return err
	}

	// Route command to appropriate handler
	var err error
	switch strings.ToUpper(cmd) {
	case "HELO":
		err = ch.HandleHELO(ctx, args)
	case "EHLO":
		err = ch.HandleEHLO(ctx, args)
	case "MAIL":
		err = ch.HandleMAIL(ctx, args)
	case "RCPT":
		err = ch.HandleRCPT(ctx, args)
	case "DATA":
		err = ch.HandleDATA(ctx)
	case "BDAT":
		err = ch.HandleBDAT(ctx, args)
	case "RSET":
		err = ch.HandleRSET(ctx)
	case "NOOP":
		err = ch.HandleNOOP(ctx)
	case "QUIT":
		err = ch.HandleQUIT(ctx)
	case "AUTH":
		err = ch.HandleAUTH(ctx, line)
	case "STARTTLS":
		err = ch.HandleSTARTTLS(ctx)
	case "HELP":
		err = ch.HandleHELP(ctx, args)
	case "VRFY":
		err = ch.HandleVRFY(ctx, args)
	case "EXPN":
		err = ch.HandleEXPN(ctx, args)
	case "XDEBUG":
		err = ch.HandleXDEBUG(ctx, line)
	default:
		err = ch.HandleUnknown(ctx, cmd)
	}

	// Log command result
	success := err == nil
	response := ""
	if err != nil {
		response = err.Error()
	}
	ch.logCommandResult(ctx, line, success, response, time.Since(startTime))

	return err
}

// HandleHELO processes the HELO command
// RFC 5321 §4.1.1.1 - HELO command: Client identifies itself with domain name
// RFC 5321 §4.1.3 - Hostname validation requirements
func (ch *CommandHandler) HandleHELO(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing HELO command", "args", args)

	if args == "" {
		return fmt.Errorf("501 5.0.0 HELO requires domain address")
	}

	// Validate hostname
	if err := ch.validateHostname(ctx, args); err != nil {
		return fmt.Errorf("501 5.0.0 Invalid hostname: %s", args)
	}

	// RFC 5321 §4.1.4: a greeting may arrive at any point and discards the
	// sender and recipient buffers. Recording the greeting first means Reset
	// lands the session in PhaseMail, ready for MAIL FROM, and also clears any
	// transaction that was in progress.
	ch.state.SetGreeted(true)
	ch.state.Reset(ctx)

	return ch.session.write(fmt.Sprintf("250 %s Hello %s", ch.config.Hostname, args))
}

// HandleEHLO processes the EHLO command
// RFC 5321 §4.1.1.1 - EHLO command: Extended HELO for ESMTP capabilities
// RFC 5321 §4.1.1.1 - Server responds with multi-line 250 response listing capabilities
func (ch *CommandHandler) HandleEHLO(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing EHLO command", "args", args)

	if args == "" {
		return fmt.Errorf("501 5.0.0 EHLO requires domain address")
	}

	// Validate hostname
	if err := ch.validateHostname(ctx, args); err != nil {
		return fmt.Errorf("501 5.0.0 Invalid hostname: %s", args)
	}

	// RFC 5321 §4.1.4: a greeting may arrive at any point and discards the
	// sender and recipient buffers. Recording the greeting first means Reset
	// lands the session in PhaseMail, ready for MAIL FROM, and also clears any
	// transaction that was in progress.
	ch.state.SetGreeted(true)
	ch.state.Reset(ctx)

	// Send EHLO response with extensions
	// PIPELINING (RFC 2920) is supported: responses are buffered and flushed
	// only when the reader has no more buffered data, allowing efficient
	// batched processing of pipelined commands.
	responses := []string{
		fmt.Sprintf("250-%s Hello %s", ch.config.Hostname, args),
		"250-SIZE " + strconv.FormatInt(ch.config.MaxSize, 10),
		"250-8BITMIME",
		"250-SMTPUTF8",
		"250-ENHANCEDSTATUSCODES",
		"250-CHUNKING",
		"250-DSN",
		"250-PIPELINING",
	}

	// Add STARTTLS if available and not already using TLS
	if ch.tlsManager != nil && !ch.state.IsTLSActive() {
		responses = append(responses, "250-STARTTLS")
	}

	// Add REQUIRETLS only when TLS is active (RFC 8689)
	if ch.state.IsTLSActive() {
		responses = append(responses, "250-REQUIRETLS")
	}

	// Add AUTH methods if authentication is enabled
	// Always advertise AUTH if auth is enabled but not required (for webmail clients)
	// Or if TLS is active or not required for PLAIN auth
	if ch.config.Auth != nil && ch.config.Auth.Enabled {
		if !ch.config.Auth.Required || ch.state.IsTLSActive() || !ch.authHandler.securityManager.config.RequireTLSForPlain {
			authMethods := ch.authHandler.GetAuthMethodsString()
			if authMethods != "" {
				responses = append(responses, "250-AUTH "+authMethods)
			}
		}
	}

	// Add XDEBUG in development mode
	if ch.config.DevMode {
		responses = append(responses, "250-XDEBUG")
	}

	// Add final response
	responses = append(responses, "250 HELP")

	// Send all responses
	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return fmt.Errorf("failed to write EHLO response: %w", err)
		}
	}

	return nil
}

// HandleMAIL processes the MAIL FROM command with RFC 1870 SIZE extension support
func (ch *CommandHandler) HandleMAIL(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing MAIL command", "args", args)

	// Check if authentication is required and user is not authenticated
	if ch.config.Auth != nil && ch.config.Auth.Enabled && ch.config.Auth.Required && !ch.state.IsAuthenticated() {
		return fmt.Errorf("530 5.7.0 Authentication required")
	}

	// Parse without mutating session state; extensions are committed only after acceptance.
	parsed, err := ch.parseMailFromParams(args)
	if err != nil {
		return err
	}
	mailFrom, declaredSize := parsed.addr, parsed.size

	// Sender domain policy. Checked after parsing so the rule matches a real
	// address rather than whatever text arrived, and before the transaction is
	// committed so a refused sender leaves no state behind.
	if ch.session != nil {
		if decision := ch.session.accessControl.CheckSender(mailFrom); decision.Denied {
			ch.logger.WarnContext(ctx, "Sender refused by access control",
				"event_type", "rejection",
				"mail_from", mailFrom,
				"rule", decision.Rule,
			)
			return fmt.Errorf("550 5.7.1 %s", decision.Reason)
		}
	}

	if err := ch.validateEmailAddress(ctx, mailFrom); err != nil {
		return fmt.Errorf("553 5.1.3 Invalid sender address: %s", mailFrom)
	}
	if containsNonASCII(mailFrom) && !parsed.smtpUTF8 {
		return fmt.Errorf("553 5.6.7 SMTPUTF8 is required for non-ASCII sender address")
	}

	// RFC 1870: Check declared SIZE against server's maximum
	// If client declares a size, reject if it exceeds our limit
	if declaredSize > 0 && declaredSize > ch.config.MaxSize {
		ch.logger.WarnContext(ctx, "Message SIZE exceeds maximum",
			"declared_size", declaredSize,
			"max_size", ch.config.MaxSize,
			"mail_from", mailFrom,
			"remote_addr", ch.session.remoteAddr,
		)
		return fmt.Errorf("552 5.3.4 Message size exceeds fixed maximum message size (%d bytes declared, %d bytes maximum)",
			declaredSize, ch.config.MaxSize)
	}

	var dsn *DSNParams
	if parsed.hasDSN {
		dsn = parsed.dsn
	}
	// Commit the complete envelope only after every check has succeeded.
	if err := ch.state.AcceptMail(ctx, mailFrom, declaredSize, parsed.smtpUTF8, dsn, parsed.requireTLS); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to set MAIL FROM in session state",
			"mail_from", mailFrom,
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	ch.logger.InfoContext(ctx, "mail_from_accepted",
		"event_type", "mail_from_accepted",
		"mail_from", mailFrom,
		"declared_size", declaredSize,
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
		"client_ip", ch.session.remoteAddr,
		"connection_id", ch.session.sessionID,
		"tls_active", ch.state.IsTLSActive(),
	)

	return ch.session.write("250 2.1.0 Sender OK")
}

// HandleRCPT processes the RCPT TO command
func (ch *CommandHandler) HandleRCPT(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing RCPT command", "args", args)

	// Parse without mutating recipient DSN state.
	parsed, err := ch.parseRcptToParams(args)
	if err != nil {
		return err
	}
	rcptTo := parsed.addr

	if err := ch.validateEmailAddress(ctx, rcptTo); err != nil {
		return fmt.Errorf("553 5.1.3 Invalid recipient address: %s", rcptTo)
	}
	if containsNonASCII(rcptTo) && !ch.state.IsSMTPUTF8() {
		return fmt.Errorf("553 5.6.7 SMTPUTF8 is required for non-ASCII recipient address")
	}

	// Check relay permissions
	if err := ch.checkRelayPermissions(ctx, rcptTo); err != nil {
		return err
	}

	// Add recipient to state
	if err := ch.state.AddRecipient(ctx, rcptTo); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to add recipient to session state",
			"recipient", rcptTo,
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}
	if parsed.hasDSN {
		ch.state.SetDSNRecipientParams(ctx, rcptTo, parsed.dsn)
	}

	ch.logger.InfoContext(ctx, "rcpt_to_accepted",
		"event_type", "rcpt_to_accepted",
		"rcpt_to", rcptTo,
		"mail_from", ch.state.GetMailFrom(),
		"total_recipients", ch.state.GetRecipientCount(),
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
		"client_ip", ch.session.remoteAddr,
		"connection_id", ch.session.sessionID,
	)

	return ch.session.write("250 2.1.5 Recipient OK")
}

// HandleDATA processes the DATA command
func (ch *CommandHandler) HandleDATA(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing DATA command")

	// Check if we have recipients
	if ch.state.GetRecipientCount() == 0 {
		return fmt.Errorf("503 5.5.1 RCPT first")
	}

	// Validate data command acceptance to prevent desynchronization attacks
	if !ch.state.CanAcceptDataCommand(ctx, "DATA") {
		ch.logger.WarnContext(ctx, "DATA command rejected - mode conflict or invalid phase",
			"event_type", "desynchronization_attempt",
			"current_mode", ch.state.GetDataTransferMode().String(),
			"current_phase", ch.state.GetPhase().String(),
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Set data transfer mode to DATA
	if err := ch.state.SetDataTransferMode(ctx, DataModeDATA); err != nil {
		ch.logger.WarnContext(ctx, "Failed to set data transfer mode",
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Set phase to data
	if err := ch.state.SetPhase(ctx, PhaseData); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to transition to DATA phase",
			"mail_from", ch.state.GetMailFrom(),
			"recipient_count", ch.state.GetRecipientCount(),
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Send data prompt and flush so the client sees it before sending data
	if err := ch.session.write("354 Start mail input; end with <CRLF>.<CRLF>"); err != nil {
		return fmt.Errorf("failed to write data prompt: %w", err)
	}
	if err := ch.session.flush(); err != nil {
		return fmt.Errorf("failed to flush data prompt: %w", err)
	}

	ch.logger.InfoContext(ctx, "DATA command accepted, ready for message data",
		"mail_from", ch.state.GetMailFrom(),
		"recipients", ch.state.GetRecipientCount(),
		"data_transfer_mode", ch.state.GetDataTransferMode().String(),
	)

	return nil
}

// HandleBDAT processes the BDAT command (RFC 3030 CHUNKING extension)
func (ch *CommandHandler) HandleBDAT(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing BDAT command", "args", args)

	// The chunk follows this command immediately, with no server reply in
	// between, so by the time any check below fails its octets are already
	// arriving. Every rejection therefore has to consume the chunk — or give up
	// on the connection — before returning, otherwise those octets are read as
	// SMTP commands. See DataHandler.DiscardBDATChunk.
	//
	// The size is parsed first for exactly that reason: nothing can
	// resynchronise without knowing how many octets to skip.
	// A size that cannot be parsed is a different situation: the server never
	// commits to reading a chunk, so the octets that follow were always going
	// to be commands and nothing is being reinterpreted. Those keep the
	// original behaviour of reporting the syntax error and carrying on.
	parts := strings.Fields(args)
	if len(parts) == 0 || len(parts) > 2 {
		return fmt.Errorf("501 5.5.4 Syntax: BDAT <chunk-size> [LAST]")
	}

	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("501 5.5.4 Invalid chunk size")
	}

	isLast := len(parts) == 2 && strings.EqualFold(parts[1], "LAST")
	if len(parts) == 2 && !isLast {
		return fmt.Errorf("501 5.5.4 Syntax: BDAT <chunk-size> [LAST]")
	}

	// rejectChunk refuses the command while leaving the connection at a known
	// position, by consuming the chunk that is already on its way.
	rejectChunk := func(e error) error {
		ch.session.dataHandler.DiscardBDATChunk(ctx, size)
		return e
	}

	// Check if we have recipients
	if ch.state.GetRecipientCount() == 0 {
		return rejectChunk(fmt.Errorf("503 5.5.1 RCPT first"))
	}

	// Validate data command acceptance to prevent desynchronization attacks
	if !ch.state.CanAcceptDataCommand(ctx, "BDAT") {
		ch.logger.WarnContext(ctx, "BDAT command rejected - mode conflict or invalid phase",
			"event_type", "desynchronization_attempt",
			"current_mode", ch.state.GetDataTransferMode().String(),
			"current_phase", ch.state.GetPhase().String(),
		)
		return rejectChunk(fmt.Errorf("503 5.5.1 Bad sequence of commands"))
	}

	// First chunk: set data transfer mode to BDAT
	if ch.state.GetDataTransferMode() == DataModeNone {
		if err := ch.state.SetDataTransferMode(ctx, DataModeBDAT); err != nil {
			return rejectChunk(fmt.Errorf("503 5.5.1 Bad sequence of commands"))
		}
	}

	// Read the chunk data
	if err := ch.session.dataHandler.ReadBDATChunk(ctx, size); err != nil {
		// On error, reset BDAT state
		ch.session.dataHandler.ResetBDAT()
		ch.state.ClearDataTransferMode(ctx)
		return err
	}

	if isLast {
		// Process the complete message
		if err := ch.session.dataHandler.ProcessBDATMessage(ctx); err != nil {
			ch.state.ClearDataTransferMode(ctx)
			return err
		}

		if err := ch.session.write("250 2.0.0 Message accepted for delivery"); err != nil {
			return fmt.Errorf("failed to write BDAT response: %w", err)
		}
		// End the transaction so the connection can carry another message,
		// matching the DATA path.
		ch.state.Reset(ctx)
		return nil
	}

	// Intermediate chunk: acknowledge receipt
	if err := ch.session.write(fmt.Sprintf("250 2.0.0 %d bytes received", size)); err != nil {
		return fmt.Errorf("failed to write BDAT response: %w", err)
	}
	return nil
}

// HandleRSET processes the RSET command
func (ch *CommandHandler) HandleRSET(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing RSET command")

	// Reset session state
	ch.state.Reset(ctx)

	// Clear any in-progress BDAT data
	ch.session.dataHandler.ResetBDAT()

	ch.logger.InfoContext(ctx, "Session state reset")

	return ch.session.write("250 2.0.0 Reset OK")
}

// HandleNOOP processes the NOOP command
func (ch *CommandHandler) HandleNOOP(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing NOOP command")
	return ch.session.write("250 2.0.0 OK")
}

// HandleQUIT processes the QUIT command
func (ch *CommandHandler) HandleQUIT(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing QUIT command")

	// Set phase to quit
	if err := ch.state.SetPhase(ctx, PhaseQuit); err != nil {
		ch.logger.WarnContext(ctx, "Failed to set QUIT phase", "error", err)
	}

	ch.logger.InfoContext(ctx, "Client initiated session termination")

	// Send the goodbye message and flush immediately so the client sees it
	if err := ch.session.write(fmt.Sprintf("221 2.0.0 %s closing connection", ch.config.Hostname)); err != nil {
		return err
	}
	if err := ch.session.flush(); err != nil {
		return err
	}

	// Give the client a moment to read the response before closing
	time.Sleep(100 * time.Millisecond)

	return nil
}

// HandleAUTH processes the AUTH command
func (ch *CommandHandler) HandleAUTH(ctx context.Context, cmd string) error {
	return ch.authHandler.HandleAuth(ctx, cmd)
}

// HandleSTARTTLS processes the STARTTLS command
func (ch *CommandHandler) HandleSTARTTLS(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing STARTTLS command")

	// Check if TLS is already active
	if ch.state.IsTLSActive() {
		return fmt.Errorf("454 4.7.0 TLS already active")
	}

	// Check if TLS is available
	if ch.tlsManager == nil {
		return fmt.Errorf("454 4.7.0 TLS not available")
	}

	// Send TLS ready response and flush immediately before TLS handshake
	if err := ch.session.write("220 2.0.0 Ready to start TLS"); err != nil {
		return fmt.Errorf("failed to write TLS ready response: %w", err)
	}
	if err := ch.session.flush(); err != nil {
		return fmt.Errorf("failed to flush TLS ready response: %w", err)
	}

	// Upgrade connection to TLS
	tlsConn, err := ch.tlsManager.WrapConnection(ch.conn)
	if err != nil {
		ch.logger.ErrorContext(ctx, "Failed to upgrade connection to TLS", "error", err)
		// The server already answered 220 and the client has begun a TLS
		// handshake, so whatever is on the wire now is TLS records, not SMTP.
		// RFC 3207 §4 requires the connection to be dropped rather than
		// returned to the command loop to be parsed as commands.
		ch.session.dataHandler.MarkDataSyncLost()
		return fmt.Errorf("454 4.7.0 TLS handshake failed")
	}

	// Rebind the session's buffered reader/writer and all component connection
	// references onto the TLS connection, discarding any pre-TLS buffered input
	// (STARTTLS command-injection defense).
	ch.session.upgradeToTLS(tlsConn)
	ch.conn = tlsConn
	ch.state.SetTLSActive(ctx, true)

	// RFC 3207 §4.2: the server must discard all state gathered before the
	// upgrade, and the client must issue EHLO again. Clearing greeted before
	// Reset sends the session back to PhaseInit rather than PhaseMail, so a
	// MAIL FROM that skips the second EHLO is refused.
	ch.state.SetGreeted(false)
	ch.state.Reset(ctx)

	ch.logger.InfoContext(ctx, "TLS connection established successfully")

	return nil
}

// HandleHELP processes the HELP command
func (ch *CommandHandler) HandleHELP(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing HELP command", "args", args)

	helpText := []string{
		"214-Commands supported:",
		"214-HELO EHLO MAIL RCPT DATA RSET NOOP QUIT",
		"214-AUTH STARTTLS HELP VRFY EXPN",
		"214 For more info use \"HELP <topic>\"",
	}

	for _, line := range helpText {
		if err := ch.session.write(line); err != nil {
			return fmt.Errorf("failed to write help text: %w", err)
		}
	}

	return nil
}

// HandleVRFY processes the VRFY command
func (ch *CommandHandler) HandleVRFY(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing VRFY command", "args", args)

	// VRFY is typically disabled for security reasons
	return ch.session.write("252 2.5.2 Cannot VRFY user, but will accept message")
}

// HandleEXPN processes the EXPN command
func (ch *CommandHandler) HandleEXPN(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing EXPN command", "args", args)

	// EXPN is typically disabled for security reasons
	return ch.session.write("502 5.5.1 EXPN not supported")
}

// HandleXDEBUG processes the XDEBUG command (development only)
func (ch *CommandHandler) HandleXDEBUG(ctx context.Context, cmd string) error {
	ch.logger.DebugContext(ctx, "Processing XDEBUG command", "command", cmd)

	// Only allow in development mode
	if !ch.config.DevMode {
		return fmt.Errorf("502 5.5.1 Command not recognized")
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		// Show available XDEBUG commands
		commands := []string{
			"214-XDEBUG commands:",
			"214-  CONTEXT    - Show complete connection context",
			"214-  STATE      - Show session state information",
			"214-  CONNECTION - Show connection details",
			"214 For more info use \"XDEBUG <command>\"",
		}
		for _, cmd := range commands {
			if err := ch.session.write(cmd); err != nil {
				return err
			}
		}
		return nil
	}

	switch strings.ToUpper(parts[1]) {
	case "CONTEXT":
		return ch.handleXDEBUGContext(ctx)
	case "STATE":
		return ch.handleXDEBUGState(ctx)
	case "CONNECTION":
		return ch.handleXDEBUGConnection(ctx)
	default:
		return ch.session.write("214 Unknown XDEBUG command")
	}
}

// HandleUnknown processes unknown commands
func (ch *CommandHandler) HandleUnknown(ctx context.Context, cmd string) error {
	ch.logger.WarnContext(ctx, "Unknown command received", "command", cmd)
	return fmt.Errorf("502 5.5.1 Command not recognized")
}

// Helper methods

// parseCommand parses a command line into command and arguments
func (ch *CommandHandler) parseCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	cmd := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	return cmd, args
}

// validateHostname validates a hostname per RFC 5321 §4.1.3
func (ch *CommandHandler) validateHostname(ctx context.Context, hostname string) error {
	if hostname == "" {
		return fmt.Errorf("empty hostname")
	}

	// Basic hostname validation
	if len(hostname) > 255 {
		return fmt.Errorf("hostname too long")
	}

	// Check if it's an address literal [x.x.x.x] or [IPv6:...] (RFC 5321 section 4.1.3)
	if len(hostname) >= 2 && hostname[0] == '[' && hostname[len(hostname)-1] == ']' {
		return ch.validateAddressLiteral(ctx, hostname)
	}

	// Validate as domain name
	return ch.validateDomainName(ctx, hostname)
}

// validateAddressLiteral validates IPv4 and IPv6 address literals per RFC 5321 §4.1.3
func (ch *CommandHandler) validateAddressLiteral(ctx context.Context, literal string) error {
	// Extract content between brackets
	content := literal[1 : len(literal)-1]

	if content == "" {
		return fmt.Errorf("malformed address literal: empty brackets")
	}

	// Check for IPv6 literal format: [IPv6:address] (RFC 5321 §4.1.3)
	if len(content) >= 5 && strings.ToUpper(content[:5]) == "IPV6:" {
		ipv6Addr := content[5:] // Remove "IPv6:" or "IPV6:" prefix

		if ipv6Addr == "" {
			return fmt.Errorf("malformed IPv6 address literal: missing address after IPv6: prefix")
		}

		// Validate IPv6 address
		ip := net.ParseIP(ipv6Addr)
		if ip == nil {
			return fmt.Errorf("malformed IPv6 address literal: invalid IPv6 address")
		}

		// Ensure it's actually an IPv6 address (ParseIP accepts both IPv4 and IPv6)
		if ip.To4() != nil {
			return fmt.Errorf("malformed IPv6 address literal: address is IPv4, not IPv6")
		}

		ch.logger.DebugContext(ctx, "accepted IPv6 address literal", "hostname", literal)
		return nil
	}

	// Check for general tagged address literal format: [tag:address]
	// This includes other address types defined in RFC 5321
	if strings.Contains(content, ":") {
		parts := strings.SplitN(content, ":", 2)
		tag := strings.ToUpper(parts[0])

		// Only IPv6 is widely supported; other tags could be added here
		// For now, we accept any tagged format but log it
		ch.logger.DebugContext(ctx, "accepted tagged address literal",
			"hostname", literal,
			"tag", tag)
		return nil
	}

	// Assume IPv4 literal format: [192.0.2.1]
	ip := net.ParseIP(content)
	if ip == nil {
		return fmt.Errorf("malformed IPv4 address literal: invalid IP address")
	}

	// Ensure it's actually IPv4 (not IPv6)
	if ip.To4() == nil {
		return fmt.Errorf("malformed IPv4 address literal: address is not IPv4 format")
	}

	ch.logger.DebugContext(ctx, "accepted IPv4 address literal", "hostname", literal)
	return nil
}

// validateDomainName validates a domain name per RFC 1035 and RFC 5321
func (ch *CommandHandler) validateDomainName(ctx context.Context, domain string) error {
	// Domain name validation per RFC 1035
	// - Labels separated by dots
	// - Each label: 1-63 characters
	// - Labels must start with alphanumeric, end with alphanumeric
	// - Labels can contain hyphens in the middle
	// - Total length <= 255 characters
	if len(domain) > 255 {
		return fmt.Errorf("invalid domain name: exceeds maximum length")
	}

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return fmt.Errorf("invalid domain name: empty domain")
	}

	// Validate each label
	// RFC 1035: Label must start with letter or digit, end with letter or digit,
	// and can contain hyphens in the middle
	labelRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("invalid domain name: empty label")
		}

		if len(label) > 63 {
			return fmt.Errorf("invalid domain name: label exceeds 63 characters")
		}

		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid domain name: malformed label")
		}
	}

	return nil
}

type mailFromParams struct {
	addr                         string
	size                         int64
	dsn                          *DSNParams
	hasDSN, smtpUTF8, requireTLS bool
}

//nolint:unused // retained for package tests and compatibility
func (ch *CommandHandler) parseMailFrom(ctx context.Context, args string) (string, int64, error) {
	p, err := ch.parseMailFromParams(args)
	return p.addr, p.size, err
}

func (ch *CommandHandler) parseMailFromParams(args string) (mailFromParams, error) {
	var p mailFromParams
	addr, fields, err := parseSMTPPath(args, "FROM:", true)
	if err != nil {
		return p, fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}
	p.addr, p.dsn = addr, &DSNParams{}
	seen := map[string]bool{}
	for _, field := range fields {
		key, value, hasValue := strings.Cut(field, "=")
		key = strings.ToUpper(key)
		if seen[key] {
			return p, fmt.Errorf("501 5.5.4 Duplicate %s parameter", key)
		}
		seen[key] = true
		switch key {
		case "SIZE":
			if !hasValue || !isASCIIDecimal(value) {
				return p, fmt.Errorf("501 5.5.4 Invalid SIZE parameter syntax")
			}
			p.size, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return p, fmt.Errorf("501 5.5.4 Invalid SIZE parameter syntax")
			}
			if ch.config.MaxSize >= 0 && p.size > ch.config.MaxSize {
				return p, fmt.Errorf("552 5.3.4 Message size exceeds fixed maximum message size")
			}
		case "SMTPUTF8":
			if hasValue {
				return p, fmt.Errorf("501 5.5.4 Invalid SMTPUTF8 parameter")
			}
			p.smtpUTF8 = true
		case "BODY":
			if !hasValue || (strings.ToUpper(value) != "7BIT" && strings.ToUpper(value) != "8BITMIME") {
				return p, fmt.Errorf("501 5.5.4 Invalid BODY parameter")
			}
		case "RET":
			if !hasValue {
				return p, fmt.Errorf("501 5.5.4 Invalid RET parameter")
			}
			switch strings.ToUpper(value) {
			case "FULL":
				p.dsn.Return = DSNReturnFull
			case "HDRS":
				p.dsn.Return = DSNReturnHeaders
			default:
				return p, fmt.Errorf("501 5.5.4 Invalid RET parameter: must be FULL or HDRS")
			}
			p.hasDSN = true
		case "ENVID":
			if !hasValue || len(value) > 100 || !validXText(value) {
				return p, fmt.Errorf("501 5.5.4 Invalid ENVID parameter")
			}
			p.dsn.EnvID, p.hasDSN = value, true
		case "REQUIRETLS":
			if hasValue {
				return p, fmt.Errorf("501 5.5.4 Invalid REQUIRETLS parameter")
			}
			p.requireTLS = true
		default:
			return p, fmt.Errorf("555 5.5.4 Unsupported MAIL FROM parameter: %s", key)
		}
	}
	if p.requireTLS && !ch.state.IsTLSActive() {
		return p, fmt.Errorf("530 5.7.4 REQUIRETLS requires an active TLS connection")
	}
	return p, nil
}

type rcptToParams struct {
	addr   string
	dsn    *DSNRecipientParams
	hasDSN bool
}

//nolint:unused // retained for package tests and compatibility
func (ch *CommandHandler) parseRcptTo(ctx context.Context, args string) (string, error) {
	p, err := ch.parseRcptToParams(args)
	return p.addr, err
}

func (ch *CommandHandler) parseRcptToParams(args string) (rcptToParams, error) {
	var p rcptToParams
	addr, fields, err := parseSMTPPath(args, "TO:", false)
	if err != nil {
		return p, fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}
	p.addr, p.dsn = addr, &DSNRecipientParams{}
	seen := map[string]bool{}
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		key = strings.ToUpper(key)
		if seen[key] {
			return p, fmt.Errorf("501 5.5.4 Duplicate %s parameter", key)
		}
		seen[key] = true
		switch key {
		case "NOTIFY":
			if !ok || value == "" {
				return p, fmt.Errorf("501 5.5.4 Invalid NOTIFY value")
			}
			values, conditions := strings.Split(strings.ToUpper(value), ","), map[string]bool{}
			for _, v := range values {
				if conditions[v] {
					return p, fmt.Errorf("501 5.5.4 Duplicate NOTIFY condition: %s", v)
				}
				conditions[v] = true
				switch v {
				case "NEVER":
					p.dsn.Notify = append(p.dsn.Notify, DSNNotifyNever)
				case "SUCCESS":
					p.dsn.Notify = append(p.dsn.Notify, DSNNotifySuccess)
				case "FAILURE":
					p.dsn.Notify = append(p.dsn.Notify, DSNNotifyFailure)
				case "DELAY":
					p.dsn.Notify = append(p.dsn.Notify, DSNNotifyDelay)
				default:
					return p, fmt.Errorf("501 5.5.4 Invalid NOTIFY value: %s", v)
				}
			}
			if conditions["NEVER"] && len(values) > 1 {
				return p, fmt.Errorf("501 5.5.4 NOTIFY=NEVER must not be combined with other values")
			}
		case "ORCPT":
			if !ok || !validORCPT(value) {
				return p, fmt.Errorf("501 5.5.4 Invalid ORCPT parameter")
			}
			p.dsn.ORCPT = value
		default:
			return p, fmt.Errorf("555 5.5.4 Unsupported RCPT TO parameter: %s", key)
		}
	}
	p.hasDSN = len(fields) > 0
	return p, nil
}

func parseSMTPPath(args, prefix string, allowNull bool) (string, []string, error) {
	if len(args) < len(prefix)+2 || !strings.EqualFold(args[:len(prefix)], prefix) || args[len(prefix)] != '<' {
		return "", nil, fmt.Errorf("invalid path")
	}
	rest, quoted, escaped, close := args[len(prefix):], false, false, -1
	for i := 1; i < len(rest); i++ {
		b := rest[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && b == '\\' {
			escaped = true
			continue
		}
		if b == '"' {
			quoted = !quoted
			continue
		}
		if b == '>' && !quoted {
			close = i
			break
		}
	}
	if close < 0 || quoted || escaped {
		return "", nil, fmt.Errorf("unterminated path")
	}
	addr := rest[1:close]
	if addr == "" && !allowNull {
		return "", nil, fmt.Errorf("null forward path")
	}
	if addr != "" && !validSMTPMailbox(addr) {
		return "", nil, fmt.Errorf("invalid mailbox")
	}
	tail := rest[close+1:]
	if tail == "" {
		return addr, nil, nil
	}
	if tail[0] != ' ' && tail[0] != '\t' {
		return "", nil, fmt.Errorf("path trailing junk")
	}
	fields, start := []string{}, 0
	for i := 0; i <= len(tail); i++ {
		if i < len(tail) && tail[i] != ' ' && tail[i] != '\t' {
			continue
		}
		if start < i {
			fields = append(fields, tail[start:i])
		}
		start = i + 1
	}
	return addr, fields, nil
}

func isASCIIDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
func containsNonASCII(s string) bool {
	for i := range s {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}
func validXText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '+' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		} else if b < 33 || b > 126 || b == '=' {
			return false
		}
	}
	return true
}
func isHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' || b >= 'a' && b <= 'f' }
func validORCPT(s string) bool {
	typ, text, ok := strings.Cut(s, ";")
	if !ok || typ == "" || !validXText(text) {
		return false
	}
	for i := range typ {
		b := typ[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}
func validSMTPMailbox(s string) bool {
	quoted, escaped, at := false, false, -1
	for i := 0; i < len(s); i++ {
		b := s[i]
		if escaped {
			if b < 32 || b > 126 {
				return false
			}
			escaped = false
			continue
		}
		if quoted && b == '\\' {
			escaped = true
			continue
		}
		if b == '"' {
			if i != 0 && !(quoted && i > 0) {
				return false
			}
			quoted = !quoted
			continue
		}
		if !quoted && b == '@' {
			if at >= 0 {
				return false
			}
			at = i
			continue
		}
		if !quoted && (b <= 32 || b == '<' || b == '>') {
			return false
		}
	}
	if quoted || escaped || at <= 0 || at == len(s)-1 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if local[0] == '"' {
		if len(local) < 2 || local[len(local)-1] != '"' {
			return false
		}
	} else {
		if strings.ContainsAny(local, "\"(),:;<>@[\\] ") || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			return false
		}
	}
	if domain[0] == '[' {
		if domain[len(domain)-1] != ']' {
			return false
		}
		return net.ParseIP(strings.TrimPrefix(domain[1:len(domain)-1], "IPv6:")) != nil
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			b := label[i]
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 0x80) {
				return false
			}
		}
	}
	return true
}

// validateEmailAddress validates an email address
func (ch *CommandHandler) validateEmailAddress(ctx context.Context, addr string) error {
	// Allow empty address for null sender
	if addr == "" {
		return nil
	}

	// Basic length check
	if len(addr) > 320 { // RFC 5321 limit
		return fmt.Errorf("address too long")
	}

	// Basic email validation - must have @ and both local-part and domain
	atIndex := strings.Index(addr, "@")
	if atIndex == -1 || atIndex == 0 || atIndex == len(addr)-1 {
		ch.logger.WarnContext(ctx, "Email validation failed",
			"address", addr,
			"reason", "invalid_format",
		)
		return fmt.Errorf("invalid email address format")
	}

	return nil
}

// checkRelayPermissions checks if relay is allowed for a recipient
func (ch *CommandHandler) checkRelayPermissions(ctx context.Context, recipient string) error {
	// DevMode bypasses all relay restrictions for testing
	if ch.config.DevMode {
		ch.logger.DebugContext(ctx, "Relay allowed (DevMode enabled)",
			"recipient", recipient,
		)
		return nil
	}

	// If authenticated, allow relay
	if ch.state.IsAuthenticated() {
		ch.logger.InfoContext(ctx, "Relay allowed for authenticated user",
			"recipient", recipient,
			"username", ch.state.GetUsername(),
		)
		return nil
	}

	// Check if recipient is in local domains first
	if ch.isLocalDomain(ctx, recipient) {
		ch.logger.InfoContext(ctx, "Local domain recipient accepted", "recipient", recipient)
		return nil
	}

	// Check if relay is explicitly allowed (AllowedRelays CIDRs / private networks)
	if ch.isRelayAllowed(recipient) {
		ch.logger.DebugContext(ctx, "Relay explicitly allowed", "recipient", recipient)
		return nil
	}

	ch.logger.WarnContext(ctx, "Relay denied for recipient",
		"recipient", recipient,
		"authenticated", ch.state.IsAuthenticated(),
	)

	return fmt.Errorf("554 5.7.1 Relay access denied")
}

// isLocalDomain checks if a recipient is in a local domain
func (ch *CommandHandler) isLocalDomain(ctx context.Context, recipient string) bool {
	if ch.config.LocalDomains == nil {
		return false
	}

	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(parts[1])
	for _, localDomain := range ch.config.LocalDomains {
		if strings.ToLower(localDomain) == domain {
			return true
		}
	}

	return false
}

// isRelayAllowed checks if relay is allowed for a recipient based on the
// client's IP address and the configured AllowedRelays list.
// Private/internal networks are always allowed to relay.
func (ch *CommandHandler) isRelayAllowed(recipient string) bool {
	if ch.conn == nil {
		return false
	}

	ip := GetClientIP(ch.conn)
	if ip == nil {
		return false
	}

	return IsAllowedRelay(ip, ch.config.AllowedRelays)
}

// logCommandResult logs the result of a command execution
func (ch *CommandHandler) logCommandResult(ctx context.Context, command string, success bool, response string, duration time.Duration) {
	level := slog.LevelInfo
	var eventType string
	if !success {
		level = slog.LevelWarn
		eventType = "rejection"
		// Check for tempfail (4xx)
		if len(response) >= 3 && response[0] == '4' {
			eventType = "tempfail"
		}
	} else {
		// For successful commands, we can use specific event types if needed,
		// or leave empty to be categorized as system/info
		if strings.HasPrefix(strings.ToUpper(command), "MAIL FROM") {
			eventType = "mail_from_accepted"
		} else if strings.HasPrefix(strings.ToUpper(command), "RCPT TO") {
			eventType = "rcpt_to_accepted"
		} else if strings.HasPrefix(strings.ToUpper(command), "DATA") {
			eventType = "data_accepted"
		}
	}

	// Sanitize command for safe logging
	sanitizedCommand := ch.securityManager.SanitizeCommand(command)

	ch.logger.Log(ctx, level, "SMTP command processed",
		"event_type", eventType,
		"command", sanitizedCommand,
		"success", success,
		"response", response,
		"duration", duration,
		"phase", ch.state.GetPhase().String(),
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
	)
}

// XDEBUG subcommand handlers

// handleXDEBUGContext shows complete connection context (like Momentum's XDUMPCONTEXT)
func (ch *CommandHandler) handleXDEBUGContext(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG CONTEXT DUMP ===",
		"214-Connection Information:",
		fmt.Sprintf("214-  Remote Address: %s", ch.session.remoteAddr),
		fmt.Sprintf("214-  Session ID: %s", ch.session.sessionID),
		fmt.Sprintf("214-  Connected At: %s", time.Now().Format("2006-01-02 15:04:05")),
		fmt.Sprintf("214-  Session Duration: %v", ch.state.GetSessionDuration()),
		fmt.Sprintf("214-  Idle Time: %v", ch.state.GetIdleTime()),
		"214-Session State:",
		fmt.Sprintf("214-  Current Phase: %s", ch.state.GetPhase().String()),
		fmt.Sprintf("214-  Mail From: %s", ch.state.GetMailFrom()),
		fmt.Sprintf("214-  Recipients: %d", ch.state.GetRecipientCount()),
		fmt.Sprintf("214-  Data Size: %d bytes", ch.state.GetDataSize()),
		fmt.Sprintf("214-  Message Count: %d", ch.state.GetMessageCount()),
		"214-Authentication:",
		fmt.Sprintf("214-  Authenticated: %t", ch.state.IsAuthenticated()),
		fmt.Sprintf("214-  Username: %s", ch.state.GetUsername()),
		fmt.Sprintf("214-  Auth Attempts: %d", ch.state.GetAuthAttempts()),
		fmt.Sprintf("214-  Last Auth Attempt: %s", ch.state.GetLastAuthAttempt().Format("2006-01-02 15:04:05")),
		"214-TLS Status:",
		fmt.Sprintf("214-  TLS Active: %t", ch.state.IsTLSActive()),
		"214-Traffic Statistics:",
	}

	sent, received := ch.state.GetTrafficStats()
	responses = append(responses, fmt.Sprintf("214-  Bytes Sent: %d", sent))
	responses = append(responses, fmt.Sprintf("214-  Bytes Received: %d", received))

	// Add error information
	errors := ch.state.GetErrors()
	responses = append(responses, fmt.Sprintf("214-  Error Count: %d", len(errors)))

	responses = append(responses, "214-=== END CONTEXT DUMP ===")
	responses = append(responses, "214 OK")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGState shows detailed session state information
func (ch *CommandHandler) handleXDEBUGState(ctx context.Context) error {
	snapshot := ch.state.GetStateSnapshot()

	responses := []string{
		"214-=== XDEBUG STATE ===",
	}

	for key, value := range snapshot {
		responses = append(responses, fmt.Sprintf("214-  %s: %v", key, value))
	}

	responses = append(responses, "214-=== END STATE ===")
	responses = append(responses, "214 OK")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGConnection shows connection details
func (ch *CommandHandler) handleXDEBUGConnection(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG CONNECTION ===",
		fmt.Sprintf("214-  Remote Address: %s", ch.session.remoteAddr),
		fmt.Sprintf("214-  Session ID: %s", ch.session.sessionID),
		fmt.Sprintf("214-  Session Duration: %v", ch.state.GetSessionDuration()),
		fmt.Sprintf("214-  Idle Time: %v", ch.state.GetIdleTime()),
		fmt.Sprintf("214-  Connected At: %s", time.Now().Format("2006-01-02 15:04:05")),
		"214-=== END CONNECTION ===",
		"214 OK",
	}

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}
