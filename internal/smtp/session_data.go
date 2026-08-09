// internal/smtp/session_data.go
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/busybox42/elemta/internal/logging"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
)

// DataReaderState represents the state of the data reader
type DataReaderState struct {
	InHeaders             bool
	LastLineEmpty         bool
	LineCount             int64
	BytesRead             int64
	HeadersComplete       bool
	LastLineEndedWithCRLF bool // Track if previous line ended with CRLF for enhanced end-of-data validation
}

// MessageMetadata contains metadata about a message
type MessageMetadata struct {
	MessageID string
	From      string
	To        []string
	Subject   string
	Date      time.Time
	Size      int64
	Headers   map[string]string
	Checksum  string
}

// SecurityScanResult represents the result of security scanning
type SecurityScanResult struct {
	Passed bool
	// SpamDetected records the engine's own verdict, which it reaches against
	// its own configured threshold. Whether that verdict rejects the message is
	// policy, held in [antispam].reject_on_spam, and is decided separately.
	SpamDetected bool
	Threats      []string
	SpamScore    float64
	VirusFound   bool
	Quarantined  bool
}

// DataHandler manages message data processing for a session
type DataHandler struct {
	session           *Session
	state             *SessionState
	logger            *slog.Logger
	conn              net.Conn
	reader            *bufio.Reader
	config            *Config
	queueManager      queue.QueueManager
	scannerManager    *ScannerManager
	enhancedValidator *EnhancedValidator
	msgLogger         *logging.MessageLogger
	receptionTime     time.Time
	bdatBuffer        bytes.Buffer // Accumulated BDAT chunk data
	bdatBytesReceived int64        // Total bytes across all chunks
	bdatChunkCount    int          // Chunks received in current transaction
}

// NewDataHandler creates a new data handler
func NewDataHandler(session *Session, state *SessionState, conn net.Conn, reader *bufio.Reader,
	config *Config, queueManager queue.QueueManager,
	scannerManager *ScannerManager, logger *slog.Logger) *DataHandler {
	baseLogger := logger.With("component", "session-data")

	// Use the existing global logger that writes to both stdout and file
	// The global logger is configured in logging_handler.go to write to /app/logs/elemta.log
	msgLogger := logging.NewMessageLogger(baseLogger)

	return &DataHandler{
		session:           session,
		state:             state,
		logger:            baseLogger,
		conn:              conn,
		reader:            reader,
		config:            config,
		queueManager:      queueManager,
		scannerManager:    scannerManager,
		enhancedValidator: NewEnhancedValidator(logger.With("component", "enhanced-validator")),
		msgLogger:         msgLogger,
		receptionTime:     time.Now(),
	}
}

// spoolDir returns the directory message spools are written to. It sits under
// the queue directory so a completed spool is on the same filesystem as the
// queue and can be renamed into place rather than copied.
func (dh *DataHandler) spoolDir() string {
	return filepath.Join(dh.config.QueueDir, "spool")
}

// spoolThreshold returns the size above which message data goes to disk.
// A negative value keeps everything in memory, restoring the previous
// behaviour for operators who need it.
func (dh *DataHandler) spoolThreshold() int64 {
	if dh.config.SpoolThresholdBytes != nil {
		return *dh.config.SpoolThresholdBytes
	}
	return DefaultSpoolThreshold
}

// ReadData reads message data from the client into a spool, keeping small
// messages in memory and spilling larger ones to disk.
// RFC 5321 §3.3 - Mail transactions: DATA command processing
// RFC 5321 §4.1.1.4 - DATA command: After client sends DATA, server responds with 354 and accepts text
// The returned spool is owned by the caller, which must Close it on every exit
// path; Close removes the backing file. On error the spool is closed here and
// nil is returned.
func (dh *DataHandler) ReadData(ctx context.Context) (*MessageSpool, error) {
	slog.LogAttrs(ctx, slog.LevelDebug, "Starting message data reading")

	startTime := time.Now()

	spool := NewMessageSpool(dh.spoolDir(), dh.spoolThreshold())
	// Any return before the spool is handed to the caller must release it.
	handedOff := false
	defer func() {
		if !handedOff {
			if err := spool.Close(); err != nil {
				dh.logger.WarnContext(ctx, "Failed to release message spool", "error", err)
			}
		}
	}()

	state := &DataReaderState{
		InHeaders: true,
	}
	suspiciousPatterns := 0
	maxSize := dh.config.MaxSize

	// Get per-session memory limit (50MB default for ELE-16)
	sessionMemoryLimit := int64(50 * 1024 * 1024) // 50MB default
	if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
		sessionMemoryLimit = dh.session.resourceManager.memoryManager.config.PerConnectionMemoryLimit
	}

	// RFC 1870: a client that declares a SIZE larger than the spool threshold
	// is going to spill anyway, so start on disk rather than growing a heap
	// buffer up to the threshold first and copying it out.
	if declaredSize := dh.state.GetDeclaredSize(); declaredSize > dh.spoolThreshold() {
		if err := spool.SpillToDisk(); err != nil {
			return nil, fmt.Errorf("451 4.3.0 Unable to prepare message spool: %w", err)
		}
		slog.LogAttrs(ctx, slog.LevelDebug, "Spooling to disk from the start based on declared SIZE",
			slog.Int64("declared_size", declaredSize),
			slog.Int64("spool_threshold", dh.spoolThreshold()),
		)
	}

	// Set read timeout with proper error handling
	if deadline, ok := ctx.Deadline(); ok {
		if err := dh.conn.SetReadDeadline(deadline); err != nil {
			dh.logger.ErrorContext(ctx, "Failed to set read deadline from context - connection compromised",
				"error", err, "deadline", deadline)
			return nil, fmt.Errorf("connection compromised: unable to set read deadline: %w", err)
		}
	} else {
		if err := dh.conn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
			dh.logger.ErrorContext(ctx, "Failed to set default read deadline - connection compromised",
				"error", err)
			return nil, fmt.Errorf("connection compromised: unable to set read deadline: %w", err)
		}
	}

	// Cleanup function to reset deadline - log error but don't fail since we're already cleaning up
	defer func() {
		if err := dh.conn.SetReadDeadline(time.Time{}); err != nil {
			dh.logger.WarnContext(ctx, "Failed to reset read deadline during cleanup", "error", err)
		}
	}()

	// Progressive memory tracking variables
	const memoryCheckInterval = 1024 * 1024 // Check every 1MB
	lastMemoryCheck := int64(0)

	for {
		line, err := dh.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				dh.logger.WarnContext(ctx, "Unexpected EOF while reading message data")
				return nil, fmt.Errorf("unexpected end of data")
			}
			dh.logger.ErrorContext(ctx, "Error reading message data", "error", err)
			return nil, fmt.Errorf("error reading data: %w", err)
		}

		state.LineCount++
		state.BytesRead += int64(len(line))

		// RFC 5321 § 2.3.7: Validate line endings
		// Lines must be terminated with CRLF (\r\n)
		// Reject bare CR (\r) or bare LF (\n) in strict mode
		if err := dh.validateLineEndings(ctx, line, state); err != nil {
			dh.logger.WarnContext(ctx, "Line ending validation failed",
				"line_number", state.LineCount,
				"error", err,
				"remote_addr", dh.conn.RemoteAddr().String(),
			)
			// Clear data transfer mode on error
			dh.state.ClearDataTransferMode(ctx)
			return nil, err
		}

		// Track if this line ended with CRLF for enhanced end-of-data validation
		state.LastLineEndedWithCRLF = (len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n')

		// Check message size limit
		if state.BytesRead > maxSize {
			dh.logger.WarnContext(ctx, "Message size limit exceeded",
				"bytes_read", state.BytesRead,
				"max_size", maxSize,
			)
			// Clear data transfer mode on error
			dh.state.ClearDataTransferMode(ctx)
			return nil, fmt.Errorf("552 5.3.4 Message size exceeds maximum allowed")
		}

		// PROGRESSIVE MEMORY TRACKING (ELE-16 Critical Fix)
		// Check memory limits progressively during data reading
		if state.BytesRead-lastMemoryCheck >= memoryCheckInterval {
			lastMemoryCheck = state.BytesRead

			// Check per-session memory limit
			if state.BytesRead > sessionMemoryLimit {
				dh.logger.WarnContext(ctx, "Session memory limit exceeded during data reading",
					"bytes_read", state.BytesRead,
					"session_memory_limit", sessionMemoryLimit,
					"session_id", dh.session.sessionID,
				)
				// Clear data transfer mode on error
				dh.state.ClearDataTransferMode(ctx)
				return nil, fmt.Errorf("552 5.3.4 Session memory limit exceeded")
			}

			// Check global memory limits if resource manager is available
			if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
				if err := dh.session.resourceManager.memoryManager.CheckMemoryLimit(); err != nil {
					dh.logger.WarnContext(ctx, "Global memory limit exceeded during data reading",
						"error", err,
						"session_id", dh.session.sessionID,
					)
					// Clear data transfer mode on error
					dh.state.ClearDataTransferMode(ctx)
					return nil, fmt.Errorf("552 5.3.4 Server memory limit exceeded")
				}
			}
		}

		// Convert line to string for processing
		lineStr := string(line)

		// Check for end of data marker with enhanced security validation
		if dh.isValidEndOfData(lineStr, state, &suspiciousPatterns) {
			dh.logger.DebugContext(ctx, "Valid end-of-data marker detected")

			// Anything still buffered here belongs to the client's next
			// command, not to this message. The server advertises PIPELINING,
			// so it must be left in the reader for the command loop.
			//
			// This used to call reader.Discard(reader.Buffered()) to stop
			// message content being parsed as commands. That was treating a
			// symptom: the real cause was end-of-data being detected early,
			// because legacy mode accepts a bare-LF ".\n" as a terminator and
			// a message body containing such a line ends the DATA phase in the
			// middle of the message. Everything after it is then, by that
			// parse, genuinely commands. strict_line_endings (now the default)
			// rejects both bare LF and ".\n", which addresses the cause.
			break
		}

		// Validate line content for security threats
		if err := dh.validateLineContent(ctx, lineStr, state); err != nil {
			dh.logger.WarnContext(ctx, "Line validation failed",
				"line_number", state.LineCount,
				"error", err,
			)
			return nil, fmt.Errorf("554 5.7.1 Message rejected: %s", err.Error())
		}

		// Track header completion
		if state.InHeaders {
			// Headers end with a single empty line (RFC 5322)
			if strings.TrimSpace(lineStr) == "" {
				state.InHeaders = false
				state.HeadersComplete = true
				slog.LogAttrs(ctx, slog.LevelDebug, "Headers section completed",
					slog.Int64("line_count", state.LineCount),
				)
			}
		}

		// Write line to buffer with RFC 5321 §4.5.2 transparent dot-stuffing
		// Lines starting with "." have the second "." removed during DATA reception
		processedLine := dh.applyDotStuffing(ctx, line, state)
		if _, err := spool.Write(processedLine); err != nil {
			dh.logger.ErrorContext(ctx, "Failed to write message data to spool", "error", err)
			dh.state.ClearDataTransferMode(ctx)
			return nil, fmt.Errorf("451 4.3.0 Unable to buffer message data")
		}

		// Periodic logging for large messages with memory tracking
		if state.LineCount%1000 == 0 {
			slog.LogAttrs(ctx, slog.LevelDebug, "Message reading progress with memory tracking",
				slog.Int64("lines_read", state.LineCount),
				slog.Int64("bytes_read", state.BytesRead),
				slog.Int64("session_memory_limit", sessionMemoryLimit),
				slog.Float64("memory_utilization_pct", float64(state.BytesRead)/float64(sessionMemoryLimit)*100),
				slog.Duration("duration", time.Since(startTime)),
			)
		}
	}

	size := spool.Size()
	dh.state.SetDataSize(ctx, size)

	dh.logger.InfoContext(ctx, "Message data reading completed",
		"total_lines", state.LineCount,
		"total_bytes", size,
		"spooled_to_disk", spool.OnDisk(),
		"duration", time.Since(startTime),
		"suspicious_patterns", suspiciousPatterns,
	)

	handedOff = true
	return spool, nil
}

// ReadBDATChunk reads exactly size bytes from the connection for a BDAT chunk
func (dh *DataHandler) ReadBDATChunk(ctx context.Context, size int64) error {
	// Check total accumulated + new chunk against max size
	if dh.bdatBytesReceived+size > dh.config.MaxSize {
		return fmt.Errorf("552 5.3.4 Message size exceeds maximum allowed (%d bytes)", dh.config.MaxSize)
	}

	// Check per-session memory limit
	sessionMemoryLimit := int64(50 * 1024 * 1024)
	if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
		sessionMemoryLimit = dh.session.resourceManager.memoryManager.config.PerConnectionMemoryLimit
	}
	if dh.bdatBytesReceived+size > sessionMemoryLimit {
		return fmt.Errorf("552 5.3.4 Session memory limit exceeded")
	}

	// Read exactly size bytes
	chunk := make([]byte, size)
	_, err := io.ReadFull(dh.reader, chunk)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to read BDAT chunk", "error", err, "expected_size", size)
		return fmt.Errorf("451 4.3.0 Error reading chunk data: %w", err)
	}

	dh.bdatBuffer.Write(chunk)
	dh.bdatBytesReceived += size
	dh.bdatChunkCount++

	dh.logger.DebugContext(ctx, "BDAT chunk received",
		"chunk_size", size,
		"total_received", dh.bdatBytesReceived,
		"chunk_count", dh.bdatChunkCount,
	)

	return nil
}

// ProcessBDATMessage processes the accumulated BDAT data as a complete message
func (dh *DataHandler) ProcessBDATMessage(ctx context.Context) error {
	data := dh.bdatBuffer.Bytes()
	dh.state.SetDataSize(ctx, int64(len(data)))

	err := dh.processMessageBytes(ctx, data, queue.OpenerForBytes(data))
	dh.ResetBDAT()
	return err
}

// ResetBDAT clears the BDAT buffer and counters
func (dh *DataHandler) ResetBDAT() {
	dh.bdatBuffer.Reset()
	dh.bdatBytesReceived = 0
	dh.bdatChunkCount = 0
}

// ProcessMessage processes a spooled message with security scanning and
// validation.
//
// Stage 1 of the spooling work reads the spool back into memory here, so that
// moving DATA reception off the heap could land and soak on its own. Stage 2
// replaces this with a reader-based path; the seam is deliberate.
func (dh *DataHandler) ProcessMessage(ctx context.Context, spool *MessageSpool) error {
	data, err := spool.Bytes()
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to read spooled message", "error", err)
		return fmt.Errorf("451 4.3.0 Unable to read message data")
	}
	// Scanning still needs the whole body, but queuing does not: the spool is
	// handed on so the queue can stream it rather than take another copy.
	return dh.processMessageBytes(ctx, data, spool.Open)
}

// processMessageBytes is the byte-oriented implementation shared by the DATA
// and BDAT paths.
func (dh *DataHandler) processMessageBytes(ctx context.Context, data []byte, body queue.ContentOpener) error {
	dh.logger.DebugContext(ctx, "Starting message processing with memory tracking", "size", len(data))

	startTime := time.Now()

	// PROGRESSIVE MEMORY TRACKING (ELE-16 Critical Fix)
	// Check memory limits before processing
	if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
		// Check global memory limits
		if err := dh.session.resourceManager.memoryManager.CheckMemoryLimit(); err != nil {
			dh.logger.WarnContext(ctx, "Global memory limit exceeded before message processing",
				"error", err,
				"session_id", dh.session.sessionID,
				"message_size", len(data),
			)
			return fmt.Errorf("552 5.3.4 Server memory limit exceeded")
		}

		// Check per-session memory limits for the message
		estimatedProcessingMemory := int64(len(data) * 3) // Estimate 3x message size for processing
		if err := dh.session.resourceManager.memoryManager.CheckConnectionMemoryLimit(dh.session.sessionID, estimatedProcessingMemory); err != nil {
			dh.logger.WarnContext(ctx, "Session memory limit exceeded for message processing",
				"error", err,
				"session_id", dh.session.sessionID,
				"message_size", len(data),
				"estimated_processing_memory", estimatedProcessingMemory,
			)
			return fmt.Errorf("552 5.3.4 Session memory limit exceeded")
		}
	}

	// Extract message metadata
	metadata, err := dh.extractMessageMetadata(ctx, data)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to extract message metadata", "error", err)
		return fmt.Errorf("451 4.3.0 Message processing failed")
	}

	// Validate message headers
	if err := dh.validateMessageHeaders(ctx, metadata); err != nil {
		dh.logger.WarnContext(ctx, "Message header validation failed", "error", err)
		return fmt.Errorf("554 5.7.1 Message rejected: %s", err.Error())
	}

	// Perform security scanning
	scanResult, err := dh.performSecurityScan(ctx, data, metadata)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Security scan failed", "error", err)
		return fmt.Errorf("451 4.3.0 Security scan failed")
	}

	// Handle security scan results
	if !scanResult.Passed {
		return dh.handleSecurityThreat(ctx, scanResult, metadata)
	}

	// Build this hop's headers. They are written ahead of the body rather than
	// concatenated with it, so the body is never copied a second time.
	headerPrefix := dh.buildServerHeaders(ctx, data, metadata, scanResult)

	if err := dh.saveMessage(ctx, headerPrefix, body, metadata); err != nil {
		dh.logger.ErrorContext(ctx, "Failed to save message", "error", err)
		return fmt.Errorf("451 4.3.0 Message processing failed")
	}

	// Reset session state for next transaction
	dh.state.Reset(ctx)
	dh.state.IncrementMessageCount(ctx)

	dh.logger.InfoContext(ctx, "Message processing completed successfully",
		"message_id", metadata.MessageID,
		"from", metadata.From,
		"recipients", len(metadata.To),
		"size", metadata.Size,
		"duration", time.Since(startTime),
	)

	return nil
}

// isValidEndOfData checks for valid end-of-data marker with strict RFC 5321 validation
func (dh *DataHandler) isValidEndOfData(line string, state *DataReaderState, suspiciousPatterns *int) bool {
	// RFC 5321 § 2.3.8: The sequence "\r\n.\r\n" indicates end of data
	// RFC 5321 § 2.3.7: Lines must be terminated with CRLF (\r\n)
	// Enhanced security: Only accept ".\r\n" when preceded by a line ending with CRLF

	// Check for strict RFC 5321 compliant end-of-data sequence: ".\r\n"
	if line == ".\r\n" {
		// Enhanced validation: Ensure previous line ended with CRLF to prevent SMTP smuggling
		if dh.config.StrictLineEndingsEnabled() && !state.LastLineEndedWithCRLF && state.LineCount > 1 {
			dh.logger.WarnContext(context.Background(), "Invalid end-of-data marker - not preceded by CRLF (security violation)",
				"event_type", "smtp_smuggling_attempt",
				"line", fmt.Sprintf("%q", line),
				"line_count", state.LineCount,
				"prev_line_ended_with_crlf", state.LastLineEndedWithCRLF,
				"remote_addr", dh.conn.RemoteAddr().String(),
				"pattern_type", "malformed_end_of_data_sequence",
			)

			// Log as security event
			LogSecurityEvent(dh.logger, "malformed_end_sequence", "smtp_smuggling",
				"End-of-data marker not preceded by CRLF", line, dh.conn.RemoteAddr().String())

			*suspiciousPatterns++
			return false
		}

		dh.logger.DebugContext(context.Background(), "Valid RFC 5321 end-of-data marker detected",
			"line", fmt.Sprintf("%q", line),
			"line_count", state.LineCount,
			"prev_line_ended_with_crlf", state.LastLineEndedWithCRLF,
		)
		return true
	}

	// Check for legacy bare LF terminator: ".\n"
	if line == ".\n" {
		// Legacy compatibility mode check
		if dh.config.StrictLineEndingsEnabled() {
			// Strict mode: Reject bare LF terminators
			dh.logger.WarnContext(context.Background(), "Invalid end-of-data marker with bare LF (security violation)",
				"event_type", "smtp_smuggling_attempt",
				"line", fmt.Sprintf("%q", line),
				"line_count", state.LineCount,
				"remote_addr", dh.conn.RemoteAddr().String(),
				"pattern_type", "bare_lf_terminator",
			)

			// Log as security event
			LogSecurityEvent(dh.logger, "bare_lf_terminator", "smtp_smuggling",
				"End-of-data marker with bare LF instead of CRLF", line, dh.conn.RemoteAddr().String())

			*suspiciousPatterns++
			return false
		} else {
			// Legacy mode: Accept but warn
			dh.logger.WarnContext(context.Background(), "Legacy end-of-data marker with bare LF (RFC 5321 violation)",
				"event_type", "rfc_violation",
				"line", fmt.Sprintf("%q", line),
				"line_count", state.LineCount,
				"remote_addr", dh.conn.RemoteAddr().String(),
				"security_warning", "Consider enabling strict_line_endings for better security",
			)
			return true
		}
	}

	// Check for suspicious patterns that could indicate SMTP smuggling
	if strings.HasPrefix(line, ".") {
		*suspiciousPatterns++

		// Log suspicious patterns for security monitoring
		dh.logger.WarnContext(context.Background(), "Suspicious dot-prefixed line detected",
			"event_type", "suspicious_pattern",
			"line", fmt.Sprintf("%q", line),
			"line_count", state.LineCount,
			"remote_addr", dh.conn.RemoteAddr().String(),
			"pattern_type", "malformed_end_of_data",
		)

		// Log as security event if it looks like an attempted terminator
		if len(line) <= 5 { // Likely an attempted terminator
			LogSecurityEvent(dh.logger, "malformed_terminator", "smtp_smuggling",
				"Malformed end-of-data terminator detected", line, dh.conn.RemoteAddr().String())
		}
	}

	return false
}

// applyDotStuffing implements RFC 5321 §4.5.2 transparent dot-stuffing
// Lines starting with "." have the second "." removed during DATA reception
func (dh *DataHandler) applyDotStuffing(ctx context.Context, line []byte, state *DataReaderState) []byte {
	// RFC 5321 §4.5.2: Before sending a line of mail text, the SMTP client
	// checks the first character of the line. If it is a period, another
	// period is inserted at the beginning of the line. On receipt, the server
	// deletes the leading period from *any* line that begins with one — not
	// just from lines beginning "..". The end-of-data marker is checked before
	// this function is reached, so a bare "." line never arrives here.
	//
	// Only stripping ".." left a non-conforming ".foo" intact, which the
	// outbound side would then re-stuff to "..foo"; the receiving end saw
	// ".foo" where the sender meant "foo". Interpreting a leading period
	// differently from the next hop is the seam SMTP smuggling exploits, so
	// this follows the RFC exactly.
	if len(line) >= 1 && line[0] == '.' {
		dh.logger.DebugContext(ctx, "Applying transparent dot-stuffing",
			"line_number", state.LineCount,
			"original_line", fmt.Sprintf("%q", string(line)),
			"processed_line", fmt.Sprintf("%q", string(line[1:])),
		)
		return line[1:] // Remove the leading period
	}

	return line // No dot-stuffing needed
}

// validateLineEndings validates line endings per RFC 5321 § 2.3.7
func (dh *DataHandler) validateLineEndings(ctx context.Context, line []byte, state *DataReaderState) error {
	// RFC 5321 § 2.3.7: Lines are terminated by CRLF (\r\n)
	// Bare CR (\r without \n) and bare LF (\n without \r) are not allowed

	if len(line) == 0 {
		return nil // Empty line is okay (shouldn't happen with ReadBytes('\n') but be safe)
	}

	// Check what we have
	hasCR := len(line) >= 2 && line[len(line)-2] == '\r'
	hasLF := line[len(line)-1] == '\n'

	// Case 1: Proper CRLF termination
	if hasCR && hasLF {
		return nil // Valid RFC 5321 line ending
	}

	// Case 2: Bare LF (no CR before LF)
	if !hasCR && hasLF {
		if dh.config.StrictLineEndingsEnabled() {
			// Strict mode: Reject bare LF
			dh.logger.WarnContext(ctx, "Bare LF detected in message data (RFC 5321 violation)",
				"event_type", "rfc_violation",
				"line_number", state.LineCount,
				"remote_addr", dh.conn.RemoteAddr().String(),
				"security_threat", "smtp_smuggling",
			)

			// Log as security event
			LogSecurityEvent(dh.logger, "bare_lf_in_data", "smtp_smuggling",
				"Bare LF (0x0A) without CR (0x0D) detected in message data",
				fmt.Sprintf("line %d", state.LineCount), dh.conn.RemoteAddr().String())

			return fmt.Errorf("500 5.5.2 Syntax error: bare LF not allowed (RFC 5321 violation)")
		} else {
			// Legacy mode: Accept but warn
			if state.LineCount%100 == 1 { // Log every 100 lines to avoid spam
				dh.logger.WarnContext(ctx, "Bare LF accepted in legacy mode (RFC 5321 violation)",
					"event_type", "rfc_violation",
					"line_number", state.LineCount,
					"remote_addr", dh.conn.RemoteAddr().String(),
					"security_warning", "Consider enabling strict_line_endings for better security",
				)
			}
			return nil
		}
	}

	// Case 3: Bare CR (CR without LF) - This shouldn't happen with ReadBytes('\n')
	// but could occur if data is malformed
	if hasCR && !hasLF {
		dh.logger.WarnContext(ctx, "Bare CR detected in message data (RFC 5321 violation)",
			"event_type", "rfc_violation",
			"line_number", state.LineCount,
			"remote_addr", dh.conn.RemoteAddr().String(),
			"security_threat", "smtp_smuggling",
		)

		// Log as security event
		LogSecurityEvent(dh.logger, "bare_cr_in_data", "smtp_smuggling",
			"Bare CR (0x0D) without LF (0x0A) detected in message data",
			fmt.Sprintf("line %d", state.LineCount), dh.conn.RemoteAddr().String())

		return fmt.Errorf("500 5.5.2 Syntax error: bare CR not allowed (RFC 5321 violation)")
	}

	// Case 4: No line terminator at all (shouldn't happen with ReadBytes('\n'))
	dh.logger.WarnContext(ctx, "Line without proper terminator detected",
		"event_type", "protocol_error",
		"line_number", state.LineCount,
		"remote_addr", dh.conn.RemoteAddr().String(),
	)

	return fmt.Errorf("500 5.5.2 Syntax error: improper line termination")
}

// validateLineContent validates individual lines for security threats using enhanced validation
func (dh *DataHandler) validateLineContent(ctx context.Context, line string, state *DataReaderState) error {
	// RFC 5321 §4.5.3.1.6: Line Length Limits
	// The maximum total length of a text line including the <CRLF> is 1000 octets.
	// Receivers MUST be able to accept lines of at least 1000 octets.
	// Receivers SHOULD be able to accept longer lines.

	// Count octets (bytes), not characters - important for UTF-8
	lineBytes := len(line)

	// RFC 5321 MUST requirement: Support lines up to 1000 octets
	const maxLineLengthMust = 1000
	// SHOULD requirement: We support longer lines up to 2000 octets
	const maxLineLengthShould = 2000

	if lineBytes > maxLineLengthShould {
		// Hard limit exceeded - reject with 552 (message exceeds storage allocation)
		dh.logger.WarnContext(ctx, "Line length exceeds hard limit",
			"line_number", state.LineCount,
			"line_bytes", lineBytes,
			"max_allowed", maxLineLengthShould,
			"remote_addr", dh.conn.RemoteAddr().String(),
		)
		return fmt.Errorf("552 5.3.4 Line too long (%d octets, maximum %d)", lineBytes, maxLineLengthShould)
	}

	if lineBytes > maxLineLengthMust {
		// Warning: Line exceeds RFC 5321 MUST requirement but within SHOULD extension
		dh.logger.DebugContext(ctx, "Line length exceeds RFC 5321 MUST requirement but within SHOULD extension",
			"line_number", state.LineCount,
			"line_bytes", lineBytes,
			"rfc_must_limit", maxLineLengthMust,
			"current_limit", maxLineLengthShould,
		)
	}

	// Check if this is an internal connection - be more permissive for security validation
	isInternal := dh.isInternalConnection()

	if isInternal {
		// For internal connections, only check for obvious security threats
		if strings.Contains(line, "'; DROP TABLE") ||
			strings.Contains(line, "\"; DROP TABLE") ||
			strings.Contains(line, "UNION SELECT") ||
			strings.Contains(line, "<script") {
			return fmt.Errorf("500 5.5.2 Security violation detected")
		}

		dh.logger.DebugContext(ctx, "Using permissive security validation for internal connection",
			"remote_addr", dh.conn.RemoteAddr().String(),
			"in_headers", state.InHeaders,
		)

		return nil
	}

	// For external connections, use enhanced validator for comprehensive security validation
	// Note: We only apply enhanced validation for lines within the MUST limit (1000 octets)
	// to avoid the enhanced validator's line length check from conflicting with our
	// RFC 5321 SHOULD extension (up to 2000 octets)
	if lineBytes <= maxLineLengthMust {
		validationResult := dh.enhancedValidator.ValidateSMTPParameter("DATA_LINE", line)

		if !validationResult.Valid {
			// Check if the failure is due to line length - if so, ignore it
			// since we handle line length validation above with proper RFC 5321 compliance
			if !strings.Contains(validationResult.ErrorMessage, "Line exceeds") {
				// Log security event for failed validation
				LogSecurityEvent(dh.logger, "line_validation_failed", validationResult.SecurityThreat,
					validationResult.ErrorMessage, line, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Line validation failed",
					"error_type", validationResult.ErrorType,
					"error_message", validationResult.ErrorMessage,
					"security_threat", validationResult.SecurityThreat,
					"security_score", validationResult.SecurityScore,
					"line_number", state.LineCount,
				)

				return fmt.Errorf("500 5.5.2 Security violation: %s", validationResult.ErrorMessage)
			}
		}

		dh.logger.DebugContext(ctx, "Using enhanced validation for external connection",
			"remote_addr", dh.conn.RemoteAddr().String(),
			"in_headers", state.InHeaders,
			"security_score", validationResult.SecurityScore,
		)
	} else {
		// For lines exceeding MUST limit but within SHOULD limit,
		// perform basic security checks without enhanced validator
		dh.logger.DebugContext(ctx, "Skipping enhanced validation for long line within SHOULD limit",
			"line_bytes", lineBytes,
			"remote_addr", dh.conn.RemoteAddr().String(),
		)

		// Basic security checks for long lines
		if strings.Contains(line, "'; DROP TABLE") ||
			strings.Contains(line, "\"; DROP TABLE") ||
			strings.Contains(line, "UNION SELECT") ||
			strings.Contains(line, "<script") {
			return fmt.Errorf("500 5.5.2 Security violation detected")
		}
	}

	// Additional header-specific validation for external connections (only for lines within MUST limit)
	if state.InHeaders && lineBytes <= maxLineLengthMust {
		dh.logger.DebugContext(ctx, "Applying strict header validation for external connection")
		return dh.validateHeaderLine(ctx, line)
	}

	return nil
}

// addServerHeaders adds server-generated headers to the message
func (dh *DataHandler) buildServerHeaders(ctx context.Context, data []byte, metadata *MessageMetadata, scanResult *SecurityScanResult) []byte {
	// Build the block this hop contributes.
	//
	// RFC 5321 §4.4 requires the trace record to go at the top of the mail
	// data, so the whole block is prepended rather than spliced in at the end
	// of the submitter's header block. Appending put this hop's Received below
	// the sender's own headers, which reverses the trace order a downstream
	// reader relies on and makes multi-hop loop detection unreliable.
	//
	// Prepending is also what allows the message body to be streamed: the
	// server never has to parse or rebuild the submission, it just writes its
	// own headers ahead of the bytes it received.
	var additionalHeaders []string

	receivedTime := time.Now().Format(time.RFC1123Z)
	sanitizedFrom := sanitizeEmailForHeader(metadata.From)
	sanitizedTo := make([]string, len(metadata.To))
	for i, addr := range metadata.To {
		sanitizedTo[i] = sanitizeEmailForHeader(addr)
	}
	receivedHeader := fmt.Sprintf("Received: from %s (%s)\r\n\tby %s with ESMTP id %s\r\n\t(envelope-from <%s>)\r\n\tfor <%s>; %s",
		dh.config.Hostname,
		dh.conn.RemoteAddr().String(),
		dh.config.Hostname,
		metadata.MessageID,
		sanitizedFrom,
		strings.Join(sanitizedTo, ", "),
		receivedTime,
	)
	additionalHeaders = append(additionalHeaders, receivedHeader)

	// Add security scan headers
	if scanResult != nil {
		if scanResult.VirusFound {
			additionalHeaders = append(additionalHeaders, "X-Virus-Scanned: Yes")
			additionalHeaders = append(additionalHeaders, "X-Virus-Status: INFECTED")
		} else {
			additionalHeaders = append(additionalHeaders, "X-Virus-Scanned: Clean (Elemta)")
		}

		spamStatus := "No"
		if scanResult.SpamDetected {
			spamStatus = "Yes"
		}
		additionalHeaders = append(additionalHeaders, "X-Spam-Scanned: Yes")
		additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Spam-Status: %s, score=%.1f/10.0", spamStatus, scanResult.SpamScore))
		additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Spam-Score: %.1f", scanResult.SpamScore))
	}

	// Add server identification headers
	additionalHeaders = append(additionalHeaders, "X-Elemta-Version: 1.0")
	additionalHeaders = append(additionalHeaders, "X-Processed-By: Elemta MTA")
	additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Message-ID: %s", metadata.MessageID))

	prefix := strings.Join(additionalHeaders, "\r\n") + "\r\n"

	// A submission with no header/body separator has no headers of its own, so
	// this hop's block becomes the header section and needs a blank line to
	// separate it from the content.
	if !bytes.Contains(data, []byte("\r\n\r\n")) && !bytes.Contains(data, []byte("\n\n")) {
		prefix += "\r\n"
	}

	slog.LogAttrs(ctx, slog.LevelDebug, "Server headers built",
		slog.Int("header_bytes", len(prefix)),
		slog.Int("message_bytes", len(data)),
	)

	// Only the prefix is returned. Concatenating it with the message here would
	// allocate a second full copy of every message; instead the caller writes
	// the prefix ahead of the body, which for a spooled message means the body
	// never has to be copied at all.
	return []byte(prefix)
}

// isInternalConnection checks if the connection is from internal Docker network
func (dh *DataHandler) isInternalConnection() bool {
	if dh.conn == nil {
		return false
	}

	remoteAddr := dh.conn.RemoteAddr().String()

	// Check for Docker internal networks (172.x.x.x range)
	if strings.HasPrefix(remoteAddr, "172.") {
		return true
	}

	// Check for localhost connections (IPv4 and IPv6)
	if strings.HasPrefix(remoteAddr, "127.") ||
		strings.HasPrefix(remoteAddr, "[::1]") ||
		strings.Contains(remoteAddr, "::1") {
		return true
	}

	// Check for Docker bridge network (10.x.x.x range)
	if strings.HasPrefix(remoteAddr, "10.") {
		return true
	}

	return false
}

// validateHeaderLine validates message header lines
func (dh *DataHandler) validateHeaderLine(ctx context.Context, line string) error {
	// Check for header continuation (starts with whitespace) BEFORE trimming
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return nil // Valid header continuation
	}

	line = strings.TrimSpace(line)

	// Empty lines are allowed in headers
	if line == "" {
		return nil
	}

	// Check for valid header format: "Name: Value"
	if !strings.Contains(line, ":") {
		dh.logger.DebugContext(ctx, "Header validation failed: no colon found", "line", line)
		return fmt.Errorf("invalid header format")
	}

	parts := strings.SplitN(line, ":", 2)
	headerName := strings.TrimSpace(parts[0])
	headerValue := strings.TrimSpace(parts[1])

	// Validate header name
	if headerName == "" {
		return fmt.Errorf("empty header name")
	}

	// Check for valid header name characters (RFC 5322)
	for _, char := range headerName {
		//nolint:staticcheck // Readable as-is, De Morgan's law would make it less clear
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return fmt.Errorf("invalid header name character")
		}
	}

	// Validate specific headers
	return dh.validateSpecificHeader(ctx, headerName, headerValue)
}

// validateSpecificHeader validates specific header types
func (dh *DataHandler) validateSpecificHeader(ctx context.Context, name, value string) error {
	name = strings.ToLower(name)

	switch name {
	case "content-type":
		return dh.validateContentTypeHeader(value)
	case "from", "to", "cc", "bcc", "reply-to":
		return dh.validateEmailHeaders(value)
	case "date":
		return dh.validateDateHeader(value)
	case "message-id":
		return dh.validateMessageIDHeader(value)
	}

	return nil
}

// validateContentTypeHeader validates Content-Type headers
func (dh *DataHandler) validateContentTypeHeader(value string) error {
	// Reject empty content type
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("empty content type")
	}

	// Allow common content types and parameters
	if strings.Contains(value, ";") {
		// Handle parameters like charset, boundary
		parts := strings.Split(value, ";")
		contentType := strings.TrimSpace(parts[0])
		if contentType == "" {
			return fmt.Errorf("empty content type")
		}
	}
	return nil
}

// validateEmailHeaders validates email address headers
func (dh *DataHandler) validateEmailHeaders(value string) error {
	// Basic email header validation
	if len(value) > 1000 {
		return fmt.Errorf("email header too long")
	}
	return nil
}

// validateDateHeader validates Date headers
func (dh *DataHandler) validateDateHeader(value string) error {
	// Basic date header validation
	if len(value) > 100 {
		return fmt.Errorf("date header too long")
	}
	return nil
}

// validateMessageIDHeader validates Message-ID headers
func (dh *DataHandler) validateMessageIDHeader(value string) error {
	// Basic Message-ID validation
	if len(value) > 1000 {
		return fmt.Errorf("message-id too long")
	}
	return nil
}

// extractMessageMetadata extracts metadata from the message
func (dh *DataHandler) extractMessageMetadata(ctx context.Context, data []byte) (*MessageMetadata, error) {
	metadata := &MessageMetadata{
		MessageID: uuid.New().String(),
		From:      dh.state.GetMailFrom(),
		To:        dh.state.GetRecipients(),
		Date:      time.Now(),
		Size:      int64(len(data)),
		Headers:   make(map[string]string),
	}

	// Calculate checksum
	hash := sha256.Sum256(data)
	metadata.Checksum = fmt.Sprintf("%x", hash)

	// Extract headers
	headers := dh.extractHeaders(data)
	for name, value := range headers {
		metadata.Headers[strings.ToLower(name)] = value
	}

	// Extract specific fields
	if subject, exists := metadata.Headers["subject"]; exists {
		metadata.Subject = subject
	}

	if msgID, exists := metadata.Headers["message-id"]; exists {
		metadata.MessageID = msgID
	}

	dh.logger.DebugContext(ctx, "Message metadata extracted",
		"message_id", metadata.MessageID,
		"from", metadata.From,
		"recipients", len(metadata.To),
		"subject", metadata.Subject,
		"size", metadata.Size,
	)

	return metadata, nil
}

// extractHeaders extracts headers from message data
func (dh *DataHandler) extractHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	var currentHeader string
	var currentValue strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Empty line indicates end of headers
		if line == "" {
			if currentHeader != "" {
				headers[currentHeader] = currentValue.String()
			}
			break
		}

		// Check for header continuation
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentHeader != "" {
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
			continue
		}

		// Save previous header
		if currentHeader != "" {
			headers[currentHeader] = currentValue.String()
		}

		// Parse new header
		if colonIndex := strings.Index(line, ":"); colonIndex > 0 {
			currentHeader = strings.TrimSpace(line[:colonIndex])
			currentValue.Reset()
			currentValue.WriteString(strings.TrimSpace(line[colonIndex+1:]))
		} else {
			currentHeader = ""
			currentValue.Reset()
		}
	}

	return headers
}

// validateMessageHeaders validates message headers using enhanced validation
func (dh *DataHandler) validateMessageHeaders(ctx context.Context, metadata *MessageMetadata) error {
	// Skip strict header requirements for internal connections (like Roundcube) or if auth is not required
	isInternal := dh.isInternalConnection()
	authNotRequired := dh.config.Auth != nil && dh.config.Auth.Enabled && !dh.config.Auth.Required

	if !isInternal && !authNotRequired {
		// Check required headers only for external connections when auth is required
		requiredHeaders := []string{"from", "date"}
		for _, header := range requiredHeaders {
			if _, exists := metadata.Headers[header]; !exists {
				dh.logger.WarnContext(ctx, "Missing required header", "header", header)
				return fmt.Errorf("missing required header: %s", header)
			}
		}
	} else {
		if isInternal {
			dh.logger.DebugContext(ctx, "Skipping strict header requirements for internal connection")
		} else {
			dh.logger.DebugContext(ctx, "Skipping strict header requirements - authentication not required")
		}
	}

	// Use enhanced validator to validate all headers comprehensively (only for external connections)
	if !isInternal {
		headersStr := dh.buildHeadersString(metadata.Headers)
		headerValidationResult := dh.enhancedValidator.ValidateEmailHeaders(headersStr)

		if !headerValidationResult.Valid {
			// Log security event for failed header validation
			LogSecurityEvent(dh.logger, "header_validation_failed", headerValidationResult.SecurityThreat,
				headerValidationResult.ErrorMessage, headersStr, dh.conn.RemoteAddr().String())

			dh.logger.WarnContext(ctx, "Header validation failed",
				"error_type", headerValidationResult.ErrorType,
				"error_message", headerValidationResult.ErrorMessage,
				"security_threat", headerValidationResult.SecurityThreat,
				"security_score", headerValidationResult.SecurityScore,
			)

			return fmt.Errorf("header validation failed: %s", headerValidationResult.ErrorMessage)
		}

		dh.logger.DebugContext(ctx, "Header validation completed successfully",
			"security_score", headerValidationResult.SecurityScore,
			"header_count", headerValidationResult.ValidationDetails["header_count"],
		)
	} else {
		dh.logger.DebugContext(ctx, "Skipping enhanced header validation for internal connection")
	}

	// Validate From header matches MAIL FROM
	if fromHeader, exists := metadata.Headers["from"]; exists {
		if err := dh.validateFromHeader(ctx, fromHeader, metadata.From); err != nil {
			return err
		}
	}

	// Validate email addresses in headers (only for external connections)
	if !isInternal {
		if err := dh.validateEmailAddressesInHeaders(ctx, metadata.Headers); err != nil {
			return err
		}

		// Validate content-type restrictions
		if err := dh.validateContentTypeRestrictions(ctx, metadata.Headers); err != nil {
			return err
		}
	} else {
		dh.logger.DebugContext(ctx, "Skipping email address and content-type validation for internal connection")
	}

	return nil
}

// buildHeadersString builds a string representation of headers for validation
func (dh *DataHandler) buildHeadersString(headers map[string]string) string {
	var headerLines []string
	for name, value := range headers {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", name, value))
	}
	return strings.Join(headerLines, "\n")
}

// validateEmailAddressesInHeaders validates email addresses in headers
func (dh *DataHandler) validateEmailAddressesInHeaders(ctx context.Context, headers map[string]string) error {
	emailHeaders := []string{"from", "to", "cc", "bcc", "reply-to"}

	for _, headerName := range emailHeaders {
		if headerValue, exists := headers[headerName]; exists {
			// Use enhanced validator to validate email addresses
			validationResult := dh.enhancedValidator.ValidateSMTPParameter("MAIL_FROM", headerValue)

			if !validationResult.Valid {
				LogSecurityEvent(dh.logger, "email_header_validation_failed", validationResult.SecurityThreat,
					validationResult.ErrorMessage, headerValue, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Email header validation failed",
					"header", headerName,
					"error_type", validationResult.ErrorType,
					"error_message", validationResult.ErrorMessage,
					"security_threat", validationResult.SecurityThreat,
				)

				return fmt.Errorf("invalid email address in %s header: %s", headerName, validationResult.ErrorMessage)
			}
		}
	}

	return nil
}

// validateContentTypeRestrictions validates content-type restrictions
func (dh *DataHandler) validateContentTypeRestrictions(ctx context.Context, headers map[string]string) error {
	if contentType, exists := headers["content-type"]; exists {
		// Check for dangerous content types
		dangerousContentTypes := []string{
			"application/x-msdownload",    // Windows executables
			"application/x-executable",    // Executables
			"application/x-sh",            // Shell scripts
			"application/x-bat",           // Batch files
			"application/x-cmd",           // Command files
			"application/x-msdos-program", // DOS programs
			"application/x-winexe",        // Windows executables
		}

		contentTypeLower := strings.ToLower(contentType)
		for _, dangerous := range dangerousContentTypes {
			if strings.Contains(contentTypeLower, dangerous) {
				LogSecurityEvent(dh.logger, "dangerous_content_type", "attachment_threat",
					"Dangerous content type detected", contentType, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Dangerous content type detected",
					"content_type", contentType,
					"threat_type", "executable_attachment",
				)

				return fmt.Errorf("dangerous content type not allowed: %s", contentType)
			}
		}

		// Validate content-type format
		validationResult := dh.enhancedValidator.validateHeaderSecurityPatterns("content-type", contentType)
		if !validationResult.Valid {
			LogSecurityEvent(dh.logger, "content_type_validation_failed", validationResult.SecurityThreat,
				validationResult.ErrorMessage, contentType, dh.conn.RemoteAddr().String())

			return fmt.Errorf("invalid content-type header: %s", validationResult.ErrorMessage)
		}
	}

	return nil
}

// validateFromHeader validates the From header against MAIL FROM
func (dh *DataHandler) validateFromHeader(ctx context.Context, fromHeader, mailFrom string) error {
	// Extract email from From header (may contain display name)
	emailRegex := regexp.MustCompile(`<([^>]+)>|([^\s<>]+@[^\s<>]+)`)
	matches := emailRegex.FindStringSubmatch(fromHeader)

	var headerEmail string
	if len(matches) > 1 && matches[1] != "" {
		headerEmail = matches[1]
	} else if len(matches) > 2 && matches[2] != "" {
		headerEmail = matches[2]
	}

	// Compare with MAIL FROM (allow some flexibility)
	if headerEmail != "" && mailFrom != "" {
		if !strings.EqualFold(headerEmail, mailFrom) {
			dh.logger.WarnContext(ctx, "From header mismatch",
				"from_header", headerEmail,
				"mail_from", mailFrom,
			)
			// Log but don't reject - some legitimate cases exist
		}
	}

	return nil
}

// scanContent holds the message once as a string and once lowercased, so the
// content scans share those two allocations instead of each making their own.
//
// The scans are substring matches over the whole message and most are
// case-insensitive. Lowercasing inside the pattern loops meant a fresh copy of
// the entire message per pattern: measured at roughly fifteen times the message
// size in garbage per delivery, which for a 25MB message is several hundred
// megabytes of allocation and about a second of CPU.
type scanContent struct {
	raw   string
	lower string
}

func newScanContent(data []byte) *scanContent {
	raw := string(data)
	return &scanContent{raw: raw, lower: strings.ToLower(raw)}
}

// mergeScanResult folds one scan's findings into the combined result.
//
// A failure in either scan fails the message, and threats accumulate, so the
// order the concurrent scans finish in does not change the outcome.
func mergeScanResult(dst, src *SecurityScanResult) {
	if !src.Passed {
		dst.Passed = false
	}
	if src.VirusFound {
		dst.VirusFound = true
	}
	if src.SpamDetected {
		dst.SpamDetected = true
	}
	if src.SpamScore > dst.SpamScore {
		dst.SpamScore = src.SpamScore
	}
	dst.Threats = append(dst.Threats, src.Threats...)
}

// performSecurityScan performs comprehensive security scanning
func (dh *DataHandler) performSecurityScan(ctx context.Context, data []byte, metadata *MessageMetadata) (*SecurityScanResult, error) {
	result := &SecurityScanResult{
		Passed:  true,
		Threats: make([]string, 0),
	}

	// The scans below are substring matches over the whole message, most of
	// them case-insensitive. Lowercasing per pattern allocated a fresh copy of
	// the message every time — around fifteen times the message size in
	// garbage per delivery, and the dominant cost of accepting a large message.
	// Build both views once and share them.
	view := newScanContent(data)

	// The antivirus and antispam scans are independent network round trips to
	// separate services, so they run concurrently. In sequence their latencies
	// add; overlapped, the pair costs about max(av, spam) rather than the sum.
	//
	// No throughput figure is claimed for this. Attempts to measure it here
	// varied by more than tenfold across consecutive identical runs — 5 to 55
	// messages a second — with all three containers near-idle on CPU, so the
	// cost is dominated by external lookups rather than by anything this
	// change affects. The reasoning stands on the shape of the work, not on a
	// benchmark that could not be reproduced.
	//
	// Each writes into its own result, merged below, because they would
	// otherwise race on the shared one.
	//
	// These used to be gated on builtinPlugins being non-nil, which was only
	// ever a proxy for "plugins are configured" — the plugins themselves were
	// never asked to scan anything. Each scan now decides for itself whether a
	// scanner is available.
	var (
		wg         sync.WaitGroup
		virusScan  = &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
		spamScan   = &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
		virusErr   error
		spamScnErr error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer func() {
			// A panic in a scan must not take the session down with it.
			if r := recover(); r != nil {
				virusErr = fmt.Errorf("antivirus scan panicked: %v", r)
			}
		}()
		virusErr = dh.performAntivirusScan(ctx, view, virusScan)
	}()
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				spamScnErr = fmt.Errorf("spam scan panicked: %v", r)
			}
		}()
		spamScnErr = dh.performSpamScan(ctx, view, metadata, spamScan)
	}()
	wg.Wait()

	if virusErr != nil {
		dh.logger.ErrorContext(ctx, "Antivirus scan failed", "error", virusErr)
		return nil, virusErr
	}
	if spamScnErr != nil {
		dh.logger.ErrorContext(ctx, "Spam scan failed", "error", spamScnErr)
		return nil, spamScnErr
	}

	mergeScanResult(result, virusScan)
	mergeScanResult(result, spamScan)

	// Perform content analysis
	if err := dh.performContentAnalysis(ctx, view, result); err != nil {
		dh.logger.ErrorContext(ctx, "Content analysis failed", "error", err)
		return nil, err
	}

	dh.logger.DebugContext(ctx, "Security scan completed",
		"passed", result.Passed,
		"threats", len(result.Threats),
		"spam_score", result.SpamScore,
		"virus_found", result.VirusFound,
	)

	return result, nil
}

// performAntivirusScan performs antivirus scanning
func (dh *DataHandler) performAntivirusScan(ctx context.Context, view *scanContent, result *SecurityScanResult) error {
	if dh.scannerManager == nil || !dh.scannerManager.HasAntivirusScanners() {
		return nil
	}

	results, err := dh.scannerManager.ScanForViruses(ctx, []byte(view.raw))
	if err != nil {
		// A scanner that is down must not take mail down with it. The message
		// is delivered unscanned and the failure is recorded.
		dh.logger.WarnContext(ctx, "Antivirus scan failed; delivering message unscanned",
			"error", err,
		)
		return nil
	}

	for _, r := range results {
		if r == nil || r.Clean {
			continue
		}

		result.Passed = false
		result.VirusFound = true
		for _, infection := range r.Infections {
			result.Threats = append(result.Threats, "Virus detected: "+infection)
		}
		if len(r.Infections) == 0 {
			result.Threats = append(result.Threats, "Virus detected by "+r.Engine)
		}

		dh.logger.WarnContext(ctx, "Virus detected",
			"event_type", "virus_detected",
			"engine", r.Engine,
			"infections", r.Infections,
			"remote_addr", dh.conn.RemoteAddr().String(),
		)
	}

	return nil
}

// performSpamScan performs spam detection
func (dh *DataHandler) performSpamScan(ctx context.Context, view *scanContent, metadata *MessageMetadata, result *SecurityScanResult) error {
	if dh.scannerManager == nil || !dh.scannerManager.HasAntispamScanners() {
		return nil
	}

	results, err := dh.scannerManager.ScanForSpam(ctx, []byte(view.raw))
	if err != nil {
		dh.logger.WarnContext(ctx, "Spam scan failed; delivering message unscored",
			"error", err,
		)
		return nil
	}

	// Several engines may report; the highest score decides, and any engine
	// calling the message spam is enough to mark it.
	var highest float64
	spam := false
	for _, r := range results {
		if r == nil {
			continue
		}
		if r.Score > highest {
			highest = r.Score
		}
		if !r.Clean {
			spam = true
			dh.logger.InfoContext(ctx, "spam_detected",
				"event_type", "spam_detected",
				"engine", r.Engine,
				"spam_score", r.Score,
				"threshold", r.Threshold,
				"rules", r.Rules,
				"message_id", metadata.MessageID,
				"from_envelope", metadata.From,
			)
		}
	}

	result.SpamScore = highest
	if spam {
		result.SpamDetected = true
		result.Threats = append(result.Threats, fmt.Sprintf("Message identified as spam (score %.1f)", highest))
		// Only refuse the message if the operator asked for that. Otherwise it
		// is delivered carrying the spam headers, and filtering happens later.
		if dh.config.Antispam != nil && dh.config.Antispam.RejectOnSpam {
			result.Passed = false
		}
	}

	return nil
}

// performContentAnalysis performs comprehensive content analysis
func (dh *DataHandler) performContentAnalysis(ctx context.Context, view *scanContent, result *SecurityScanResult) error {
	content := view.raw

	// Check if this is an internal connection - be more permissive for internal connections
	isInternal := dh.isInternalConnection()

	// For internal connections, only do basic content analysis
	if isInternal {
		dh.logger.DebugContext(ctx, "Using permissive content analysis for internal connection",
			"remote_addr", dh.conn.RemoteAddr().String(),
		)

		// Only check for obvious security threats in internal connections
		if strings.Contains(content, "'; DROP TABLE") ||
			strings.Contains(content, "\"; DROP TABLE") ||
			strings.Contains(content, "UNION SELECT") ||
			strings.Contains(content, "<script") {
			result.Passed = false
			result.Threats = append(result.Threats, "Basic security violation detected")
			dh.logger.WarnContext(ctx, "Basic security violation detected in internal connection",
				"remote_addr", dh.conn.RemoteAddr().String(),
			)
		}
		return nil
	}

	// For external connections, use enhanced validator for comprehensive content analysis
	// Separate headers and body to avoid false positives on legitimate headers
	headers, _ := dh.separateHeadersAndBody(content)

	// Validate headers separately (more permissive for legitimate headers)
	if headers != "" {
		headerValidationResult := dh.enhancedValidator.ValidateSMTPParameter("HEADER", headers)
		if !headerValidationResult.Valid {
			result.Passed = false
			result.Threats = append(result.Threats, fmt.Sprintf("Header validation failed: %s", headerValidationResult.ErrorMessage))

			LogSecurityEvent(dh.logger, "content_analysis_failed", headerValidationResult.SecurityThreat,
				headerValidationResult.ErrorMessage, headers[:min(200, len(headers))], dh.conn.RemoteAddr().String())

			dh.logger.WarnContext(ctx, "Header analysis failed",
				"error_type", headerValidationResult.ErrorType,
				"security_threat", headerValidationResult.SecurityThreat,
				"security_score", headerValidationResult.SecurityScore,
			)
		}
	}

	// The message body is deliberately not validated as a block here.
	//
	// Everything this pass used to contribute is already enforced per line by
	// validateLineContent as the data arrives: RFC 5321 line length (1000 MUST,
	// 2000 SHOULD) and dangerous control characters both reject there.
	//
	// What it added on top was a pair of regexes matching a blank line followed
	// by a header line, intended as header-injection detection. Those match
	// ordinary mail — a forwarded message ("---------- Forwarded message
	// ---------" then "From:"), or a quoted reply containing "To:" after a
	// blank line — so enforcing them refuses common legitimate traffic. They
	// also guard something unreachable: content below the header/body separator
	// cannot become a header at the next hop, because the separator is
	// unambiguous and preserved on relay.
	//
	// None of this had ever run in production. The block was called as
	// ValidateSMTPParameter("DATA_LINE", body), which applies the *per-line*
	// 1000-octet limit to the whole body, so any external sender with a body
	// over 1000 octets was rejected as "line_too_long" before reaching the
	// injection patterns at all. Loopback and Docker peers take the internal
	// branch above, which is why no test or local run ever saw it.

	// Check for executable attachments (enhanced check)
	if strings.Contains(content, "Content-Type: application/") {
		dangerousTypes := []string{
			"application/x-msdownload",
			"application/x-executable",
			"application/x-sh",
			"application/x-bat",
			"application/x-cmd",
			"application/x-msdos-program",
			"application/x-winexe",
			"application/octet-stream",
		}

		for _, dangerousType := range dangerousTypes {
			if strings.Contains(view.lower, dangerousType) {
				result.Passed = false
				result.Threats = append(result.Threats, fmt.Sprintf("Dangerous attachment type: %s", dangerousType))

				LogSecurityEvent(dh.logger, "dangerous_attachment", "attachment_threat",
					"Dangerous attachment type detected", dangerousType, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Dangerous attachment detected",
					"attachment_type", dangerousType,
					"threat_type", "executable_attachment",
				)
			}
		}
	}

	// Check for embedded scripts and malicious content
	maliciousPatterns := []string{
		"<script",
		"javascript:",
		"vbscript:",
		"data:text/html",
		"eval(",
		"expression(",
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(view.lower, pattern) {
			result.Threats = append(result.Threats, fmt.Sprintf("Malicious content pattern: %s", pattern))
			dh.logger.WarnContext(ctx, "Malicious content pattern detected",
				"pattern", pattern,
				"threat_type", "malicious_content",
			)
		}
	}

	// Check for suspicious file extensions in attachments (but not in email addresses)
	suspiciousExtensions := []string{
		".exe", ".bat", ".cmd", ".pif", ".scr", ".vbs", ".js",
		".jar", ".app", ".deb", ".rpm", ".dmg", ".pkg", ".msi",
	}

	// Only check for .com if it's not part of an email address
	contentLower := view.lower
	for _, ext := range suspiciousExtensions {
		if strings.Contains(contentLower, ext) {
			// Special handling for .com - only flag if it's not in an email address
			if ext == ".com" {
				// Check if .com is part of an email address pattern
				if strings.Contains(contentLower, "@") && strings.Contains(contentLower, ".com") {
					// This is likely an email address, skip
					continue
				}
			}

			result.Threats = append(result.Threats, fmt.Sprintf("Suspicious file extension: %s", ext))
			dh.logger.WarnContext(ctx, "Suspicious file extension detected",
				"extension", ext,
				"threat_type", "suspicious_attachment",
			)
		}
	}

	return nil
}

// separateHeadersAndBody separates email headers from the message body
func (dh *DataHandler) separateHeadersAndBody(content string) (headers, body string) {
	// Find the double CRLF that separates headers from body
	doubleCRLF := "\r\n\r\n"
	separatorIndex := strings.Index(content, doubleCRLF)

	if separatorIndex == -1 {
		// Try single CRLF as fallback
		singleCRLF := "\n\n"
		separatorIndex = strings.Index(content, singleCRLF)
		if separatorIndex == -1 {
			// No clear separation found, treat entire content as headers
			return content, ""
		}
		headers = content[:separatorIndex]
		body = content[separatorIndex+len(singleCRLF):]
	} else {
		headers = content[:separatorIndex]
		body = content[separatorIndex+len(doubleCRLF):]
	}

	return headers, body
}

// handleSecurityThreat handles detected security threats
func (dh *DataHandler) handleSecurityThreat(ctx context.Context, scanResult *SecurityScanResult, metadata *MessageMetadata) error {
	if scanResult.VirusFound {
		dh.logger.WarnContext(ctx, "Message rejected due to virus",
			"event_type", "rejection",
			"threats", scanResult.Threats,
			"message_id", metadata.MessageID,
		)

		// Log rejection event
		dh.msgLogger.LogRejection(logging.MessageContext{
			MessageID:      metadata.MessageID,
			QueueID:        metadata.MessageID,
			From:           metadata.From,
			To:             metadata.To,
			Subject:        metadata.Subject,
			Size:           metadata.Size,
			ClientIP:       dh.session.remoteAddr,
			ClientHostname: dh.session.remoteAddr,
			Username:       dh.state.GetUsername(),
			Authenticated:  dh.state.IsAuthenticated(),
			TLSActive:      dh.state.IsTLSActive(),
			ReceptionTime:  dh.receptionTime,
			ProcessingTime: time.Now(),
			Error:          "virus detected",
			VirusFound:     true,
		})

		return fmt.Errorf("554 5.7.1 Message rejected: virus detected")
	}

	if scanResult.SpamDetected {
		dh.logger.WarnContext(ctx, "Message rejected as spam",
			"event_type", "rejection",
			"spam_score", scanResult.SpamScore,
			"message_id", metadata.MessageID,
		)

		// Log rejection event
		dh.msgLogger.LogRejection(logging.MessageContext{
			MessageID:      metadata.MessageID,
			QueueID:        metadata.MessageID,
			From:           metadata.From,
			To:             metadata.To,
			Subject:        metadata.Subject,
			Size:           metadata.Size,
			ClientIP:       dh.session.remoteAddr,
			ClientHostname: dh.session.remoteAddr,
			Username:       dh.state.GetUsername(),
			Authenticated:  dh.state.IsAuthenticated(),
			TLSActive:      dh.state.IsTLSActive(),
			ReceptionTime:  dh.receptionTime,
			ProcessingTime: time.Now(),
			Error:          "identified as spam",
			SpamScore:      scanResult.SpamScore,
		})

		return fmt.Errorf("554 5.7.1 Message rejected: identified as spam")
	}

	// For lower threat levels, quarantine instead of reject
	if len(scanResult.Threats) > 0 {
		scanResult.Quarantined = true
		dh.logger.InfoContext(ctx, "Message quarantined due to security concerns",
			"threats", scanResult.Threats,
			"message_id", metadata.MessageID,
		)
	}

	return nil
}

// saveMessage saves the message to the queue
func (dh *DataHandler) saveMessage(ctx context.Context, headerPrefix []byte, body queue.ContentOpener, metadata *MessageMetadata) error {
	// The stored message is this hop's headers followed by the body exactly as
	// received. Composing them as a reader means a spooled message goes to the
	// queue disk-to-disk, without being assembled in memory first.
	open := func() (io.ReadCloser, error) {
		r, err := body()
		if err != nil {
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(headerPrefix), r),
			Closer: r,
		}, nil
	}

	msgID, err := dh.queueManager.EnqueueMessageStream(
		metadata.From,
		metadata.To,
		metadata.Subject,
		open,
		int64(len(headerPrefix))+dh.state.GetDataSize(),
		queue.PriorityNormal,
		dh.receptionTime,
	)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to enqueue message", "error", err)
		return fmt.Errorf("failed to save message: %w", err)
	}

	// Store DSN and REQUIRETLS annotations on the queued message. Delivery-time
	// enforcement of REQUIRETLS (RFC 8689) happens in the queue package's
	// SMTPDeliveryHandler, which mandates TLS and next-hop REQUIRETLS support
	// before sending mail carrying the require_tls annotation.
	dh.saveDSNAnnotations(ctx, msgID)

	// Log message reception with timing
	dh.msgLogger.LogReception(logging.MessageContext{
		MessageID:      metadata.MessageID,
		QueueID:        metadata.MessageID,
		From:           metadata.From,
		To:             metadata.To,
		Subject:        metadata.Subject,
		Size:           metadata.Size,
		ClientIP:       dh.session.remoteAddr,
		ClientHostname: dh.session.remoteAddr,
		Username:       dh.state.GetUsername(),
		Authenticated:  dh.state.IsAuthenticated(),
		TLSActive:      dh.state.IsTLSActive(),
		ReceptionTime:  dh.receptionTime,
		ProcessingTime: time.Now(),
	})

	// Note: Queue integration processing would be handled by the queue manager

	return nil
}

// saveDSNAnnotations stores DSN and REQUIRETLS annotations on a queued message
func (dh *DataHandler) saveDSNAnnotations(ctx context.Context, msgID string) {
	if dh.queueManager == nil {
		return
	}

	// Store DSN envelope params
	if dsnParams := dh.state.GetDSNParams(); dsnParams != nil {
		if dsnParams.Return != "" {
			if err := dh.queueManager.SetAnnotation(msgID, "dsn_return", string(dsnParams.Return)); err != nil {
				dh.logger.WarnContext(ctx, "Failed to set dsn_return annotation", "error", err)
			}
		}
		if dsnParams.EnvID != "" {
			if err := dh.queueManager.SetAnnotation(msgID, "dsn_envid", dsnParams.EnvID); err != nil {
				dh.logger.WarnContext(ctx, "Failed to set dsn_envid annotation", "error", err)
			}
		}
	}

	// Store per-recipient DSN params
	if rcptParams := dh.state.GetAllDSNRecipientParams(); rcptParams != nil {
		for addr, params := range rcptParams {
			if len(params.Notify) > 0 {
				notifyStrs := make([]string, len(params.Notify))
				for i, n := range params.Notify {
					notifyStrs[i] = string(n)
				}
				key := "dsn_notify:" + addr
				if err := dh.queueManager.SetAnnotation(msgID, key, strings.Join(notifyStrs, ",")); err != nil {
					dh.logger.WarnContext(ctx, "Failed to set dsn_notify annotation", "error", err, "recipient", addr)
				}
			}
			if params.ORCPT != "" {
				key := "dsn_orcpt:" + addr
				if err := dh.queueManager.SetAnnotation(msgID, key, params.ORCPT); err != nil {
					dh.logger.WarnContext(ctx, "Failed to set dsn_orcpt annotation", "error", err, "recipient", addr)
				}
			}
		}
	}

	// Store REQUIRETLS flag
	if dh.state.IsRequireTLS() {
		if err := dh.queueManager.SetAnnotation(msgID, "require_tls", "true"); err != nil {
			dh.logger.WarnContext(ctx, "Failed to set require_tls annotation", "error", err)
		}
	}
}
