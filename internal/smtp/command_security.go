package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// CommandSecurityManager provides comprehensive SMTP command injection prevention
type CommandSecurityManager struct {
	logger *slog.Logger
	config *CommandSecurityConfig

	// Compiled once from config. Compiling them on every command made each
	// line cost tens of microseconds before it was even recognised.
	commandChars   *regexp.Regexp
	parameterChars *regexp.Regexp
	blockedCommand []*regexp.Regexp
	blockedParam   []*regexp.Regexp
}

var (
	hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	emailPattern    = regexp.MustCompile(`^[a-zA-Z0-9._%+=/'!#*?^{}~-]+@([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|localhost)$`)
	// suspiciousPattern marks arguments worth a log line without refusing
	// them. Keywords are deliberately absent; see DefaultCommandSecurityConfig.
	suspiciousPattern = regexp.MustCompile("[;&|`$]|\\.\\./|\\.\\.\\\\|[\\x00-\\x08\\x0B\\x0C\\x0E\\x0F]")
)

// CommandSecurityConfig defines security policies for command validation
type CommandSecurityConfig struct {
	// Maximum command line length
	MaxCommandLength int
	// Maximum parameter length
	MaxParameterLength int
	// Allowed command characters (regex pattern)
	AllowedCommandChars string
	// Allowed parameter characters (regex pattern)
	AllowedParameterChars string
	// Blocked command patterns
	BlockedCommandPatterns []string
	// Blocked parameter patterns
	BlockedParameterPatterns []string
	// Enable strict mode (more aggressive filtering)
	StrictMode bool
	// Enable logging of suspicious commands
	LogSuspiciousCommands bool
	// Command processing timeout
	CommandTimeout time.Duration
}

// DefaultCommandSecurityConfig returns a secure default configuration
func DefaultCommandSecurityConfig() *CommandSecurityConfig {
	config := &CommandSecurityConfig{
		MaxCommandLength:    512, // RFC 5321 limit
		MaxParameterLength:  320, // RFC 5321 email address limit
		AllowedCommandChars: `^[A-Za-z0-9\-_]+$`,
		// RFC 5321 allows these characters in email local-part and parameters:
		// Letters, digits, and special chars: ! # $ % & ' * + - / = ? ^ _ ` { | } ~ . @ : < > [ ]
		AllowedParameterChars: "^[A-Za-z0-9\\-_@\\.:<>=\\s\\[\\]!#$%&'*\\+/?\\^`{|}~]+$",
		// No keyword lists. These used to refuse any argument containing
		// "select", "update", "create", "drop", "exec", "script" and so on,
		// anywhere and in any case. Nothing here builds SQL, shell or HTML
		// from a command argument, so the words blocked nothing real, while
		// they refused real senders at EHLO (mail.createsend.com,
		// mx.dropboxmail.com) and, because AUTH PLAIN base64 is mixed-case
		// letters, refused some users' credentials and logged them.
		BlockedCommandPatterns: []string{
			// Command injection patterns
			`[;&|` + "`" + `$]`,
			// Path traversal patterns
			`\.\./|\.\.\\`,
			// Control characters
			`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
		},
		BlockedParameterPatterns: []string{
			// Command injection patterns
			`[;&|` + "`" + `$]`,
			// Path traversal patterns
			`\.\./|\.\.\\`,
			// Control characters
			`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
			// CRLF injection
			`\r\n|\r|\n`,
		},
		StrictMode:            true,
		LogSuspiciousCommands: true,
		CommandTimeout:        30 * time.Second, // 30 second timeout for command processing
	}
	return config
}

// NewCommandSecurityManager creates a new command security manager
func NewCommandSecurityManager(logger *slog.Logger) *CommandSecurityManager {
	config := DefaultCommandSecurityConfig()
	compile := func(patterns []string) []*regexp.Regexp {
		out := make([]*regexp.Regexp, len(patterns))
		for i, p := range patterns {
			out[i] = regexp.MustCompile(p)
		}
		return out
	}
	return &CommandSecurityManager{
		logger:         logger.With("component", "command-security"),
		config:         config,
		commandChars:   regexp.MustCompile(config.AllowedCommandChars),
		parameterChars: regexp.MustCompile(config.AllowedParameterChars),
		blockedCommand: compile(config.BlockedCommandPatterns),
		blockedParam:   compile(config.BlockedParameterPatterns),
	}
}

// loggableArgs is a command's arguments as they may be logged. AUTH
// arguments are credentials (for PLAIN, the base64 of username and
// password), so only the mechanism is kept.
func loggableArgs(cmd, args string) string {
	if !strings.EqualFold(cmd, "AUTH") {
		return args
	}
	if fields := strings.Fields(args); len(fields) > 1 {
		return fields[0] + " [redacted]"
	}
	return args
}

// ValidateCommand performs comprehensive security validation on SMTP commands
func (csm *CommandSecurityManager) ValidateCommand(ctx context.Context, line string) error {
	// Create a context with timeout for command processing
	timeoutCtx, cancel := context.WithTimeout(ctx, csm.config.CommandTimeout)
	defer cancel()

	// Step 1: Basic length validation
	if err := csm.validateLength(timeoutCtx, line); err != nil {
		return err
	}

	// Step 2: UTF-8 validation
	if err := csm.validateUTF8(timeoutCtx, line); err != nil {
		return err
	}

	// Step 3: Control character filtering
	if err := csm.filterControlCharacters(timeoutCtx, line); err != nil {
		return err
	}

	// Step 4: Command canonicalization
	canonicalLine, err := csm.canonicalizeCommand(timeoutCtx, line)
	if err != nil {
		return err
	}

	// Step 5: Parse command and arguments
	cmd, args := csm.parseCommand(canonicalLine)

	// Step 6: Validate command structure
	if err := csm.validateCommandStructure(timeoutCtx, cmd, args); err != nil {
		return err
	}

	// Step 7: Validate command name
	if err := csm.validateCommandName(timeoutCtx, cmd); err != nil {
		return err
	}

	// Step 8: Validate command parameters
	if cmd == "RCPT" {
		// ORCPT requires a semicolon and NOTIFY lists require commas. The
		// envelope parser validates those fields; applying shell/SQL character
		// rules to them rejects valid DSN commands before that parser runs.
		parsed, err := parseRCPTEnvelope(args)
		if err != nil {
			return err
		}
		args = "TO:<" + parsed.addr + ">"
	}
	if err := csm.validateCommandParameters(timeoutCtx, cmd, args); err != nil {
		return err
	}

	// Step 9: Check for blocked patterns. Addresses were checked character by
	// character in step 8. Matching words in them refuses real senders: to
	// these patterns, updates@example.com is an UPDATE statement.
	if cmd != "MAIL" && cmd != "RCPT" {
		if err := csm.checkBlockedPatterns(timeoutCtx, cmd, args); err != nil {
			return err
		}
	}

	// Step 11: Log suspicious activity if enabled
	if csm.config.LogSuspiciousCommands {
		csm.logSuspiciousActivity(timeoutCtx, line, cmd, args)
	}

	return nil
}

// validateLength checks command line length
func (csm *CommandSecurityManager) validateLength(ctx context.Context, line string) error {
	if len(line) > csm.config.MaxCommandLength {
		csm.logger.WarnContext(ctx, "Command line too long",
			"length", len(line),
			"max_length", csm.config.MaxCommandLength,
		)
		return fmt.Errorf("500 5.5.2 Line too long")
	}
	return nil
}

// validateUTF8 ensures the line contains valid UTF-8
func (csm *CommandSecurityManager) validateUTF8(ctx context.Context, line string) error {
	if !utf8.ValidString(line) {
		csm.logger.WarnContext(ctx, "Invalid UTF-8 in command line")
		return fmt.Errorf("500 5.5.2 Invalid character encoding")
	}
	return nil
}

// filterControlCharacters removes or flags control characters
func (csm *CommandSecurityManager) filterControlCharacters(ctx context.Context, line string) error {
	// Check for null bytes and other dangerous control characters
	for i, r := range line {
		if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
			csm.logger.WarnContext(ctx, "Control character detected in command",
				"position", i,
				"character", fmt.Sprintf("\\x%02X", r),
			)
			return fmt.Errorf("500 5.5.2 Invalid control character")
		}
		if r == 127 { // DEL character
			csm.logger.WarnContext(ctx, "DEL character detected in command",
				"position", i,
			)
			return fmt.Errorf("500 5.5.2 Invalid control character")
		}
	}
	return nil
}

// canonicalizeCommand normalizes the command for consistent processing
func (csm *CommandSecurityManager) canonicalizeCommand(ctx context.Context, line string) (string, error) {
	// Trim whitespace
	canonical := strings.TrimSpace(line)

	// Normalize whitespace (replace multiple spaces with single space)
	whitespaceRegex := regexp.MustCompile(`\s+`)
	canonical = whitespaceRegex.ReplaceAllString(canonical, " ")

	// Remove any trailing whitespace
	canonical = strings.TrimSpace(canonical)

	// Check for empty command
	if canonical == "" {
		return "", fmt.Errorf("500 5.5.2 Empty command")
	}

	return canonical, nil
}

// parseCommand splits command into command name and arguments with bounds checking
func (csm *CommandSecurityManager) parseCommand(line string) (string, string) {
	// Validate input bounds
	if len(line) == 0 {
		return "", ""
	}

	// Safe string splitting with bounds checking
	spaceIndex := strings.Index(line, " ")
	if spaceIndex == -1 {
		// No space found, entire line is command
		return strings.ToUpper(line), ""
	}

	// Extract command and arguments safely
	cmd := strings.ToUpper(line[:spaceIndex])
	args := strings.TrimSpace(line[spaceIndex+1:])

	return cmd, args
}

// validateCommandStructure validates the basic command structure
func (csm *CommandSecurityManager) validateCommandStructure(ctx context.Context, cmd, args string) error {
	// Command name must not be empty
	if cmd == "" {
		return fmt.Errorf("500 5.5.2 Invalid command structure")
	}

	// Command name must contain only allowed characters
	if !csm.commandChars.MatchString(cmd) {
		csm.logger.WarnContext(ctx, "Command name contains invalid characters",
			"command", redactCommand(cmd),
		)
		return fmt.Errorf("500 5.5.2 Invalid command name")
	}

	// Check parameter length if present
	if args != "" && len(args) > csm.config.MaxParameterLength {
		csm.logger.WarnContext(ctx, "Command parameters too long",
			"length", len(args),
			"max_length", csm.config.MaxParameterLength,
		)
		return fmt.Errorf("500 5.5.2 Parameters too long")
	}

	return nil
}

// validateCommandName validates the command name against known commands
func (csm *CommandSecurityManager) validateCommandName(ctx context.Context, cmd string) error {
	// List of valid SMTP commands
	validCommands := map[string]bool{
		"HELO":     true,
		"EHLO":     true,
		"MAIL":     true,
		"RCPT":     true,
		"DATA":     true,
		"BDAT":     true,
		"RSET":     true,
		"NOOP":     true,
		"QUIT":     true,
		"AUTH":     true,
		"STARTTLS": true,
		"HELP":     true,
		"VRFY":     true,
		"EXPN":     true,
		"XDEBUG":   true, // Development only
	}

	if !validCommands[cmd] {
		csm.logger.WarnContext(ctx, "Unknown command received",
			"command", redactCommand(cmd),
		)
		return fmt.Errorf("502 5.5.1 Command not recognized")
	}

	return nil
}

// validateCommandParameters validates command parameters
func (csm *CommandSecurityManager) validateCommandParameters(ctx context.Context, cmd, args string) error {
	if args == "" {
		return nil // No parameters to validate
	}

	// Validate parameter characters
	if !csm.parameterChars.MatchString(args) {
		csm.logger.WarnContext(ctx, "Command parameters contain invalid characters",
			"command", redactCommand(cmd),
			"parameters", loggableArgs(cmd, args),
			"regex_pattern", csm.config.AllowedParameterChars,
		)
		return fmt.Errorf("500 5.5.2 Invalid parameter characters")
	}

	// Command-specific parameter validation
	switch cmd {
	case "HELO", "EHLO":
		return csm.validateHostnameParameter(ctx, args)
	case "MAIL":
		return csm.validateMailFromParameter(ctx, args)
	case "RCPT":
		return csm.validateRcptToParameter(ctx, args)
	case "AUTH":
		return csm.validateAuthParameter(ctx, args)
	case "VRFY", "EXPN":
		return csm.validateEmailParameter(ctx, args)
	}

	return nil
}

// validateHostnameParameter validates hostname parameters
func (csm *CommandSecurityManager) validateHostnameParameter(ctx context.Context, hostname string) error {
	// Check for empty hostname
	if hostname == "" {
		return fmt.Errorf("501 5.0.0 Hostname required")
	}

	// Basic hostname validation
	if len(hostname) > 255 {
		return fmt.Errorf("501 5.0.0 Hostname too long")
	}

	// Check if it's an IP address literal [x.x.x.x] or [IPv6:...] (RFC 5321)
	if len(hostname) > 2 && hostname[0] == '[' && hostname[len(hostname)-1] == ']' {
		// Valid IP address literal format - accept it
		return nil
	}

	// Check for valid hostname characters
	if !hostnamePattern.MatchString(hostname) {
		csm.logger.WarnContext(ctx, "Invalid hostname format",
			"hostname", hostname,
		)
		return fmt.Errorf("501 5.0.0 Invalid hostname format")
	}

	return nil
}

// validateMailFromParameter validates MAIL FROM parameters
func (csm *CommandSecurityManager) validateMailFromParameter(ctx context.Context, args string) error {
	// Validate input bounds
	if err := csm.validateBounds(ctx, args, "MAIL_FROM_PARAM"); err != nil {
		return err
	}

	// Check for proper MAIL FROM syntax
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Extract email address, handling SMTP extensions (SIZE, BODY, etc.)
	// Case-insensitive removal of "FROM:" (already validated above)
	addr := args[5:] // Skip "FROM:" or any case variation
	addr = strings.TrimSpace(addr)

	// Check if address is empty after FROM:
	if addr == "" {
		return fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// RFC 5321: MAIL FROM:<address> [SP <mail-parameters>]
	// Extract just the email part, ignoring extensions like SIZE=, BODY=
	addrPart := addr
	if idx := strings.Index(addr, ">"); idx > 0 {
		// Extract everything up to and including the closing bracket
		addrPart = addr[:idx+1]
	}

	// Remove angle brackets if present (with bounds checking)
	addrPart = strings.Trim(addrPart, "<>")
	addrPart = strings.TrimSpace(addrPart)

	return csm.validateEmailAddress(ctx, addrPart)
}

// validateRcptToParameter validates RCPT TO parameters
func (csm *CommandSecurityManager) validateRcptToParameter(ctx context.Context, args string) error {
	// Validate input bounds
	if err := csm.validateBounds(ctx, args, "RCPT_TO_PARAM"); err != nil {
		return err
	}

	// Check for proper RCPT TO syntax
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Extract and validate email address safely
	// Case-insensitive removal of "TO:" (already validated above)
	addr := args[3:] // Skip "TO:" or any case variation
	addr = strings.TrimSpace(addr)

	// Check if address is empty after TO:
	if addr == "" {
		return fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Remove angle brackets if present (with bounds checking)
	if len(addr) >= 2 && strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}

	return csm.validateEmailAddress(ctx, addr)
}

// validateAuthParameter validates AUTH parameters
func (csm *CommandSecurityManager) validateAuthParameter(ctx context.Context, args string) error {
	// AUTH command should have a mechanism
	if args == "" {
		return fmt.Errorf("501 5.5.4 Syntax: AUTH <mechanism>")
	}

	// Split args and get the first part (mechanism)
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return fmt.Errorf("501 5.5.4 Syntax: AUTH <mechanism>")
	}

	// Check for valid auth mechanisms
	validMechanisms := []string{"PLAIN", "LOGIN"}
	mechanism := strings.ToUpper(fields[0])

	valid := false
	for _, vm := range validMechanisms {
		if mechanism == vm {
			valid = true
			break
		}
	}

	if !valid {
		csm.logger.WarnContext(ctx, "Invalid AUTH mechanism",
			"mechanism", mechanism,
		)
		return fmt.Errorf("504 5.7.4 Unrecognized authentication type")
	}

	return nil
}

// validateEmailParameter validates email address parameters
func (csm *CommandSecurityManager) validateEmailParameter(ctx context.Context, email string) error {
	return csm.validateEmailAddress(ctx, email)
}

// validateEmailAddress validates an email address
func (csm *CommandSecurityManager) validateEmailAddress(ctx context.Context, addr string) error {
	// Allow empty address for null sender
	if addr == "" {
		return nil
	}

	// Basic length check
	if len(addr) > 320 { // RFC 5321 limit
		return fmt.Errorf("501 5.1.3 Address too long")
	}

	// Basic email validation
	if !strings.Contains(addr, "@") || len(addr) < 3 {
		csm.logger.WarnContext(ctx, "Email validation failed",
			"address", addr,
			"reason", "invalid_format",
		)
		return fmt.Errorf("501 5.1.3 Invalid email address format")
	}

	// Forwarding and bounce handling put = in senders, and rewriting schemes
	// can add / and more, so a narrow list refuses real mail: Gmail's
	// forwarding sender has an =. This is RFC 5321's atext without & | ` and $,
	// which no real sender needs and which stay out as shell metacharacters.
	// A sender is free text from anyone, so ../ stays out as well, even
	// though nothing here builds a path from one today.
	if strings.Contains(addr, "../") {
		return fmt.Errorf("501 5.1.3 Invalid email address format")
	}
	// Require proper domain with TLD (e.g., example.com) or special case for localhost
	if !emailPattern.MatchString(addr) {
		csm.logger.WarnContext(ctx, "Invalid email address format",
			"address", addr,
			"addr_len", len(addr),
			"addr_bytes", []byte(addr),
		)
		return fmt.Errorf("501 5.1.3 Invalid email address format")
	}

	return nil
}

// checkBlockedPatterns checks for blocked patterns in command and parameters
func (csm *CommandSecurityManager) checkBlockedPatterns(ctx context.Context, cmd, args string) error {
	// Check command for blocked patterns
	for _, regex := range csm.blockedCommand {
		if regex.MatchString(cmd) {
			csm.logger.WarnContext(ctx, "Blocked pattern detected in command",
				"command", redactCommand(cmd),
				"pattern", regex.String(),
			)
			return fmt.Errorf("554 5.7.1 Command rejected: security violation")
		}
	}

	// Check parameters for blocked patterns
	if args != "" {
		for _, regex := range csm.blockedParam {
			if regex.MatchString(args) {
				csm.logger.WarnContext(ctx, "Blocked pattern detected in parameters",
					"command", redactCommand(cmd),
					"parameters", loggableArgs(cmd, args),
					"pattern", regex.String(),
				)
				return fmt.Errorf("554 5.7.1 Parameters rejected: security violation")
			}
		}
	}

	return nil
}

// logSuspiciousActivity logs potentially suspicious command activity
func (csm *CommandSecurityManager) logSuspiciousActivity(ctx context.Context, originalLine, cmd, args string) {
	if suspiciousPattern.MatchString(cmd + " " + args) {
		csm.logger.WarnContext(ctx, "Suspicious command pattern detected",
			"original_line", redactCommand(originalLine),
			"command", redactCommand(cmd),
			"parameters", loggableArgs(cmd, args),
		)
	}
}

// SanitizeCommand sanitizes a command for safe logging
func (csm *CommandSecurityManager) SanitizeCommand(line string) string {
	// Remove control characters for safe logging
	sanitized := ""
	for _, r := range redactCommand(line) {
		if r >= 32 && r != 127 { // Keep printable characters except DEL
			sanitized += string(r)
		} else {
			sanitized += fmt.Sprintf("\\x%02X", r)
		}
	}

	// Truncate if too long
	if len(sanitized) > 200 {
		sanitized = sanitized[:200] + "..."
	}

	return sanitized
}

// validateBounds performs enhanced bounds checking on string operations
func (csm *CommandSecurityManager) validateBounds(ctx context.Context, str string, operation string) error {
	// Check for extremely large strings that could cause issues
	if len(str) > 1024*1024 { // 1MB limit for any single string
		csm.logger.WarnContext(ctx, "String too large for safe processing",
			"operation", operation,
			"length", len(str),
		)
		return fmt.Errorf("500 5.5.2 String too large")
	}

	return nil
}

// safeStringOperation performs string operations with bounds checking
// Currently unused but kept for future security enhancements
//
//nolint:unused
func (csm *CommandSecurityManager) safeStringOperation(ctx context.Context, str string, start, end int, operation string) (string, error) {
	// Validate input string bounds
	if err := csm.validateBounds(ctx, str, operation); err != nil {
		return "", err
	}

	// Check slice bounds
	if start < 0 || end < 0 || start > len(str) || end > len(str) || start > end {
		csm.logger.WarnContext(ctx, "Invalid slice bounds",
			"operation", operation,
			"start", start,
			"end", end,
			"string_length", len(str),
		)
		return "", fmt.Errorf("500 5.5.2 Internal error: invalid slice bounds")
	}

	return str[start:end], nil
}

// GetSecurityStats returns security statistics
func (csm *CommandSecurityManager) GetSecurityStats() map[string]interface{} {
	return map[string]interface{}{
		"max_command_length":   csm.config.MaxCommandLength,
		"max_parameter_length": csm.config.MaxParameterLength,
		"strict_mode":          csm.config.StrictMode,
		"log_suspicious":       csm.config.LogSuspiciousCommands,
		"blocked_patterns":     len(csm.config.BlockedCommandPatterns) + len(csm.config.BlockedParameterPatterns),
		"command_timeout":      csm.config.CommandTimeout,
	}
}

// redactCommand is a command line safe to log. An AUTH argument is
// credentials: for PLAIN it is the base64 of the username and the
// password, so logging it puts every password in the log. The mechanism is
// kept; the rest is replaced.
func redactCommand(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 3 && strings.EqualFold(fields[0], "AUTH") {
		return fields[0] + " " + fields[1] + " [redacted]"
	}
	return line
}
