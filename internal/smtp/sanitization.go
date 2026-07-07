// internal/smtp/sanitization.go
package smtp

import "strings"

// sanitizeEmailForHeader removes CRLF sequences from email addresses to prevent header injection
// This function addresses CVE-style header injection vulnerabilities where attackers can use
// CRLF sequences in email addresses (from MAIL FROM or RCPT TO commands) to inject arbitrary
// email headers (e.g., BCC headers).
//
// Usage: Call this before interpolating email addresses into SMTP headers
func sanitizeEmailForHeader(email string) string {
	// Remove carriage return (0x0D) and line feed (0x0A) characters
	email = strings.ReplaceAll(email, "\r", "")
	email = strings.ReplaceAll(email, "\n", "")
	return email
}
