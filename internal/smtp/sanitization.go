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

// sanitizeHeloForHeader makes a client's HELO/EHLO argument safe to write into
// a Received header. The value is entirely client-controlled, so anything
// outside the characters a hostname or address literal uses is dropped, and
// the length is capped at a DNS name's maximum.
func sanitizeHeloForHeader(helo string) string {
	var b strings.Builder
	for _, r := range helo {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ':', r == '[', r == ']':
			b.WriteRune(r)
		}
		if b.Len() >= 255 {
			break
		}
	}
	return b.String()
}
