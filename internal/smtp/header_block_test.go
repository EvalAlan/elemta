package smtp

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// buildHeaderBlock returns a realistic header section for a message that has
// passed through hops hops, each adding a Received line and an ARC seal.
func buildHeaderBlock(hops int) string {
	var b strings.Builder
	b.WriteString("Subject: quarterly report\r\nFrom: sender@example.com\r\nTo: recipient@example.com\r\n")
	for i := 0; i < hops; i++ {
		fmt.Fprintf(&b, "Received: from relay%d.example.net (relay%d.example.net [203.0.113.%d])\r\n"+
			"\tby mx.example.org with ESMTPS id abc%d\r\n"+
			"\t(version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256);\r\n"+
			"\tTue, 08 Aug 2026 12:0%d:00 +0000\r\n", i, i, i%254, i, i%10)
		fmt.Fprintf(&b, "ARC-Seal: i=%d; a=rsa-sha256; t=1786000000; cv=none; d=example.net; s=arc;\r\n"+
			"\tb=%s\r\n", i+1, strings.Repeat("A", 340))
		fmt.Fprintf(&b, "ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed; d=example.net;\r\n"+
			"\tb=%s\r\n", i+1, strings.Repeat("B", 340))
	}
	return b.String()
}

// TestLongHeaderBlockFromExternalSenderIsAccepted is the regression test.
//
// The block-level cap was MaxLineLength*10 — 10KB — which conflates a per-field
// limit with a whole-section one. A message through a dozen hops carrying ARC
// seals and DKIM signatures exceeds 12KB of headers on its own, so ordinary
// forwarded and mailing-list mail was refused with "Headers exceed maximum
// length" and a buffer_overflow_attempt threat.
//
// Like the body-size bug before it, this only affected external senders:
// loopback and Docker peers take the internal branch and never reach here.
func TestLongHeaderBlockFromExternalSenderIsAccepted(t *testing.T) {
	dh := externalDataHandler(t)

	headers := buildHeaderBlock(12)
	if len(headers) <= 10*1024 {
		t.Fatalf("test header block must exceed the old 10KB cap, got %d", len(headers))
	}

	content := headers + "\r\nthe message body\r\n"
	result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
	if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content)), result); err != nil {
		t.Fatalf("content analysis: %v", err)
	}

	if !result.Passed {
		t.Errorf("a %d-byte header block from twelve hops was rejected: %v", len(headers), result.Threats)
	}
}

// TestAbsurdHeaderBlockIsStillRejected shows the cap still exists: raising it
// to something realistic is not the same as removing it.
func TestAbsurdHeaderBlockIsStillRejected(t *testing.T) {
	dh := externalDataHandler(t)

	// Well past any plausible header section.
	headers := buildHeaderBlock(200)
	if len(headers) <= 100*1024 {
		t.Fatalf("test block must exceed the 100KB cap, got %d", len(headers))
	}

	content := headers + "\r\nbody\r\n"
	result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
	if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content)), result); err != nil {
		t.Fatalf("content analysis: %v", err)
	}

	if result.Passed {
		t.Errorf("a %d-byte header block should still be refused", len(headers))
	}
}

// TestHeaderBlockLimitIsSeparateFromPerFieldLimit pins that the two limits are
// not the same number wearing different names. Conflating them is what made
// the block cap ten times a per-line limit.
func TestHeaderBlockLimitIsSeparateFromPerFieldLimit(t *testing.T) {
	limits := DefaultSMTPParameterLimits()

	if limits.MaxHeaderLength != 998 {
		t.Errorf("per-field limit = %d, want RFC 5322's 998", limits.MaxHeaderLength)
	}
	if limits.MaxHeaderBlockLength <= limits.MaxLineLength*10 {
		t.Errorf("block limit %d is not meaningfully above the old MaxLineLength*10 (%d)",
			limits.MaxHeaderBlockLength, limits.MaxLineLength*10)
	}
}

// TestHeaderBlockLimitFallsBackWhenUnset covers limits built before the field
// existed, which would otherwise reject every header block as over-length.
func TestHeaderBlockLimitFallsBackWhenUnset(t *testing.T) {
	v := NewEnhancedValidator(quietLogger())
	v.limits = &SMTPParameterLimits{MaxLineLength: 1000} // MaxHeaderBlockLength unset

	if got := v.headerBlockLimit(); got <= 0 {
		t.Fatalf("limit fell back to %d, which would reject everything", got)
	}

	headers := buildHeaderBlock(12)
	result := v.validateHeaderParameter(headers)
	if !result.Valid {
		t.Errorf("an unset block limit should not refuse ordinary headers: %s", result.ErrorMessage)
	}
}
