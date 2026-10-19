package smtp

import (
	"context"
	"testing"
)

func TestGoogleDKIMHeaderValidation(t *testing.T) {
	v := NewEnhancedValidator(quietLogger())
	for _, name := range []string{"DKIM-Signature", "X-Google-DKIM-Signature"} {
		t.Run(name, func(t *testing.T) {
			header := name + ": v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n\td=1e100.net; s=20260707; b=abc+/def=="
			if result := v.ValidateEmailHeaders(header); !result.Valid {
				t.Fatalf("ordinary folded signature rejected: %s", result.ErrorMessage)
			}
			if result := v.validateSingleHeader(name + ": v=1; b=abc\x00def"); result.Valid {
				t.Fatal("signature containing a control character accepted")
			}
		})
	}
}

func TestExtensionHeaderPunctuation(t *testing.T) {
	v := NewEnhancedValidator(quietLogger())
	for _, header := range []string{
		"X-Provider-Signature: v=1; a=rsa-sha256; b=abc+/def==",
		"From: \"Alan Denniston\" <sender@example.com>",
		"Subject: Today's test; quoted \"message\"",
	} {
		if result := v.ValidateEmailHeaders(header); !result.Valid {
			t.Errorf("ordinary header rejected: %s: %s", header, result.ErrorMessage)
		}
	}
}

func TestExternalHeaderContinuationPunctuation(t *testing.T) {
	dh := externalDataHandler(t)
	for _, inHeaders := range []bool{true, false} {
		state := &DataReaderState{InHeaders: inHeaders, LineCount: 7}
		for _, line := range []string{
			"\td=1e100.net; s=20260707; b=abc+/def==\r\n",
			" Today's test; quoted \"message\"\r\n",
		} {
			if err := dh.validateLineContent(context.Background(), line, state); err != nil {
				t.Errorf("inHeaders=%v: ordinary DATA text rejected: %v", inHeaders, err)
			}
		}
	}
}

func TestExternalAddressHeaderLists(t *testing.T) {
	dh := externalDataHandler(t)
	for _, headers := range []map[string]string{
		{"from": `"Alan Denniston" <sender@example.com>`},
		{"to": `First Person <one@example.com>, "Second, Person" <two@example.net>`},
		{"bcc": ""},
	} {
		if err := dh.validateEmailAddressesInHeaders(context.Background(), headers); err != nil {
			t.Errorf("valid address header rejected: %v", err)
		}
	}
	if err := dh.validateEmailAddressesInHeaders(context.Background(), map[string]string{"from": "not an address"}); err == nil {
		t.Fatal("malformed From accepted")
	}
}

func TestMessageTextIsNotCommandSyntax(t *testing.T) {
	v := NewEnhancedValidator(quietLogger())
	dh := externalDataHandler(t)
	for _, text := range []string{
		`<div><img src="https://images.example.net/proxy?width=992&amp;h=abc123"></div>`,
		`R&D | Engineering & Operations`,
		`Discussion: javascript: URLs and eval(code)`,
		`Example SQL: UNION SELECT name FROM users; DROP TABLE demo`,
		`<script>alert("quoted source code")</script>`,
	} {
		if result := v.ValidateEmailHeaders("Subject: " + text); !result.Valid {
			t.Errorf("message subject rejected: %q: %s", text, result.ErrorMessage)
		}
		content := "From: sender@example.com\r\nSubject: message text\r\n\r\n" + text + "\r\n"
		scan := &SecurityScanResult{Passed: true}
		if err := dh.performContentAnalysis(context.Background(), newScanContent([]byte(content)), scan); err != nil || !scan.Passed {
			t.Errorf("message content rejected: %q: error=%v threats=%v", text, err, scan.Threats)
		}
		for _, inHeaders := range []bool{true, false} {
			line := text
			if inHeaders {
				line = " " + text
			}
			if err := dh.validateLineContent(context.Background(), line+"\r\n", &DataReaderState{InHeaders: inHeaders}); err != nil {
				t.Errorf("message text rejected (headers=%v): %q: %v", inHeaders, text, err)
			}
		}
	}
	for _, text := range []string{"value\r\nBcc: victim@example.net", "value\x00", "value\x1b", "value\x7f"} {
		if result := v.validateHeaderValueRelaxed(text); result.Valid {
			t.Errorf("framing/control bytes accepted: %q", text)
		}
	}
}
