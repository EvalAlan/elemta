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
