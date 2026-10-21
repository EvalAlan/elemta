package smtp

import (
	"context"
	"strings"
	"testing"
)

// Real mail that the DATA checks used to refuse, from a load test against
// public corpora. With the default [message_checks] all of it is accepted;
// each option turns its check back on.
func TestMessageChecksAcceptRealMailByDefault(t *testing.T) {
	long := "To: " + strings.TrimSuffix(strings.Repeat("someone.with.a.long.name@example.com, ", 40), ", ")
	headers := map[string]string{
		"from": "sender@example.com",
		"date": "Mon, 20 Oct 2026 10:00:00 +0000",
		"to":   "undisclosed-recipients:;",
		"cc":   ".leading.dot@example.com",
	}
	latin1 := "Caf\xe9 au lait, se\xf1or\r\n"

	dh := externalDataHandler(t)
	dh.enhancedValidator = newMessageValidator(quietLogger(), dh.config)
	if r := dh.enhancedValidator.ValidateEmailHeaders(long); !r.Valid {
		t.Errorf("a long folded recipient list was refused: %s", r.ErrorMessage)
	}
	if err := dh.validateMessageHeaders(context.Background(), &MessageMetadata{Headers: headers}); err != nil {
		t.Errorf("unparseable address headers were refused: %v", err)
	}
	if err := dh.validateLineContent(context.Background(), latin1, &DataReaderState{}); err != nil {
		t.Errorf("Latin-1 text was refused: %v", err)
	}

	dh.config.MessageChecks = &MessageChecksConfig{StrictAddressHeaders: true, MaxHeaderLength: 998, RejectInvalidUTF8: true}
	dh.enhancedValidator = newMessageValidator(quietLogger(), dh.config)
	if r := dh.enhancedValidator.ValidateEmailHeaders(long); r.Valid {
		t.Error("max_header_length = 998 accepted a longer header")
	}
	if err := dh.validateMessageHeaders(context.Background(), &MessageMetadata{Headers: headers}); err == nil {
		t.Error("strict_address_headers accepted an unparseable To")
	}
	if err := dh.validateLineContent(context.Background(), latin1, &DataReaderState{}); err == nil {
		t.Error("reject_invalid_utf8 accepted Latin-1 text")
	}
}

// RFC 5322 field names: printable ASCII except the colon. A malformed name
// is left as text, not a reason to refuse the message.
func TestHeaderFieldNames(t *testing.T) {
	dh := externalDataHandler(t)
	for _, line := range []string{"X_Original_To: a@example.com", "X.Mailer: Old Client 1.0", "X-Thread#: 4", "Bad Name: value"} {
		if err := dh.validateHeaderLine(context.Background(), line); err != nil {
			t.Errorf("%q refused: %v", line, err)
		}
	}
	if err := dh.validateHeaderLine(context.Background(), "no colon here"); err == nil {
		t.Error("a header line without a colon was accepted")
	}
}
