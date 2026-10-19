package mailbox

import (
	"bytes"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestOpaqueBodyAndBoundedMIME(t *testing.T) {
	raw := []byte("damaged\x00header without line ending")
	if !bytes.Equal(bodySection(raw, &imap.FetchItemBodySection{}), raw) {
		t.Fatal("raw download changed malformed message")
	}
	if got := bodySection(raw, &imap.FetchItemBodySection{Partial: &imap.SectionPartial{Offset: 1, Size: 3}}); !bytes.Equal(got, raw[1:4]) {
		t.Fatalf("partial %q", got)
	}
	if got := bodySection(raw, &imap.FetchItemBodySection{Partial: &imap.SectionPartial{Offset: 1 << 40, Size: 1 << 40}}); len(got) != 0 {
		t.Fatal("past-end partial was not empty")
	}
	nested := []byte("Subject: inner\r\n\r\nbody")
	for range 40 {
		nested = append([]byte("Content-Type: message/rfc822\r\n\r\n"), nested...)
	}
	part, ok := bodyStructure(nested).(*imap.BodyStructureSinglePart)
	if !ok || part.Subtype != "octet-stream" || part.Extended == nil {
		t.Fatal("deep MIME did not use bounded opaque fallback")
	}
}
