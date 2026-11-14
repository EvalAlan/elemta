package mailpolicy

import "testing"

func TestSenderVerifiedReadsOnlyTheFirst(t *testing.T) {
	for _, tc := range []struct {
		raw, kind, value string
	}{
		{"Subject: x\r\n\r\n", "none", ""},
		{SenderVerifiedHeader + ": auth Dana@Example.com\r\nSubject: x\r\n\r\n", "auth", "dana@example.com"},
		{SenderVerifiedHeader + ": dmarc example.com\r\n\r\n", "dmarc", "example.com"},
		{SenderVerifiedHeader + ": none\r\n" + SenderVerifiedHeader + ": auth dana@example.com\r\n\r\n", "none", ""},
		{SenderVerifiedHeader + ": weird thing\r\n\r\n", "none", ""},
		{"Subject: x\r\n\r\n" + SenderVerifiedHeader + ": auth dana@example.com\r\n", "none", ""}, // in the body
	} {
		if k, v := SenderVerified([]byte(tc.raw)); k != tc.kind || v != tc.value {
			t.Errorf("%q: got %q %q, want %q %q", tc.raw, k, v, tc.kind, tc.value)
		}
	}
}
