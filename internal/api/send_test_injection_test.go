package api

import (
	"strings"
	"testing"
)

// handleSendTestEmail builds RFC 5322 headers by string concatenation from
// request fields. Before validateTestEmailRequest existed, a subject of
// "x\r\nBcc: hidden@..." wrote its own header, and a from of
// "a@b\r\n\r\n<body>" terminated the header block outright. These tests call
// the validation the handler actually uses.

func TestValidateTestEmailRequest(t *testing.T) {
	cases := []struct {
		name              string
		from, to, subject string
		wantErr           string // empty means the request must be accepted
		wantFrom, wantTo  string
	}{
		{
			name: "plain", from: "a@example.com", to: "b@example.com", subject: "hello",
			wantFrom: "a@example.com", wantTo: "b@example.com",
		},
		{
			name: "display name is stripped to the bare address",
			from: "Alice Admin <a@example.com>", to: "b@example.com", subject: "hi",
			wantFrom: "a@example.com", wantTo: "b@example.com",
		},
		{
			name: "subject crlf injection", from: "a@example.com", to: "b@example.com",
			subject: "x\r\nBcc: victim@example.com", wantErr: "line breaks",
		},
		{
			name: "subject bare lf injection", from: "a@example.com", to: "b@example.com",
			subject: "x\nBcc: victim@example.com", wantErr: "line breaks",
		},
		{
			name: "from carries a header", from: "a@example.com\r\nX-Evil: 1", to: "b@example.com",
			subject: "s", wantErr: "from",
		},
		{
			name: "to carries a header", from: "a@example.com", to: "b@example.com\r\nX-Evil: 1",
			subject: "s", wantErr: "to",
		},
		{
			name: "from is not an address", from: "not an address", to: "b@example.com",
			subject: "s", wantErr: "from",
		},
		{
			name: "recipient list is not a single recipient",
			from: "a@example.com", to: "b@example.com, c@example.com",
			subject: "s", wantErr: "to",
		},
		{
			name: "empty from", from: "", to: "b@example.com", subject: "s", wantErr: "from",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, to, err := validateTestEmailRequest(tc.from, tc.to, tc.subject)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("accepted %q/%q/%q — header injection reaches the queue",
						tc.from, tc.to, tc.subject)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("rejected a legitimate request: %v", err)
			}
			if from != tc.wantFrom || to != tc.wantTo {
				t.Errorf("got %q/%q, want %q/%q", from, to, tc.wantFrom, tc.wantTo)
			}
			if strings.ContainsAny(from+to, "\r\n") {
				t.Error("validated addresses still contain line breaks")
			}
		})
	}
}
