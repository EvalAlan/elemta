package webmail

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message/mail"
)

func TestDraftBuild(t *testing.T) {
	d := &Draft{
		From:        Address{Name: "Dana Okafor", Email: "dana@example.com"},
		To:          []Address{{Name: "Priya Shah", Email: "priya@northwind.example"}},
		Cc:          []Address{{Email: "marcus@example.com"}},
		Bcc:         []Address{{Email: "archive@example.com"}, {Email: "PRIYA@northwind.example"}},
		Subject:     "Kickoff ✓",
		Text:        "Line one\nLine two\r\nLine three",
		InReplyTo:   "<msa@northwind.example>",
		References:  "<root@northwind.example>",
		Attachments: []Attachment{{Filename: "plan.txt", ContentType: "text/plain", Data: []byte("step 1")}},
	}
	raw, err := d.Build(time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	// The hidden recipients must not appear anywhere. Checked by address and
	// by header name, not by searching for "bcc": the multipart boundary is
	// random hex and contains "bcc" in about one build in sixty.
	if strings.Contains(strings.ToLower(s), "archive@example.com") {
		t.Fatalf("Bcc recipient leaked into the message:\n%s", s)
	}
	for _, line := range strings.Split(s[:strings.Index(s, "\r\n\r\n")], "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("Bcc header in the message:\n%s", s)
		}
	}
	if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\n") {
		t.Fatal("message contains a bare LF; Elemta rejects those")
	}

	r, err := mail.CreateReader(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	if subj, _ := r.Header.Subject(); subj != "Kickoff ✓" {
		t.Errorf("subject = %q", subj)
	}
	if got := r.Header.Get("References"); got != "<root@northwind.example> <msa@northwind.example>" {
		t.Errorf("references = %q", got)
	}
	if id := r.Header.Get("Message-Id"); !strings.HasSuffix(id, "@example.com>") {
		t.Errorf("message id %q not in sender's domain", id)
	}

	if got := d.Recipients(); len(got) != 3 {
		t.Errorf("recipients = %v, want 3 with the duplicate removed", got)
	}
}

func TestRejectedOnlyWrapsPermanentFailures(t *testing.T) {
	if err := rejected("RCPT", errors.New("550 5.1.1 no such user")); !errors.Is(err, ErrRejected) {
		t.Errorf("5xx not marked rejected: %v", err)
	}
	if err := rejected("RCPT", errors.New("451 4.7.1 try later")); errors.Is(err, ErrRejected) {
		t.Errorf("4xx marked as a permanent rejection: %v", err)
	}
}
