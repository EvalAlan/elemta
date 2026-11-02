package smtp

import (
	"bytes"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
)

// A place name in the subject and body must arrive readable, and the message
// must say it's automatic so nothing replies to it.
func TestNoticeMessage(t *testing.T) {
	n := abuse.Notice{Time: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), Subject: "Impossible travel: dana@example.com (São Paulo)", Body: "Signed in from São Paulo.\nThen Oslo."}
	raw := noticeMessage("postmaster@example.com", "mail.example.com", []string{"a@example.com", "b@example.org"}, n)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != n.Subject {
		t.Fatalf("subject %q, %v", subject, err)
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" || msg.Header.Get("To") != "<a@example.com>, <b@example.org>" {
		t.Fatalf("headers %v", msg.Header)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if !strings.Contains(string(body), "São Paulo.\r\nThen Oslo.") {
		t.Fatalf("body %q", body)
	}
}
