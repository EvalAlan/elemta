package webmail

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func nestedMIMEMessage(depth int) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nSubject: nest\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b0\"\r\n\r\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "--b%d\r\nContent-Type: multipart/mixed; boundary=\"b%d\"\r\n\r\n", i, i+1)
	}
	b.WriteString("--b" + fmt.Sprint(depth) + "\r\nContent-Type: text/plain\r\n\r\nhi\r\n")
	return []byte(b.String())
}

// Opening a message of deeply nested multiparts used to hold a CPU for a
// time growing with the square of the depth (12 s at 10,000 levels). It now
// shows the headers and a note instead of walking it.
func TestDeeplyNestedMessageIsNotWalked(t *testing.T) {
	raw := nestedMIMEMessage(20000)
	start := time.Now()
	msg, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("parse took %v", el)
	}
	if msg.Subject != "nest" || !strings.Contains(msg.Text, "too many nested parts") {
		t.Errorf("got subject %q, text %q", msg.Subject, msg.Text)
	}
	// Attachment and inline-image lookups share the reader, so they don't
	// walk it either.
	start = time.Now()
	_, _, _ = findPart(raw, 2, "")
	if el := time.Since(start); el > time.Second {
		t.Errorf("findPart took %v", el)
	}
}
