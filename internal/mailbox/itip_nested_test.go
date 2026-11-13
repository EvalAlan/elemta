package mailbox

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

// calendarPart runs at delivery on mail from anyone. On deeply nested
// multiparts it used to take time growing with the square of the depth
// (14 s at 10,000 levels, hours near the size limit).
func TestCalendarPartSkipsDeeplyNestedMail(t *testing.T) {
	start := time.Now()
	if method, data := calendarPart(nestedMIMEMessage(20000)); method != "" || data != nil {
		t.Errorf("found a calendar part: %q", method)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("calendarPart took %v", el)
	}
}
