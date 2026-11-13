package interp

import (
	"bytes"
	"context"
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

// The body test runs at delivery. An unbounded walk of deeply nested
// multiparts took time growing with the square of the depth, and its
// recursion could exhaust the stack.
func TestBodyPartsStopAtDepth(t *testing.T) {
	start := time.Now()
	if _, err := ParseBodyParts(context.Background(), bytes.NewReader(nestedMIMEMessage(20000)), []string{"text"}, 1<<20); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("ParseBodyParts took %v", el)
	}
}
