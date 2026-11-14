package mailpolicy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func nestedMultipart(depth int) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b0\"\r\n\r\n")
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "--b%d\r\nContent-Type: Multipart/Mixed; boundary=\"b%d\"\r\n\r\n", i, i+1)
	}
	b.WriteString("--b" + fmt.Sprint(depth) + "\r\nContent-Type: text/plain\r\n\r\nhi\r\n")
	return []byte(b.String())
}

func TestMIMETooComplex(t *testing.T) {
	ordinary := []byte("Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n--a--\r\n")
	if MIMETooComplex(ordinary) {
		t.Error("an ordinary message was refused")
	}
	if MIMETooComplex(nestedMultipart(MaxMultipartContainers - 1)) {
		t.Error("a message at the limit was refused")
	}
	if !MIMETooComplex(nestedMultipart(MaxMultipartContainers + 1)) {
		t.Error("a message over the limit was accepted")
	}
	if MIMETooComplex([]byte("multipart")) || MIMETooComplex(nil) {
		t.Error("short input misread")
	}
}

// The check itself must stay linear: it runs on every message at delivery.
func TestMIMETooComplexIsFast(t *testing.T) {
	raw := nestedMultipart(400000) // about 25 MiB
	start := time.Now()
	if !MIMETooComplex(raw) {
		t.Fatal("not detected")
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("took %v on %d MiB", el, len(raw)>>20)
	}
}
