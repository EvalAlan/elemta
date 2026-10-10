package smtp

import (
	"io"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/queue"
)

func TestNeutralizeForgedAuthResults(t *testing.T) {
	msg := "Authentication-Results: mx.example.com; dkim=pass header.d=bank.example\r\n" +
		"authentication-results:  MX.Example.Com 1 ; spf=pass\r\n" +
		"Authentication-Results: other.example.net; dkim=fail\r\n" +
		"Subject: hi\r\n" +
		"\r\n" +
		"Authentication-Results: mx.example.com; this is body text\r\n"

	patched, changed := neutralizeForgedAuthResults([]byte(msg), "mx.example.com")
	if !changed {
		t.Fatal("forged header not detected")
	}
	if len(patched) != len(msg) {
		t.Fatalf("length changed: %d -> %d", len(msg), len(patched))
	}
	got := string(patched)
	if strings.Count(got, "X-Untrusted-AuthResult:") != 2 {
		t.Errorf("want both headers claiming mx.example.com renamed:\n%s", got)
	}
	if !strings.Contains(got, "Authentication-Results: other.example.net") {
		t.Error("a header from another server was renamed")
	}
	if !strings.Contains(got, "\r\n\r\nAuthentication-Results: mx.example.com; this is body text") {
		t.Error("body text was modified")
	}

	if _, changed := neutralizeForgedAuthResults([]byte("Subject: x\r\n\r\nbody\r\n"), "mx.example.com"); changed {
		t.Error("clean message reported as changed")
	}
}

func TestWithPatchedHead(t *testing.T) {
	full := "Authentication-Results: mx.example.com; dkim=pass\r\nSubject: s\r\n\r\nbody bytes\r\n"
	head := []byte(full[:40])
	patched, _ := neutralizeForgedAuthResults(head, "mx.example.com")
	open := withPatchedHead(queue.OpenerForBytes([]byte(full)), head, patched)
	r, err := open()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	_ = r.Close()
	if len(out) != len(full) || !strings.HasPrefix(string(out), "X-Untrusted-AuthResult: mx.example.com") || !strings.HasSuffix(string(out), "body bytes\r\n") {
		t.Errorf("patched stream wrong: %q", out)
	}
}
