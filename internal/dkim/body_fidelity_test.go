package dkim

import (
	"bytes"
	"strings"
	"testing"
)

// DKIM body-hash fidelity.
//
// These exist for the move of DATA off the heap and onto a spool file. A
// signature covers a hash of the canonicalised body, so any change to how the
// body is stored or replayed — one byte of CRLF, a dropped trailing line, a
// re-stuffed leading period — produces a signature that verifies locally and
// fails at every recipient. That failure is silent from the sending side,
// which is why it is pinned here rather than left to be noticed in the wild.
//
// The content used is shaped like what the queue actually stores: this hop's
// trace headers prepended to the submission, per RFC 5321 §4.4.

// storedMessage builds content in the shape saveMessage persists: server
// headers first, then the submitted headers and body verbatim.
func storedMessage(body string) string {
	return "Received: from mail.example.com ([203.0.113.10])\r\n" +
		"\tby mail.example.com with ESMTP id test-message-id\r\n" +
		"\t(envelope-from <alice@example.com>)\r\n" +
		"\tfor <bob@remote.test>; Thu, 09 Jul 2026 12:00:00 +0000\r\n" +
		"X-Virus-Scanned: Clean (Elemta)\r\n" +
		"X-Message-ID: test-message-id\r\n" +
		"From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@remote.test>\r\n" +
		"Subject: Hello\r\n" +
		"Date: Thu, 09 Jul 2026 12:00:00 +0000\r\n" +
		"Message-ID: <abc@example.com>\r\n" +
		"\r\n" +
		body
}

// TestSignedBodySurvivesRoundTrip signs stored-shaped content and verifies the
// signature independently, for the body shapes most likely to be mangled by a
// change to how message data is buffered.
func TestSignedBodySurvivesRoundTrip(t *testing.T) {
	bodies := []struct {
		name string
		body string
	}{
		{"simple", "This is the body.\r\n"},
		{"empty body", ""},
		{"no trailing CRLF", "no newline at the end"},
		{"trailing blank lines", "text\r\n\r\n\r\n"},
		{"leading period line", ".hidden\r\n"},
		{"lone period line", "before\r\n.\r\nafter\r\n"},
		{"looks like a terminator", "before\r\n.\r\n\r\nafter\r\n"},
		{"8-bit content", "naïve café — €5\r\n"},
		{"long line", strings.Repeat("x", 2000) + "\r\n"},
		{"many lines", strings.Repeat("line of text\r\n", 5000)},
		{"binary-ish", "\x00\x01\x02\xff\r\nafter nulls\r\n"},
		{"CR only inside line", "a\rb\r\n"},
		{"tabs and spaces", "col1\tcol2   \r\n  indented\r\n"},
	}

	dir := t.TempDir()
	keyPath, pub := writeRSAKey(t, dir)
	txt := rsaDNSRecord(t, pub)

	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(storedMessage(tc.body))

			signed, err := s.Sign(content, "example.com")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
				t.Fatal("signed message has no DKIM-Signature header")
			}

			// The signature must be prepended; the content below it must be
			// untouched, or the body the recipient hashes is not the body that
			// was signed.
			if !bytes.HasSuffix(signed, content) {
				t.Errorf("signing rewrote the message instead of prepending the signature\n  content tail: %q\n  signed tail:  %q",
					lastBytes(content, 64), lastBytes(signed, 64))
			}

			vs := verifyWithKey(t, signed, "sel1", "example.com", txt)
			if len(vs) != 1 {
				t.Fatalf("expected 1 verification, got %d", len(vs))
			}
			if vs[0].Err != nil {
				t.Fatalf("signature did not verify: %v", vs[0].Err)
			}
		})
	}
}

// TestSignedBodyFailsVerificationIfBodyChanges is the control: it proves the
// checks above can actually detect corruption, rather than passing because
// verification is lenient. A single byte flipped after signing must fail.
func TestSignedBodyFailsVerificationIfBodyChanges(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeRSAKey(t, dir)
	txt := rsaDNSRecord(t, pub)

	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	signed, err := s.Sign([]byte(storedMessage("original body text\r\n")), "example.com")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	corruptions := []struct {
		name     string
		mutate   func([]byte) []byte
		mustFail bool
	}{
		{
			name:     "one byte changed",
			mutate:   func(b []byte) []byte { return bytes.Replace(b, []byte("original"), []byte("modified"), 1) },
			mustFail: true,
		},
		{
			name:     "leading period re-stuffed",
			mutate:   func(b []byte) []byte { return bytes.Replace(b, []byte("original"), []byte(".original"), 1) },
			mustFail: true,
		},
		{
			name: "line ending downgraded to bare LF",
			// Still verifies. Relaxed body canonicalisation normalises line
			// endings to CRLF before hashing (go-msgauth applies crlfFixer in
			// relaxedBodyCanonicalizer.Write), so DKIM cannot see this class
			// of change at all.
			//
			// This is the important negative result for the spooling work: a
			// spool that alters line endings would keep producing valid
			// signatures while corrupting the message on the wire. DKIM
			// verification is not sufficient coverage on its own — the
			// byte-equality round-trip tests in internal/smtp are what catch it.
			mutate:   func(b []byte) []byte { return bytes.Replace(b, []byte("body text\r\n"), []byte("body text\n"), 1) },
			mustFail: false,
		},
		{
			name: "extra trailing blank line",
			// Also tolerated: relaxed canonicalisation strips trailing empty
			// lines. Documented here so the boundary of what DKIM protects is
			// explicit rather than assumed.
			mutate:   func(b []byte) []byte { return append(append([]byte{}, b...), "\r\n"...) },
			mustFail: false,
		},
	}

	for _, tc := range corruptions {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(append([]byte{}, signed...))
			if bytes.Equal(mutated, signed) {
				t.Fatal("mutation did not change the message")
			}

			vs := verifyWithKey(t, mutated, "sel1", "example.com", txt)
			if len(vs) != 1 {
				t.Fatalf("expected 1 verification, got %d", len(vs))
			}

			failed := vs[0].Err != nil
			if failed != tc.mustFail {
				t.Errorf("verification failed = %v, want %v (err: %v)", failed, tc.mustFail, vs[0].Err)
			}
		})
	}
}

// TestSignIsDeterministicForIdenticalContent pins that signing the same bytes
// twice produces the same signature. Retries re-sign from stored content, so a
// spool that replays bytes differently between attempts would show up here.
func TestSignIsDeterministicForIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeRSAKey(t, dir)

	s := newTestSigner(t, &Config{
		Enabled: true,
		Domains: []DomainConfig{{Domain: "example.com", Selector: "sel1", PrivateKeyPath: keyPath}},
	})

	content := []byte(storedMessage("stable body\r\n"))

	first, err := s.Sign(content, "example.com")
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	second, err := s.Sign(content, "example.com")
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}

	// The body hash (bh=) covers only content, so it must match even if the
	// timestamp in the signature differs between calls.
	bh1, bh2 := bodyHashOf(t, first), bodyHashOf(t, second)
	if bh1 != bh2 {
		t.Errorf("body hash differs between signings of identical content: %q vs %q", bh1, bh2)
	}
}

func bodyHashOf(t *testing.T, signed []byte) string {
	t.Helper()
	idx := bytes.Index(signed, []byte("bh="))
	if idx < 0 {
		t.Fatal("no bh= tag in DKIM-Signature")
	}
	rest := signed[idx+3:]
	end := bytes.IndexByte(rest, ';')
	if end < 0 {
		t.Fatal("malformed bh= tag")
	}
	return strings.Join(strings.Fields(string(rest[:end])), "")
}

func lastBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "..." + string(b[len(b)-n:])
}
