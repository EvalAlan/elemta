package queue

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/busybox42/elemta/internal/dkim"
)

const dkimTestMessage = "From: Alice <alice@example.com>\r\n" +
	"To: Bob <bob@remote.test>\r\n" +
	"Subject: Hello\r\n" +
	"Date: Thu, 09 Jul 2026 12:00:00 +0000\r\n" +
	"Message-ID: <abc@example.com>\r\n" +
	"\r\n" +
	"Body.\r\n"

func newTestSigner(t *testing.T, domain string) *dkim.Signer {
	t.Helper()
	dir := t.TempDir()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := filepath.Join(dir, "dkim.key")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s, err := dkim.NewSigner(&dkim.Config{
		Enabled: true,
		Domains: []dkim.DomainConfig{{Domain: domain, Selector: "sel", PrivateKeyPath: keyPath}},
	}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func countSignatures(content []byte) int {
	n := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "DKIM-Signature:") {
			n++
		}
	}
	return n
}

// TestSignContentUsesEnvelopeFrom verifies the handler selects the signing
// domain from the envelope-from address and signs the message.
func TestSignContentUsesEnvelopeFrom(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.SetDKIMSigner(newTestSigner(t, "example.com"))

	msg := Message{ID: "m1", From: "alice@example.com"}
	out := h.signContent(msg, []byte(dkimTestMessage))
	if countSignatures(out) != 1 {
		t.Fatalf("expected 1 signature, got %d", countSignatures(out))
	}
}

// TestSignContentRetryDoesNotDoubleSign feeds already-signed content back
// through signContent (as a retry would) and asserts no second signature.
func TestSignContentRetryDoesNotDoubleSign(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.SetDKIMSigner(newTestSigner(t, "example.com"))
	msg := Message{ID: "m1", From: "alice@example.com"}

	first := h.signContent(msg, []byte(dkimTestMessage))
	second := h.signContent(msg, first)

	if !bytes.Equal(first, second) {
		t.Fatal("retry produced different bytes (re-signed)")
	}
	if n := countSignatures(second); n != 1 {
		t.Fatalf("expected exactly 1 signature after retry, got %d", n)
	}
}

// TestSignContentFallsBackToFromHeader verifies that when the envelope-from is
// empty (e.g. a bounce), the From header domain is used.
func TestSignContentFallsBackToFromHeader(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.SetDKIMSigner(newTestSigner(t, "example.com"))

	msg := Message{ID: "bounce", From: ""} // empty envelope-from
	out := h.signContent(msg, []byte(dkimTestMessage))
	if countSignatures(out) != 1 {
		t.Fatalf("expected signing via From header fallback, got %d signatures", countSignatures(out))
	}
}

// TestSignContentSkipsUnconfiguredDomain verifies unconfigured domains pass
// through unchanged.
func TestSignContentSkipsUnconfiguredDomain(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	h.SetDKIMSigner(newTestSigner(t, "other.test"))

	msg := Message{ID: "m1", From: "alice@example.com"}
	out := h.signContent(msg, []byte(dkimTestMessage))
	if countSignatures(out) != 0 {
		t.Fatal("message for unconfigured domain must not be signed")
	}
}

// TestSignContentNilSignerPassThrough verifies signing is a no-op when disabled.
func TestSignContentNilSignerPassThrough(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	msg := Message{ID: "m1", From: "alice@example.com"}
	out := h.signContent(msg, []byte(dkimTestMessage))
	if !bytes.Equal(out, []byte(dkimTestMessage)) {
		t.Fatal("nil signer must pass content through unchanged")
	}
}
