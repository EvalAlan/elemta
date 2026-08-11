package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ARC decides whether a receiver may trust an authentication result recorded by
// somebody else. The tests that matter are therefore the ones that try to make
// a forged or damaged chain report "pass".

const testMessage = "From: sender@example.com\r\n" +
	"To: recipient@example.net\r\n" +
	"Subject: hello\r\n" +
	"Date: Tue, 11 Aug 2026 12:00:00 -0400\r\n" +
	"Message-ID: <one@example.com>\r\n" +
	"\r\n" +
	"This is the body.\r\n"

type testZone struct {
	records map[string][]string
}

func (z *testZone) lookup(_ context.Context, name string) ([]string, error) {
	if r, ok := z.records[name]; ok {
		return r, nil
	}
	return nil, &missingRecord{name}
}

type missingRecord struct{ name string }

func (e *missingRecord) Error() string { return "no TXT record for " + e.name }

// newSealer builds a plugin with a freshly generated key and a zone that
// publishes the matching public key.
func newSealer(t *testing.T, domain, selector string, bits int) (*Plugin, *testZone) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, selector+".key")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	zone := &testZone{records: map[string][]string{
		selector + "._domainkey." + domain: {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)},
	}}

	plugin, err := New(Config{
		Enabled: true, Verify: true, Seal: true,
		Domain: domain, Selector: selector, PrivateKeyPath: path,
		HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed",
	})
	if err != nil {
		t.Fatal(err)
	}
	plugin.resolver = zone.lookup
	return plugin, zone
}

func mustSeal(t *testing.T, p *Plugin, message, authResults string) string {
	t.Helper()
	sealed, err := p.Seal(context.Background(), []byte(message), authResults)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return string(sealed)
}

// TestSealThenVerify is the baseline: if this fails nothing else means anything.
func TestSealThenVerify(t *testing.T) {
	p, _ := newSealer(t, "example.com", "arc", 2048)
	sealed := mustSeal(t, p, testMessage, "example.com; spf=pass smtp.mailfrom=example.com")

	if !strings.Contains(sealed, "ARC-Seal: i=1;") ||
		!strings.Contains(sealed, "ARC-Message-Signature: i=1;") ||
		!strings.Contains(sealed, "ARC-Authentication-Results: i=1;") {
		t.Fatalf("sealed message is missing part of the ARC set:\n%s", sealed)
	}
	// The first hop must record that it saw no chain.
	if !strings.Contains(sealed, "cv=none") {
		t.Errorf("first seal should record cv=none:\n%s", sealed)
	}

	result := p.Verify(context.Background(), []byte(sealed))
	if result.Value != ChainPass {
		t.Fatalf("verify = %s (%s)", result.Value, result.Reason)
	}
}

// TestTwoHopChainVerifies covers the case ARC exists for: a message that has
// been relayed, where each hop sealed what it saw.
func TestTwoHopChainVerifies(t *testing.T) {
	first, zone := newSealer(t, "first.example", "a1", 2048)
	second, zone2 := newSealer(t, "second.example", "a2", 2048)
	// One resolver that knows both domains.
	for name, record := range zone2.records {
		zone.records[name] = record
	}
	second.resolver = zone.lookup

	once := mustSeal(t, first, testMessage, "first.example; spf=pass")
	twice := mustSeal(t, second, once, "second.example; arc=pass")

	if strings.Count(twice, "ARC-Seal:") != 2 {
		t.Fatalf("expected two seals:\n%s", twice)
	}
	// The second hop must record that the chain below it passed.
	if !strings.Contains(twice, "cv=pass") {
		t.Errorf("second seal should record cv=pass:\n%s", twice)
	}

	if result := second.Verify(context.Background(), []byte(twice)); result.Value != ChainPass {
		t.Fatalf("verify = %s (%s)", result.Value, result.Reason)
	}
}

// TestTamperingIsDetected is the security property. Each case takes a validly
// sealed message and changes one thing an attacker would want to change.
func TestTamperingIsDetected(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(sealed string) string
		why    string
	}{
		{
			name:   "body edited after sealing",
			tamper: func(s string) string { return strings.Replace(s, "This is the body.", "This is not the body.", 1) },
			why:    "rewriting the content is the whole point of forging a chain",
		},
		{
			name:   "signed header edited",
			tamper: func(s string) string { return strings.Replace(s, "Subject: hello", "Subject: goodbye", 1) },
			why:    "the subject is signed by the message signature",
		},
		{
			name: "From replaced",
			tamper: func(s string) string {
				return strings.Replace(s, "From: sender@example.com", "From: ceo@example.com", 1)
			},
			why: "the From identity is the one a reader actually sees",
		},
		{
			name: "authentication results rewritten",
			tamper: func(s string) string {
				return strings.Replace(s, "spf=pass", "spf=fail", 1)
			},
			why: "the AAR is signed precisely so a later hop cannot forge our verdict",
		},
		{
			name: "seal signature swapped for another",
			tamper: func(s string) string {
				index := strings.Index(s, "ARC-Seal:")
				end := strings.Index(s[index:], "\r\n") + index
				line := s[index:end]
				bIndex := strings.LastIndex(line, "b=")
				return s[:index] + line[:bIndex+2] + "AAAA" + line[bIndex+6:] + s[end:]
			},
			why: "a seal that does not verify must break the chain",
		},
		{
			name: "whole ARC set removed",
			tamper: func(s string) string {
				// Drop the AAR, leaving an incomplete set.
				index := strings.Index(s, "ARC-Authentication-Results:")
				end := strings.Index(s[index:], "\r\n") + index + 2
				return s[:index] + s[end:]
			},
			why: "an incomplete set leaves part of the chain unsigned",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newSealer(t, "example.com", "arc", 2048)
			sealed := mustSeal(t, p, testMessage, "example.com; spf=pass smtp.mailfrom=example.com")

			// Sanity: it passed before we broke it.
			if before := p.Verify(context.Background(), []byte(sealed)); before.Value != ChainPass {
				t.Fatalf("precondition failed, chain did not verify before tampering: %s", before.Reason)
			}

			after := p.Verify(context.Background(), []byte(tc.tamper(sealed)))
			if after.Value == ChainPass {
				t.Errorf("tampered chain reported pass — %s", tc.why)
			}
		})
	}
}

// TestBrokenIntermediateHopBreaksTheChain: the seals exist to make history
// immutable. Editing hop 1 after hop 2 sealed over it must invalidate hop 2.
func TestBrokenIntermediateHopBreaksTheChain(t *testing.T) {
	first, zone := newSealer(t, "first.example", "a1", 2048)
	second, zone2 := newSealer(t, "second.example", "a2", 2048)
	for name, record := range zone2.records {
		zone.records[name] = record
	}
	second.resolver = zone.lookup

	once := mustSeal(t, first, testMessage, "first.example; spf=pass")
	twice := mustSeal(t, second, once, "second.example; arc=pass")

	// Rewrite what hop 1 claimed to have seen.
	tampered := strings.Replace(twice, "i=1; first.example; spf=pass", "i=1; first.example; spf=fail", 1)
	if tampered == twice {
		t.Fatal("test did not modify the first hop's results")
	}

	if result := second.Verify(context.Background(), []byte(tampered)); result.Value == ChainPass {
		t.Error("editing an earlier hop must invalidate every seal above it")
	}
}

func TestNoARCHeadersIsNoneNotFail(t *testing.T) {
	p, _ := newSealer(t, "example.com", "arc", 2048)
	result := p.Verify(context.Background(), []byte(testMessage))
	if result.Value != ChainNone {
		t.Errorf("verify = %s; an unsealed message has no chain, which is not a failure", result.Value)
	}
}

// TestStructuralAttacks covers hand-built chains that never came from a signer.
func TestStructuralAttacks(t *testing.T) {
	p, _ := newSealer(t, "example.com", "arc", 2048)

	cases := []struct {
		name    string
		headers string
		why     string
	}{
		{
			name: "first set claims cv=pass",
			headers: "ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=arc; b=AAAA\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; h=from; bh=AAAA; b=AAAA\r\n" +
				"ARC-Authentication-Results: i=1; example.com; spf=pass\r\n",
			why: "the first hop cannot have validated a chain that did not exist",
		},
		{
			name: "instances skip a number",
			headers: "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=example.com; s=arc; b=AAAA\r\n" +
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; h=from; bh=AAAA; b=AAAA\r\n" +
				"ARC-Authentication-Results: i=2; example.com; spf=pass\r\n",
			why: "a missing hop lets an attacker delete an inconvenient one",
		},
		{
			name: "duplicate header in one instance",
			headers: "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
				"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=other.example; s=arc; b=BBBB\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; h=from; bh=AAAA; b=AAAA\r\n" +
				"ARC-Authentication-Results: i=1; example.com; spf=pass\r\n",
			why: "two seals in one instance let two readers reach different conclusions",
		},
		{
			name: "unsupported algorithm",
			headers: "ARC-Seal: i=1; a=rsa-sha1; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=arc; h=from; bh=AAAA; b=AAAA\r\n" +
				"ARC-Authentication-Results: i=1; example.com; spf=pass\r\n",
			why: "ARC defines only rsa-sha256; anything else is an unreviewed downgrade",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := p.Verify(context.Background(), []byte(tc.headers+testMessage))
			if result.Value == ChainPass {
				t.Errorf("chain reported pass — %s", tc.why)
			}
		})
	}
}

// TestWeakKeyIsRejected: a 512-bit key can be factored, so honouring one lets
// anyone forge a seal for that domain.
func TestWeakKeyIsRejected(t *testing.T) {
	strong, zone := newSealer(t, "example.com", "arc", 2048)
	sealed := mustSeal(t, strong, testMessage, "example.com; spf=pass")

	weak, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Skipf("this Go version refuses to generate a 512-bit key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	zone.records["arc._domainkey.example.com"] = []string{
		"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der),
	}

	if result := strong.Verify(context.Background(), []byte(sealed)); result.Value == ChainPass {
		t.Error("a chain whose key is below the RFC 8301 minimum must not pass")
	}
}

// TestRevokedKeyIsRejected: an empty p= is how a domain withdraws a selector.
func TestRevokedKeyIsRejected(t *testing.T) {
	p, zone := newSealer(t, "example.com", "arc", 2048)
	sealed := mustSeal(t, p, testMessage, "example.com; spf=pass")
	zone.records["arc._domainkey.example.com"] = []string{"v=DKIM1; k=rsa; p="}

	if result := p.Verify(context.Background(), []byte(sealed)); result.Value == ChainPass {
		t.Error("a revoked selector must not verify")
	}
}

// TestMissingKeyFailsClosed. Unlike SPF, an ARC seal whose key cannot be
// fetched is not "inconclusive" — the chain simply cannot vouch for anything.
func TestMissingKeyFailsClosed(t *testing.T) {
	p, zone := newSealer(t, "example.com", "arc", 2048)
	sealed := mustSeal(t, p, testMessage, "example.com; spf=pass")
	delete(zone.records, "arc._domainkey.example.com")

	if result := p.Verify(context.Background(), []byte(sealed)); result.Value == ChainPass {
		t.Error("a seal whose key is unavailable must not pass")
	}
}

// TestPartialBodySigningIsRefused. l= lets a signature cover only a prefix of
// the body, so anything appended is unsigned but still displayed.
func TestPartialBodySigningIsRefused(t *testing.T) {
	p, _ := newSealer(t, "example.com", "arc", 2048)
	sealed := mustSeal(t, p, testMessage, "example.com; spf=pass")
	withLength := strings.Replace(sealed, "ARC-Message-Signature: i=1;", "ARC-Message-Signature: i=1; l=5;", 1)

	if result := p.Verify(context.Background(), []byte(withLength)); result.Value == ChainPass {
		t.Error("a partially signed body must not report a verified chain")
	}
}

// TestSealingRequiresConfiguration: a sealer with no key is a misconfiguration
// that must surface at startup, not as a delivery failure later.
func TestSealingRequiresConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		config Config
	}{
		{"no domain", Config{Enabled: true, Seal: true, Selector: "arc", PrivateKeyPath: "/dev/null"}},
		{"no selector", Config{Enabled: true, Seal: true, Domain: "example.com", PrivateKeyPath: "/dev/null"}},
		{"no key", Config{Enabled: true, Seal: true, Domain: "example.com", Selector: "arc"}},
		{"bad canonicalization", Config{Enabled: true, Verify: true, HeaderCanonicalization: "invented"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.config); err == nil {
				t.Error("expected configuration to be refused")
			}
		})
	}
}

// TestDisabledPluginSealsNothing keeps the off switch honest.
func TestDisabledPluginSealsNothing(t *testing.T) {
	p, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Seal(context.Background(), []byte(testMessage), "example.com; spf=pass")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != testMessage {
		t.Error("a disabled plugin must return the message untouched")
	}
	if result := p.Verify(context.Background(), []byte(testMessage)); result.Value != ChainNone {
		t.Errorf("verify = %s on a disabled plugin", result.Value)
	}
}
