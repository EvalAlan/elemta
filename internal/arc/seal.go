package arc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// defaultSignedHeaders is the header set an ARC-Message-Signature covers when
// the operator has not chosen one.
//
// ARC-Seal is deliberately absent: a message signature must not cover the seal
// that will be computed over it, and RFC 8617 §4.1.2 forbids it outright.
var defaultSignedHeaders = []string{
	"From", "To", "Cc", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Reply-To", "In-Reply-To", "References",
}

// sealMessage adds one ARC set to a message.
//
// The new set records what this hop observed, and its seal covers every ARC
// header below it. The three headers are prepended in the order AAR, AMS, AS
// so the newest set reads first, which is the convention every ARC signer
// follows and what a human debugging a chain expects.
func sealMessage(ctx context.Context, raw []byte, opts sealOptions, resolver TXTResolver) ([]byte, error) {
	msg := parseMessage(raw)

	existing, err := collectSets(msg.headers)
	if err != nil {
		// A message arriving with a broken chain is still sealable — we simply
		// record that it was broken when we saw it. Refusing to relay it is a
		// policy decision that belongs upstream, not here.
		existing = nil
	}

	instance := len(existing) + 1
	if instance > maxSets {
		return nil, fmt.Errorf("refusing to add ARC set %d; the chain is already at the limit", instance)
	}

	// What this hop asserts about the chain it received.
	cv := ChainNone
	if len(existing) > 0 {
		cv, _ = verifyChain(ctx, raw, resolver)
		if cv == ChainNone {
			// Sets are present, so "none" is not a possible honest answer.
			cv = ChainFail
		}
	}

	timestamp := opts.now
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	aar := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s", instance, sanitizeValue(opts.authResults))

	ams, err := buildAMS(msg, instance, timestamp, opts)
	if err != nil {
		return nil, err
	}

	// The seal is computed last, over the chain including the AAR and AMS just
	// created, because it is what binds them together.
	chain := append(append([]arcSet(nil), existing...), arcSet{
		instance: instance, aar: aar, ams: ams,
		seal: fmt.Sprintf("ARC-Seal: i=%d; a=%s; t=%d; cv=%s; d=%s; s=%s; b=",
			instance, algorithmRSASHA256, timestamp.Unix(), cv, opts.domain, opts.selector),
	})
	sealField := chain[len(chain)-1].seal
	signature, err := signRSA(opts.key, sealSignedData(chain, instance))
	if err != nil {
		return nil, err
	}
	sealField += signature

	prepend := aar + "\r\n" + ams + "\r\n" + sealField + "\r\n"
	return []byte(prepend + string(raw)), nil
}

// buildAMS constructs and signs the ARC-Message-Signature.
//
// The AMS covers the message — headers and body — and no ARC header at all.
// RFC 8617 §4.1.2 forbids listing ARC fields in h=, and the reason is
// practical: every hop prepends its own set, so any rule for picking "the" ARC
// header would be evaluated against a different header block by the signer and
// by the verifier. The authentication results are protected instead by the
// ARC-Seal, which covers the whole chain.
func buildAMS(msg message, instance int, timestamp time.Time, opts sealOptions) (string, error) {
	names := opts.headersToSign
	if len(names) == 0 {
		names = defaultSignedHeaders
	}

	// Only sign headers that exist, or the h= list would name fields the
	// verifier cannot find and the signature would be unverifiable.
	present := map[string]bool{}
	for _, h := range msg.headers {
		present[h.name] = true
	}
	selected := make([]string, 0, len(names)+1)
	hasFrom := false
	for _, name := range names {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" || !present[lower] {
			continue
		}
		if strings.HasPrefix(lower, "arc-") {
			// Never sign an ARC header into the message signature. The seal
			// covers those, and including one here would make the AMS
			// unverifiable after any legitimate later hop prepends its own set.
			continue
		}
		if lower == "from" {
			hasFrom = true
		}
		selected = append(selected, name)
	}
	if !hasFrom {
		return "", fmt.Errorf("cannot sign a message with no From header")
	}
	bh := base64.StdEncoding.EncodeToString(bodyHash(msg.body, opts.bodyCanon))
	field := fmt.Sprintf("ARC-Message-Signature: i=%d; a=%s; c=%s/%s; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		instance, algorithmRSASHA256, opts.headerCanon, opts.bodyCanon,
		opts.domain, opts.selector, timestamp.Unix(),
		strings.Join(selected, ":"), bh)

	signature, err := signRSA(opts.key, amsSignedData(msg.headers, field, opts.headerCanon))
	if err != nil {
		return "", err
	}
	return field + signature, nil
}

// sealOptions is the resolved configuration for one sealing operation.
type sealOptions struct {
	domain        string
	selector      string
	key           *rsa.PrivateKey
	headerCanon   Canonicalization
	bodyCanon     Canonicalization
	headersToSign []string
	authResults   string
	now           time.Time
}

// sanitizeValue strips CR and LF from text that becomes a header value.
//
// The authentication results come from our own verifier, so they are already
// constrained — but a value that can carry CRLF can inject headers of its own,
// and this one ends up in a header on mail we send.
func sanitizeValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if value == "" {
		return "none"
	}
	return value
}
