package arc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Chain-validation values (RFC 8617 §4.1.3, cv= tag).
const (
	ChainNone = "none" // no ARC headers at all
	ChainPass = "pass" // every seal verified and the chain is intact
	ChainFail = "fail" // the chain is broken, forged, or malformed
)

// Minimum RSA modulus we will accept from DNS.
//
// RFC 8301 requires verifiers to reject signing keys below 1024 bits. A 512-bit
// key is factorable cheaply, so honouring one would let anyone who bothered
// forge a seal for that domain — the signature would verify, which is exactly
// the failure mode that matters.
const minKeyBits = 1024

// maxSets bounds the work one message can demand. Each set costs a DNS lookup
// and a signature verification while a client waits at end-of-DATA.
const maxSets = 50

// TXTResolver looks up DNS TXT records. It matches net.Resolver.LookupTXT so
// the default resolver drops in, and so tests can supply a fake zone instead of
// depending on the network.
type TXTResolver func(ctx context.Context, name string) ([]string, error)

// arcSet is one instance: the three headers that must appear together.
type arcSet struct {
	instance int
	aar      string // ARC-Authentication-Results
	ams      string // ARC-Message-Signature
	seal     string // ARC-Seal
}

// verifyChain evaluates the ARC chain on a message.
//
// Every ambiguous or broken condition resolves to "fail" rather than "pass".
// That is the opposite of the choice made for SPF and DMARC elsewhere in this
// server, and deliberately so: an inconclusive SPF result says nothing much,
// whereas an ARC chain that cannot be fully verified is either damaged or
// forged, and treating it as intact is precisely what an attacker wants. A
// "fail" here does not by itself reject mail — it removes the chain's ability
// to vouch for an earlier authentication result.
func verifyChain(ctx context.Context, raw []byte, resolver TXTResolver) (string, string) {
	msg := parseMessage(raw)
	sets, err := collectSets(msg.headers)
	if err != nil {
		return ChainFail, err.Error()
	}
	if len(sets) == 0 {
		return ChainNone, "no ARC sets present"
	}

	newest := sets[len(sets)-1]

	// cv= semantics (RFC 8617 §5.2): the first hop must record that it saw no
	// chain, and every later hop must record that the chain below it passed. A
	// hop that recorded "fail" is stating the chain was already broken when it
	// arrived, and nothing above can repair that.
	for _, set := range sets {
		tags := parseTags(headerValue(set.seal))
		cv := strings.ToLower(strings.TrimSpace(tags["cv"]))
		switch {
		case set.instance == 1 && cv != ChainNone:
			return ChainFail, fmt.Sprintf("first ARC set records cv=%s; it must be none", cv)
		case set.instance > 1 && cv == ChainFail:
			return ChainFail, fmt.Sprintf("ARC set %d recorded that the chain had already failed", set.instance)
		case set.instance > 1 && cv != ChainPass:
			return ChainFail, fmt.Sprintf("ARC set %d records cv=%s; it must be pass", set.instance, cv)
		}
	}

	// Only the newest ARC-Message-Signature is verified. Intermediaries are
	// permitted to modify a message as they relay it, so an older AMS is
	// expected not to match the body we received; requiring all of them to
	// verify would fail every genuinely forwarded message.
	if err := verifyAMS(ctx, msg, newest, resolver); err != nil {
		return ChainFail, fmt.Sprintf("ARC-Message-Signature %d: %v", newest.instance, err)
	}

	// Every seal is verified. The seals are what make the chain a chain: each
	// one covers all the ARC headers beneath it, so a forged or edited earlier
	// hop cannot survive.
	for _, set := range sets {
		if err := verifySeal(ctx, sets, set, resolver); err != nil {
			return ChainFail, fmt.Sprintf("ARC-Seal %d: %v", set.instance, err)
		}
	}

	return ChainPass, fmt.Sprintf("%d ARC set(s) verified", len(sets))
}

// collectSets gathers the ARC headers into instances and enforces structure.
func collectSets(headers []header) ([]arcSet, error) {
	byInstance := map[int]*arcSet{}
	get := func(n int) *arcSet {
		if byInstance[n] == nil {
			byInstance[n] = &arcSet{instance: n}
		}
		return byInstance[n]
	}

	var seenAny bool
	for _, h := range headers {
		var slot *string
		switch h.name {
		case "arc-authentication-results":
			seenAny = true
			n := instanceOf(h.raw)
			if n == 0 {
				return nil, fmt.Errorf("ARC-Authentication-Results has no usable instance number")
			}
			slot = &get(n).aar
		case "arc-message-signature":
			seenAny = true
			n := instanceOf(h.raw)
			if n == 0 {
				return nil, fmt.Errorf("ARC-Message-Signature has no usable instance number")
			}
			slot = &get(n).ams
		case "arc-seal":
			seenAny = true
			n := instanceOf(h.raw)
			if n == 0 {
				return nil, fmt.Errorf("ARC-Seal has no usable instance number")
			}
			slot = &get(n).seal
		default:
			continue
		}
		if *slot != "" {
			// Two of the same header in one instance means the verifier and a
			// downstream reader could disagree about which one counts.
			return nil, fmt.Errorf("duplicate ARC header in instance %d", instanceOf(h.raw))
		}
		*slot = h.raw
	}

	if !seenAny {
		return nil, nil
	}
	if len(byInstance) > maxSets {
		return nil, fmt.Errorf("%d ARC sets exceeds the %d this server will evaluate", len(byInstance), maxSets)
	}

	sets := make([]arcSet, 0, len(byInstance))
	for _, set := range byInstance {
		sets = append(sets, *set)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].instance < sets[j].instance })

	// Instances must run 1..N with nothing missing and nothing incomplete.
	// A gap would let an attacker delete a hop that recorded something
	// inconvenient; a partial set would leave part of the chain unsigned.
	for i, set := range sets {
		if set.instance != i+1 {
			return nil, fmt.Errorf("ARC instances are not contiguous: expected %d, found %d", i+1, set.instance)
		}
		if set.aar == "" || set.ams == "" || set.seal == "" {
			return nil, fmt.Errorf("ARC set %d is incomplete", set.instance)
		}
	}
	return sets, nil
}

// verifyAMS checks a message signature: body hash first, then the signature.
func verifyAMS(ctx context.Context, msg message, set arcSet, resolver TXTResolver) error {
	tags := parseTags(headerValue(set.ams))
	if err := checkAlgorithm(tags["a"]); err != nil {
		return err
	}

	// The h= list must cover From. Without it, a signature says nothing about
	// who the message claims to be from, which is the only identity a reader
	// ever sees.
	if !coversFrom(tags["h"]) {
		return fmt.Errorf("signed header list does not cover From")
	}

	headerCanon, bodyCanon, err := canonicalizationsOf(tags["c"])
	if err != nil {
		return err
	}

	// Body hash first: it is cheap, needs no DNS, and a mismatch is decisive.
	expected, err := decodeBase64(tags["bh"])
	if err != nil {
		return fmt.Errorf("bh= is not valid base64")
	}
	body := msg.body
	if length := strings.TrimSpace(tags["l"]); length != "" {
		// l= says only a prefix of the body is signed, which lets anyone append
		// content that the signature does not cover. Refusing it is a policy
		// choice, not a spec requirement: accepting a partially signed body
		// means reporting "verified" for a message whose visible content may
		// have been written by someone else.
		return fmt.Errorf("l= (partial body signing) is not accepted")
	}
	if got := bodyHash(body, bodyCanon); !equalBytes(got, expected) {
		return fmt.Errorf("body hash does not match; the body changed after signing")
	}

	key, err := fetchKey(ctx, tags["s"], tags["d"], resolver)
	if err != nil {
		return err
	}
	return verifyRSA(key, amsSignedData(msg.headers, set.ams, headerCanon), tags["b"])
}

// verifySeal checks one ARC-Seal over the chain beneath it.
func verifySeal(ctx context.Context, sets []arcSet, set arcSet, resolver TXTResolver) error {
	tags := parseTags(headerValue(set.seal))
	if err := checkAlgorithm(tags["a"]); err != nil {
		return err
	}
	key, err := fetchKey(ctx, tags["s"], tags["d"], resolver)
	if err != nil {
		return err
	}
	return verifyRSA(key, sealSignedData(sets, set.instance), tags["b"])
}

// canonicalizationsOf reads a c= tag. Absent means simple/simple (RFC 6376
// §3.5); "relaxed" alone means relaxed headers with a simple body.
func canonicalizationsOf(value string) (Canonicalization, Canonicalization, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return CanonSimple, CanonSimple, nil
	}
	headerPart, bodyPart, found := strings.Cut(value, "/")
	headerCanon := Canonicalization(strings.TrimSpace(headerPart))
	bodyCanon := CanonSimple
	if found && strings.TrimSpace(bodyPart) != "" {
		bodyCanon = Canonicalization(strings.TrimSpace(bodyPart))
	}
	if !headerCanon.valid() || !bodyCanon.valid() {
		return "", "", fmt.Errorf("unsupported canonicalization %q", value)
	}
	return headerCanon, bodyCanon, nil
}

// coversFrom reports whether an h= list includes the From field.
func coversFrom(list string) bool {
	for _, name := range strings.Split(list, ":") {
		if strings.EqualFold(strings.TrimSpace(name), "from") {
			return true
		}
	}
	return false
}

// fetchKey retrieves and validates a public key from DNS.
func fetchKey(ctx context.Context, selector, domain string, resolver TXTResolver) (*rsa.PublicKey, error) {
	selector = strings.TrimSpace(selector)
	domain = strings.TrimSpace(domain)
	if selector == "" || domain == "" {
		return nil, fmt.Errorf("signature names no selector or domain")
	}
	if resolver == nil {
		resolver = net.DefaultResolver.LookupTXT
	}

	name := selector + "._domainkey." + domain
	records, err := resolver(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("no key at %s: %w", name, err)
	}

	for _, record := range records {
		tags := parseTags(record)
		if v, ok := tags["v"]; ok && !strings.EqualFold(strings.TrimSpace(v), "DKIM1") {
			continue
		}
		if k, ok := tags["k"]; ok && !strings.EqualFold(strings.TrimSpace(k), "rsa") {
			return nil, fmt.Errorf("key at %s is %s; ARC requires rsa", name, k)
		}
		encoded := stripWSP(tags["p"])
		if encoded == "" {
			// An empty p= is how a domain revokes a selector (RFC 6376 §3.6.1).
			return nil, fmt.Errorf("key at %s has been revoked", name)
		}
		der, err := decodeBase64(encoded)
		if err != nil {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key at %s is not RSA", name)
		}
		if bits := key.N.BitLen(); bits < minKeyBits {
			return nil, fmt.Errorf("key at %s is %d bits; below the %d-bit minimum", name, bits, minKeyBits)
		}
		return key, nil
	}
	return nil, fmt.Errorf("no usable key in the records at %s", name)
}

// equalBytes compares two hashes. These are public values, so a timing-safe
// comparison buys nothing; correctness is all that matters.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
