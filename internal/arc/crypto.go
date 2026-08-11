package arc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// RFC 8617 §4.1.2 defines exactly one algorithm for both ARC header signatures.
// Accepting anything else would mean accepting an algorithm whose security
// properties nobody has agreed on for this protocol.
const algorithmRSASHA256 = "rsa-sha256"

// bodyHash is the bh= value: the hash of the canonicalized body.
func bodyHash(body string, canon Canonicalization) []byte {
	sum := sha256.Sum256([]byte(canonicalizeBody(body, canon)))
	return sum[:]
}

// amsSignedData is the input to an ARC-Message-Signature signature.
//
// The signed headers come first, each canonicalized, then the AMS field itself
// with its b= value emptied. That last field carries no trailing CRLF: it is
// the terminator of the hash input, and adding one would make every signature
// produced elsewhere fail to verify here.
func amsSignedData(headers []header, amsField string, canon Canonicalization) string {
	tags := parseTags(headerValue(amsField))
	signed := selectHeaders(headers, tags["h"], canon)
	self := canonicalizeHeader(withEmptyTag(amsField, "b"), canon)
	return signed + strings.TrimSuffix(self, "\r\n")
}

// sealSignedData is the input to an ARC-Seal signature.
//
// An ARC-Seal signs every ARC header of every set from instance 1 up to and
// including its own, in instance order and in the order
// AAR, AMS, AS within each set. That is what chains the sets together: a
// tampered or reordered earlier hop invalidates every seal above it, so a
// forwarder cannot rewrite history and re-seal only the top.
//
// Canonicalization is always relaxed — ARC-Seal has no c= tag (RFC 8617 §4.1.3).
func sealSignedData(sets []arcSet, upto int) string {
	var out strings.Builder
	for _, set := range sets {
		if set.instance > upto {
			break
		}
		out.WriteString(canonicalizeHeader(set.aar, CanonRelaxed))
		out.WriteString(canonicalizeHeader(set.ams, CanonRelaxed))
		if set.instance == upto {
			// The seal being computed is included with its own signature
			// removed, and without a trailing CRLF.
			self := canonicalizeHeader(withEmptyTag(set.seal, "b"), CanonRelaxed)
			out.WriteString(strings.TrimSuffix(self, "\r\n"))
			break
		}
		out.WriteString(canonicalizeHeader(set.seal, CanonRelaxed))
	}
	return out.String()
}

// signRSA produces a base64 signature over data.
func signRSA(key *rsa.PrivateKey, data string) (string, error) {
	digest := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyRSA checks a base64 signature over data.
func verifyRSA(key *rsa.PublicKey, data, signature string) error {
	raw, err := decodeBase64(signature)
	if err != nil {
		return fmt.Errorf("signature is not valid base64")
	}
	digest := sha256.Sum256([]byte(data))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], raw); err != nil {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// decodeBase64 accepts folded and unpadded base64.
//
// Values arrive wrapped across header continuation lines, and some signers emit
// unpadded output. Being strict here would reject valid signatures, which reads
// as a verification failure and is indistinguishable from an attack.
func decodeBase64(value string) ([]byte, error) {
	value = stripWSP(value)
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
}

// checkAlgorithm rejects anything but the one algorithm ARC defines.
func checkAlgorithm(value string) error {
	if strings.ToLower(strings.TrimSpace(value)) != algorithmRSASHA256 {
		return fmt.Errorf("unsupported algorithm %q; ARC defines only %s", value, algorithmRSASHA256)
	}
	return nil
}
