package dkim

import (
	"bytes"
	"strings"
	"testing"
)

// The i= identity is compared with d= case-insensitively: domain names are
// (RFC 4343), and senders such as Rocket Mortgage sign with
// d=rocketmortgage.com and i=RocketMortgage@t.RocketMortgage.com.
func TestVerifyIdentifierCaseInsensitive(t *testing.T) {
	for identifier, wantErr := range map[string]bool{
		"user@example.org":           false,
		"User@Sub.EXAMPLE.org":       false,
		"User@EXAMPLE.ORG":           false,
		"user@example.org.evil.test": true,
		"user@notexample.org":        true,
		"user@evil.test":             true,
	} {
		var b bytes.Buffer
		err := Sign(&b, strings.NewReader(mailString), &SignOptions{
			Domain: "example.org", Selector: "brisbane", Signer: testPrivateKey, Identifier: identifier,
		})
		if err != nil {
			t.Fatal(err)
		}
		verifications, err := Verify(&b)
		if err != nil {
			t.Fatal(err)
		}
		if len(verifications) != 1 {
			t.Fatalf("%s: %d verifications", identifier, len(verifications))
		}
		v := verifications[0]
		if wantErr {
			if v.Err == nil || !IsPermFail(v.Err) {
				t.Errorf("i=%s: want a permanent failure, got %v", identifier, v.Err)
			}
		} else if v.Err != nil {
			t.Errorf("i=%s: %v", identifier, v.Err)
		}
	}
}
