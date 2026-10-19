package mailbox

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTOTPEncryptionBindsAccountAndSupportsRotation(t *testing.T) {
	old := "v1:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	newKey := "v2:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	keys, err := parseTOTPKeys(old)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{totpKeys: keys}
	sealed, err := engine.sealTOTP("account-one", "active", "SEED")
	if err != nil || strings.Contains(sealed, "SEED") {
		t.Fatalf("seal: %v", err)
	}
	if _, err := engine.openTOTP("account-two", "active", sealed); err == nil {
		t.Fatal("ciphertext moved to another account")
	}
	if _, err := engine.openTOTP("account-one", "pending", sealed); err == nil {
		t.Fatal("active ciphertext accepted as pending enrollment")
	}
	rotated, err := parseTOTPKeys(newKey + "," + old)
	if err != nil {
		t.Fatal(err)
	}
	engine.totpKeys = rotated
	if got, err := engine.openTOTP("account-one", "active", sealed); err != nil || got != "SEED" {
		t.Fatalf("old version after rotation: %q %v", got, err)
	}
	newCiphertext, err := engine.sealTOTP("account-one", "active", "SEED")
	if err != nil || !strings.HasPrefix(newCiphertext, "enc:v2:") {
		t.Fatalf("new version after rotation: %q %v", newCiphertext, err)
	}
}
