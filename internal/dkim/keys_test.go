package dkim

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	msgauth "github.com/emersion/go-msgauth/dkim"
)

// A generated key, published with the record DNSRecord prints, must verify a
// message the signer signed with it. This is the whole rotation path short of
// DNS itself.
func TestGeneratedKeysSignAndVerifyThroughTheirRecord(t *testing.T) {
	for _, keyType := range []string{"rsa", "ed25519"} {
		t.Run(keyType, func(t *testing.T) {
			key, err := GenerateKey(keyType, 2048)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "k.key")
			if err := WritePrivateKey(path, key); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("key mode %o, want 600", info.Mode().Perm())
			}
			if err := WritePrivateKey(path, key); err == nil {
				t.Error("an existing key file was overwritten")
			}

			record, err := DNSRecord(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			published, err := PublishedKey([]string{record})
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadPublicKey(path)
			if err != nil {
				t.Fatal(err)
			}
			if !SamePublicKey(loaded, published) {
				t.Fatal("the published record does not round-trip to the key on disk")
			}

			signer, err := NewSigner(&Config{Enabled: true, Domains: []DomainConfig{{
				Domain: "example.com", Selector: "s1", PrivateKeyPath: path,
			}}}, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("From: a@example.com\r\nTo: b@example.net\r\nSubject: hi\r\n\r\nbody\r\n")
			signed, err := signer.Sign(msg, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			verifications, err := msgauth.VerifyWithOptions(bytes.NewReader(signed), &msgauth.VerifyOptions{
				LookupTXT: func(domain string) ([]string, error) {
					if domain != RecordName("s1", "example.com") {
						t.Errorf("verifier looked up %q", domain)
					}
					return []string{record}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(verifications) != 1 || verifications[0].Err != nil {
				t.Fatalf("signature did not verify against the printed record: %+v", verifications)
			}
		})
	}
}

func TestPublishedKeyRejectsMismatchAndRevocation(t *testing.T) {
	a, _ := GenerateKey("ed25519", 0)
	b, _ := GenerateKey("ed25519", 0)
	record, _ := DNSRecord(b.Public())
	published, err := PublishedKey([]string{record})
	if err != nil {
		t.Fatal(err)
	}
	if SamePublicKey(a.Public(), published) {
		t.Error("different keys compared equal")
	}
	if _, err := PublishedKey([]string{"v=DKIM1; k=rsa; p="}); err == nil {
		t.Error("a revoked (empty p=) record was accepted as a key")
	}
	if _, err := PublishedKey([]string{"v=spf1 -all"}); err == nil {
		t.Error("an unrelated TXT record was accepted")
	}
	if _, ok := published.(ed25519.PublicKey); !ok {
		t.Errorf("ed25519 record parsed as %T", published)
	}
	if _, err := GenerateKey("rsa", 1024); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("1024-bit RSA accepted: %v", err)
	}
}
