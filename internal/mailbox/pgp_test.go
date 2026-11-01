package mailbox

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// testPGPPair makes a key pair for address, locked unless passphrase is empty.
func testPGPPair(t *testing.T, address, passphrase string) (string, string) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", address, nil)
	if err != nil {
		t.Fatal(err)
	}
	var public, private bytes.Buffer
	w, _ := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err := entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if passphrase != "" {
		if err := entity.EncryptPrivateKeys([]byte(passphrase), nil); err != nil {
			t.Fatal(err)
		}
	}
	w, _ = armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return public.String(), private.String()
}

func TestPGPKeyRules(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	public, private := testPGPPair(t, a.Address, "correct horse battery staple")
	unlockedPublic, unlocked := testPGPPair(t, a.Address, "")
	otherPublic, otherPrivate := testPGPPair(t, "someone@example.org", "correct horse battery staple")
	_, elsewhere := testPGPPair(t, a.Address, "correct horse battery staple")

	for name, pair := range map[string][2]string{
		"an unlocked private key": {unlockedPublic, unlocked},
		"another person's key":    {otherPublic, otherPrivate},
		"mismatched halves":       {public, elsewhere},
		"a private key as public": {private, private},
		"not a key":               {"hello", "world"},
	} {
		if _, err := e.PutPGPKey(ctx, a, pair[0], pair[1]); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	saved, err := e.PutPGPKey(ctx, a, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Fingerprint) != 40 {
		t.Fatalf("fingerprint %q", saved.Fingerprint)
	}
	got, err := e.PGPKeyOf(ctx, a.ID)
	if err != nil || got == nil || got.PrivateKey != private {
		t.Fatalf("%+v %v", got, err)
	}
	found, err := e.PGPLookup(ctx, []string{strings.ToUpper(a.Address), "nobody@example.net"})
	if err != nil || len(found) != 1 {
		t.Fatalf("%+v %v", found, err)
	}
	if found[0].PrivateKey != "" {
		t.Fatal("a lookup carried a private key")
	}
	local, domain, _ := strings.Cut(strings.ToLower(a.Address), "@")
	if key, err := e.WKDKey(ctx, domain, wkdHash(local)); err != nil || key != public {
		t.Fatalf("wkd: %v", err)
	}
	if err := e.DeletePGPKey(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got, err := e.PGPKeyOf(ctx, a.ID); err != nil || got != nil {
		t.Fatalf("%+v %v", got, err)
	}
}

// The example in the Web Key Directory draft.
func TestWKDHash(t *testing.T) {
	if got := wkdHash("Joe.Doe"); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatalf("got %s", got)
	}
}

func TestPGPPins(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	pin := PGPPin{Address: "Friend@Example.org", Fingerprint: strings.Repeat("ab", 20)}
	if err := e.PutPGPPin(ctx, a.ID, pin); err != nil {
		t.Fatal(err)
	}
	pin.Fingerprint = strings.Repeat("cd", 20)
	if err := e.PutPGPPin(ctx, a.ID, pin); err != nil {
		t.Fatal(err)
	}
	pins, err := e.PGPPins(ctx, a.ID)
	if err != nil || len(pins) != 1 || pins[0].Fingerprint != strings.Repeat("CD", 20) || pins[0].Address != "friend@example.org" {
		t.Fatalf("%+v %v", pins, err)
	}
	if err := e.PutPGPPin(ctx, a.ID, PGPPin{Address: "x@example.org", Fingerprint: "nothex"}); err == nil {
		t.Fatal("accepted a bad fingerprint")
	}
}

// Turning publishing off takes a key out of the public directory only, and a new
// key keeps the owner's choice.
func TestPGPPublishChoice(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	public, private := testPGPPair(t, a.Address, "correct horse battery staple")
	saved, err := e.PutPGPKey(ctx, a, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Published {
		t.Fatal("a new key should be published until its owner says otherwise")
	}
	local, domain, _ := strings.Cut(strings.ToLower(a.Address), "@")
	if err := e.SetPGPPublished(ctx, a, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WKDKey(ctx, domain, wkdHash(local)); err == nil {
		t.Fatal("an unpublished key is still in the directory")
	}
	if found, err := e.PGPLookup(ctx, []string{a.Address}); err != nil || len(found) != 1 {
		t.Fatalf("colleagues lost the key: %+v %v", found, err)
	}
	second, secondPrivate := testPGPPair(t, a.Address, "correct horse battery staple")
	again, err := e.PutPGPKey(ctx, a, second, secondPrivate)
	if err != nil || again.Published {
		t.Fatalf("replacing the key changed the choice: %+v %v", again, err)
	}
	if err := e.SetPGPPublished(ctx, a, true); err != nil {
		t.Fatal(err)
	}
	if key, err := e.WKDKey(ctx, domain, wkdHash(local)); err != nil || key != second {
		t.Fatalf("back on: %v", err)
	}
	if err := e.SetPGPPublished(ctx, Account{ID: "nobody", Address: "x@example.com"}, false); err == nil {
		t.Fatal("an account with no key")
	}
}
