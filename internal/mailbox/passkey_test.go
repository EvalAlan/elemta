package mailbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

const (
	testRP     = "mail.example.com"
	testOrigin = "https://mail.example.com"
)

// softKey is a software authenticator, so the real verification runs on real
// signatures rather than on a stub of it.
type softKey struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	id     []byte
	handle []byte
	rp     string
	count  uint32
	// noUV leaves the user-verified flag off, as a key with no PIN would.
	noUV bool
}

func newSoftKey(t *testing.T) *softKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softKey{t: t, key: key, id: id, rp: testRP}
}

var rawB64 = base64.RawURLEncoding.EncodeToString

func clientData(kind, challenge, origin string) []byte {
	data, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin})
	return data
}

func (k *softKey) authData(attested bool) []byte {
	var out bytes.Buffer
	hash := sha256.Sum256([]byte(k.rp))
	out.Write(hash[:])
	flags := byte(0x01)
	if !k.noUV {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}
	out.WriteByte(flags)
	_ = binary.Write(&out, binary.BigEndian, k.count)
	if attested {
		out.Write(make([]byte, 16))
		_ = binary.Write(&out, binary.BigEndian, uint16(len(k.id)))
		out.Write(k.id)
		pub, err := k.key.PublicKey.ECDH()
		if err != nil {
			k.t.Fatal(err)
		}
		raw := pub.Bytes()
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:]})
		if err != nil {
			k.t.Fatal(err)
		}
		out.Write(cose)
	}
	return out.Bytes()
}

func (k *softKey) create(challenge, origin string) []byte {
	data := clientData("webauthn.create", challenge, origin)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(true)})
	if err != nil {
		k.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{"id": rawB64(k.id), "rawId": rawB64(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": rawB64(data), "attestationObject": rawB64(attestation)}})
	return out
}

func (k *softKey) sign(challenge, origin string) []byte {
	k.count++
	data := clientData("webauthn.get", challenge, origin)
	auth := k.authData(false)
	hash := sha256.Sum256(data)
	digest := sha256.Sum256(append(bytes.Clone(auth), hash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{"id": rawB64(k.id), "rawId": rawB64(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": rawB64(data), "authenticatorData": rawB64(auth), "signature": rawB64(signature), "userHandle": rawB64(k.handle)}})
	return out
}

// passkeyRig is a service with an account that has a passkey.
type passkeyRig struct {
	*sieveRig
	key *softKey
}

func (r *passkeyRig) register(key *softKey) {
	r.t.Helper()
	ctx := context.Background()
	challenge, options, err := r.svc.beginPasskeyRegistration(ctx, r.a, testRP, testOrigin)
	if err != nil {
		r.t.Fatal(err)
	}
	key.handle = passkeyHandle(r.a.ID)
	if options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		r.t.Fatal("user verification isn't required")
	}
	if _, err := r.svc.finishPasskeyRegistration(ctx, r.a, testRP, testOrigin, challenge, "Laptop", key.create(options.Response.Challenge.String(), testOrigin)); err != nil {
		r.t.Fatalf("register: %v", err)
	}
}

func (r *passkeyRig) signIn(key *softKey) (string, string, error) {
	r.t.Helper()
	ctx := context.Background()
	challenge, options, err := r.svc.beginPasskeyLogin(ctx, testRP, testOrigin)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, challenge, key.sign(options.Response.Challenge.String(), testOrigin))
}

func newPasskeyRig(t *testing.T) *passkeyRig {
	t.Helper()
	r := &passkeyRig{sieveRig: newSieveRig(t), key: newSoftKey(t)}
	r.register(r.key)
	t.Cleanup(func() { _ = r.e.DeletePasskeys(context.Background(), r.a.ID) })
	return r
}

func TestPasskeySignInIssuesAWorkingToken(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	address, token, err := r.signIn(r.key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(address, r.a.Address) || !strings.HasPrefix(token, sessionTokenPrefix) {
		t.Fatalf("%q %q", address, token)
	}
	if a, err := r.svc.login(ctx, address, token, false, "", "test"); err != nil || a.ID != r.a.ID {
		t.Fatalf("internal login: %+v %v", a, err)
	}
	auth, err := r.svc.securityLogin(ctx, address, token)
	if err != nil || !auth.session {
		t.Fatalf("security login: %+v %v", auth, err)
	}
}

// The whole reason the token is safe to issue.
func TestSessionTokenWorksNowhereElse(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	address, token, err := r.signIn(r.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.login(ctx, address, token, true, "", "test"); err == nil {
		t.Error("worked on a public listener")
	}
	for _, protocol := range []string{mailpolicy.IMAP, mailpolicy.POP3} {
		if _, err := r.svc.login(ctx, address, token, false, protocol, "test"); err == nil {
			t.Errorf("worked for %s", protocol)
		}
	}
	if _, err := r.svc.login(ctx, "someone-else@example.com", token, false, "", "test"); err == nil {
		t.Error("worked for another user")
	}
	if _, err := r.svc.login(ctx, address, sessionTokenPrefix+"forged", false, "", "test"); err == nil {
		t.Error("a forged token worked")
	}
}

func TestEndingSessionsAndRemovingPasskeys(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	address, token, err := r.signIn(r.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.e.endSessionToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.login(ctx, address, token, false, "", "test"); err == nil {
		t.Fatal("signing out left the token working")
	}
	_, token, err = r.signIn(r.key)
	if err != nil {
		t.Fatal(err)
	}
	list, err := r.e.Passkeys(ctx, r.a.ID)
	if err != nil || len(list) != 1 || list[0].Name != "Laptop" || list[0].LastUsed == nil {
		t.Fatalf("%+v %v", list, err)
	}
	if err := r.e.DeletePasskey(ctx, Account{ID: "someone-else", Address: "x@example.com"}, list[0].ID); err == nil {
		t.Fatal("removed someone else's passkey")
	}
	if err := r.e.DeletePasskey(ctx, r.a, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.login(ctx, address, token, false, "", "test"); err == nil {
		t.Fatal("removing the passkey left its session working")
	}
	if _, _, err := r.signIn(r.key); err == nil {
		t.Fatal("a removed passkey signed in")
	}
}

func TestExpiredSessionTokenStops(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	address, token, err := r.signIn(r.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.DB.ExecContext(ctx, `UPDATE mailbox_session_tokens SET absolute_expires=now()-interval '1 minute' WHERE token_hash=$1`, adminTokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.login(ctx, address, token, false, "", "test"); err == nil {
		t.Fatal("an expired token worked")
	}
}

func TestPasskeySignInRefusals(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	challengeFor := func() (string, string) {
		id, options, err := r.svc.beginPasskeyLogin(ctx, testRP, testOrigin)
		if err != nil {
			t.Fatal(err)
		}
		return id, options.Response.Challenge.String()
	}

	id, challenge := challengeFor()
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, r.key.sign(challenge, "https://evil.example")); err == nil {
		t.Error("a signature from another site was accepted")
	}
	id, challenge = challengeFor()
	stranger := newSoftKey(t)
	stranger.id, stranger.handle = r.key.id, r.key.handle
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, stranger.sign(challenge, testOrigin)); err == nil {
		t.Error("a different key claiming the same ID was accepted")
	}
	id, challenge = challengeFor()
	response := r.key.sign(challenge, testOrigin)
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, response); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, response); err == nil {
		t.Error("a challenge worked twice")
	}
	id, challenge = challengeFor()
	r.key.noUV = true
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, r.key.sign(challenge, testOrigin)); err == nil {
		t.Error("a signature without user verification was accepted")
	}
	r.key.noUV = false
	id, challenge = challengeFor()
	r.key.count = 0 // behind what the server has seen: a cloned key
	if _, _, err := r.svc.finishPasskeyLogin(ctx, testRP, testOrigin, id, r.key.sign(challenge, testOrigin)); err == nil {
		t.Error("a cloned key was accepted")
	}
}

func TestRelyingPartyRules(t *testing.T) {
	for _, tc := range [][2]string{{"mail.example.com", "http://mail.example.com"}, {"mail.example.com", "https://other.example.com"}, {"", "https://x"}, {"mail.example.com", "https://mail.example.com/path"}} {
		if _, err := relyingParty(tc[0], tc[1]); err == nil {
			t.Errorf("accepted %v", tc)
		}
	}
	for _, tc := range [][2]string{{"mail.example.com", "https://mail.example.com"}, {"localhost", "http://localhost:8027"}} {
		if _, err := relyingParty(tc[0], tc[1]); err != nil {
			t.Errorf("refused %v: %v", tc, err)
		}
	}
}

// One domain's passkey doesn't sign in on another of the server's domains.
func TestPasskeyBelongsToItsHost(t *testing.T) {
	r := newPasskeyRig(t)
	ctx := context.Background()
	other := "mail.example.org"
	id, options, err := r.svc.beginPasskeyLogin(ctx, other, "https://"+other)
	if err != nil {
		t.Fatal(err)
	}
	r.key.rp = other
	if _, _, err := r.svc.finishPasskeyLogin(ctx, other, "https://"+other, id, r.key.sign(options.Response.Challenge.String(), "https://"+other)); err == nil {
		t.Fatal("a passkey worked on a host it wasn't made for")
	}
}
