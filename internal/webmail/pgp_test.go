package webmail

import (
	"crypto/sha1" // #nosec G505 -- the Web Key Directory hash
	"net/url"
	"strings"
	"testing"
	"time"
)

const sealedMessage = "-----BEGIN PGP MESSAGE-----\n\nwcBMAxxx\n-----END PGP MESSAGE-----"

func TestEncryptedDraftIsPGPMIME(t *testing.T) {
	d := &Draft{From: Address{Email: "a@example.com"}, To: []Address{{Email: "b@example.com"}}, Subject: "...", Text: "the real words", Encrypted: []byte(sealedMessage + "\r\n")}
	raw, err := d.Build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"multipart/encrypted", `protocol="application/pgp-encrypted"`, "Version: 1", "application/octet-stream", "BEGIN PGP MESSAGE"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "the real words") {
		t.Fatal("the plaintext went out")
	}
	msg, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(msg.PGP, "-----BEGIN PGP MESSAGE") || len(msg.Parts) != 0 {
		t.Fatalf("pgp %q parts %+v", msg.PGP, msg.Parts)
	}
}

func TestOlderMailAppsPutTheMessageInTheText(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\nHello\r\n" + strings.ReplaceAll(sealedMessage, "\n", "\r\n") + "\r\n"
	msg, err := parseMessage([]byte(raw))
	if err != nil || msg.PGP == "" {
		t.Fatalf("%q %v", msg.PGP, err)
	}
}

func TestComposeEncryptedTakesOnlyAFinishedMessage(t *testing.T) {
	if _, err := composeEncrypted("hello"); err == nil {
		t.Error("accepted plain text as encrypted")
	}
	if _, err := composeEncrypted("-----BEGIN PGP MESSAGE-----\nno end"); err == nil {
		t.Error("accepted a truncated message")
	}
	if _, err := composeEncrypted(sealedMessage); err != nil {
		t.Error(err)
	}
}

// Whatever else a form carries, only the sealed message may leave.
func TestComposeSendsOnlyTheSealedMessage(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/compose", url.Values{"csrf": {csrf}, "op": {"send"}, "to": {"b@example.com"}, "subject": {"..."},
		"body": {"the real words"}, "html": {"<p>the real words</p>"}, "format": {"html"}, "pgp_message": {sealedMessage}})
	if resp.StatusCode != 303 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Contains(string(h.sub.raw), "the real words") || !strings.Contains(string(h.sub.raw), "BEGIN PGP MESSAGE") {
		t.Fatalf("sent:\n%s", h.sub.raw)
	}
}

func TestComposeRefusesAnEncryptedDraft(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/compose", url.Values{"csrf": {csrf}, "op": {"save"}, "subject": {"..."}, "pgp_message": {sealedMessage}})
	if resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestZBase32(t *testing.T) {
	// The example in the Web Key Directory draft.
	sum := sha1.Sum([]byte("joe.doe")) // #nosec G401 -- the format requires it
	if got := zbase32(sum[:]); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatal(got)
	}
}

// Addresses anyone can name mustn't reach this server's own network.
func TestWKDRefusesBadDomains(t *testing.T) {
	for _, address := range []string{"a@localhost", "a@127.0.0.1", "a@bad_domain.example", "nope"} {
		if _, err := fetchWKD(t.Context(), address); err == nil {
			t.Errorf("fetched %s", address)
		}
	}
}

func TestWKDRoutes(t *testing.T) {
	security := &fakeSecurity{}
	h := newSecurityHarness(t, security)
	for path, want := range map[string]int{
		"/.well-known/openpgpkey/policy":             200,
		"/.well-known/openpgpkey/example.com/policy": 200,
		"/.well-known/openpgpkey/hu/nobody":          404,
		"/.well-known/openpgpkey/example.com/hu/x":   404,
		"/.well-known/openpgpkey/too/many/parts/x":   404,
	} {
		if resp, _ := h.get(path); resp.StatusCode != want {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}
	}
}

const signedMail = "From: a@example.com\r\nSubject: x\r\nMIME-Version: 1.0\r\n" +
	"Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha512; boundary=sig\r\n\r\n" +
	"--sig\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSigned words.\r\n" +
	"--sig\r\nContent-Type: application/pgp-signature; name=signature.asc\r\n\r\n" +
	"-----BEGIN PGP SIGNATURE-----\r\n\r\nabc\r\n-----END PGP SIGNATURE-----\r\n--sig--\r\n"

// The signature covers these exact bytes, so nothing may reformat them.
func TestSignedContentIsCutFromTheRawMessage(t *testing.T) {
	msg, err := parseMessage([]byte(signedMail))
	if err != nil {
		t.Fatal(err)
	}
	want := "Content-Type: text/plain; charset=utf-8\r\n\r\nSigned words."
	if string(msg.PGPSignedContent) != want {
		t.Fatalf("content %q", msg.PGPSignedContent)
	}
	if !strings.Contains(msg.PGPSignature, "BEGIN PGP SIGNATURE") || len(msg.Parts) != 0 {
		t.Fatalf("signature %q parts %+v", msg.PGPSignature, msg.Parts)
	}
	if !strings.Contains(msg.Text, "Signed words") {
		t.Fatal("the message itself should still show")
	}
	// Stored with bare newlines, it's still signed with CRLF.
	bare, err := parseMessage([]byte(strings.ReplaceAll(signedMail, "\r\n", "\n")))
	if err != nil || string(bare.PGPSignedContent) != want {
		t.Fatalf("%q %v", bare.PGPSignedContent, err)
	}
}

func TestClearsignedBlock(t *testing.T) {
	text := "Hi\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nwords\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\nbye"
	got := clearsigned(text)
	if !strings.HasPrefix(got, "-----BEGIN PGP SIGNED") || !strings.HasSuffix(got, "-----END PGP SIGNATURE-----") {
		t.Fatalf("%q", got)
	}
}

func TestEncryptedOriginalKeepsARepliesEncryptionOn(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.store.raw[9] = []byte("From: a@example.com\r\nSubject: ...\r\nMessage-Id: <e@example.com>\r\nContent-Type: text/plain\r\n\r\n" + strings.ReplaceAll(sealedMessage, "\n", "\r\n") + "\r\n")
	_, page := h.get("/compose?mode=reply&f=INBOX&uid=9")
	if !strings.Contains(page, "data-pgp-original") {
		t.Fatal("a reply to encrypted mail doesn't start encrypted")
	}
}
