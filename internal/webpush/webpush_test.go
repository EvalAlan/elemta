package webpush

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The worked example in RFC 8291 Appendix A.
const (
	rfcPlaintext = "When I grow up, I want to be a watermelon"
	rfcUAPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcUAPublic  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcAuth      = "BTBZMqHH6r4Tts7J_aSIgg"
	rfcASPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcSalt      = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcBody      = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func TestEncryptMatchesRFC8291(t *testing.T) {
	raw, _ := b64.DecodeString(rfcASPrivate)
	local, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := b64.DecodeString(rfcSalt)
	got, err := encrypt(Subscription{P256dh: rfcUAPublic, Auth: rfcAuth}, []byte(rfcPlaintext), local, salt)
	if err != nil {
		t.Fatal(err)
	}
	if b64.EncodeToString(got) != rfcBody {
		t.Fatalf("body = %s\nwant   %s", b64.EncodeToString(got), rfcBody)
	}
	uaRaw, _ := b64.DecodeString(rfcUAPrivate)
	ua, _ := ecdh.P256().NewPrivateKey(uaRaw)
	auth, _ := b64.DecodeString(rfcAuth)
	if string(decrypt(t, ua, auth, got)) != rfcPlaintext {
		t.Fatal("the browser's side doesn't decrypt it")
	}
}

func decrypt(t *testing.T, uaPriv *ecdh.PrivateKey, auth, body []byte) []byte {
	t.Helper()
	plain, err := Decrypt(uaPriv, auth, body)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestSendSignsAndEncrypts(t *testing.T) {
	keys, priv, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseKeys(priv)
	if err != nil || again.Public != keys.Public {
		t.Fatalf("ParseKeys round trip: %v %q %q", err, again.Public, keys.Public)
	}
	ua, _ := ecdh.P256().GenerateKey(nil)
	auth := []byte("0123456789abcdef")
	var got *http.Request
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	s := &Sender{Keys: keys, Contact: "https://mail.example", Client: srv.Client(), Allowed: func(*url.URL) bool { return true }}
	sub := Subscription{Endpoint: srv.URL + "/push/abc", P256dh: b64.EncodeToString(ua.PublicKey().Bytes()), Auth: b64.EncodeToString(auth)}
	if err := sub.Valid(); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sub, Message{Payload: []byte(`{"title":"Hi"}`), TTL: time.Hour, Urgency: "high", Topic: "mail"}); err != nil {
		t.Fatal(err)
	}
	if string(decrypt(t, ua, auth, body)) != `{"title":"Hi"}` {
		t.Fatal("payload didn't round trip")
	}
	for h, want := range map[string]string{"TTL": "3600", "Content-Encoding": "aes128gcm", "Urgency": "high", "Topic": "mail"} {
		if got.Header.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, got.Header.Get(h), want)
		}
	}
	// The VAPID token verifies with the public key and names the endpoint's origin.
	a := got.Header.Get("Authorization")
	tok, k, ok := strings.Cut(strings.TrimPrefix(a, "vapid t="), ", k=")
	if !ok || k != keys.Public {
		t.Fatalf("Authorization = %q", a)
	}
	parts := strings.Split(tok, ".")
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := b64.DecodeString(parts[2])
	if !ecdsa.Verify(&keys.private.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("VAPID signature doesn't verify")
	}
	claimsJSON, _ := b64.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(claimsJSON, &claims)
	if claims["aud"] != srv.URL || claims["sub"] != "https://mail.example" {
		t.Errorf("claims = %v", claims)
	}
}

func TestSendGone(t *testing.T) {
	keys, _, _ := GenerateKeys()
	ua, _ := ecdh.P256().GenerateKey(nil)
	for _, code := range []int{http.StatusGone, http.StatusNotFound} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		s := &Sender{Keys: keys, Client: srv.Client(), Allowed: func(*url.URL) bool { return true }}
		err := s.Send(context.Background(), Subscription{Endpoint: srv.URL, P256dh: b64.EncodeToString(ua.PublicKey().Bytes()), Auth: rfcAuth}, Message{Payload: []byte("x")})
		srv.Close()
		if !errors.Is(err, ErrGone) {
			t.Errorf("%d: err = %v, want ErrGone", code, err)
		}
	}
}

func TestAllowedEndpoint(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":                 true,
		"https://updates.push.services.mozilla.com/wpush/v2/abc":  true,
		"https://web.push.apple.com/QGx":                          true,
		"https://wns2-par02p.notify.windows.com/w/?token=abc":     true,
		"http://fcm.googleapis.com/fcm/send/abc":                  false,
		"https://fcm.googleapis.com:8443/x":                       false,
		"https://evilfcm.googleapis.com.example/x":                false,
		"https://fcm.googleapis.com.example/x":                    false,
		"https://notfcm.googleapis.com/x":                         false,
		"https://user@fcm.googleapis.com/x":                       false,
		"https://169.254.169.254/latest/meta-data":                false,
		"https://elemta-mailbox-server-1:8080/v1/security/check":  false,
		"https://push.apple.com.attacker.example/x":               false,
		"https://xpush.services.mozilla.com/wpush/v2/abc":         false,
		"https://updates.push.services.mozilla.com:443/wpush/abc": true,
	} {
		u, _ := url.Parse(raw)
		if got := AllowedEndpoint(u); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}

func TestPayloadLimit(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(nil)
	sub := Subscription{P256dh: b64.EncodeToString(ua.PublicKey().Bytes()), Auth: rfcAuth}
	if _, err := Encrypt(sub, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("an oversized payload was accepted")
	}
	body, err := Encrypt(sub, make([]byte, MaxPayload))
	if err != nil || len(body) > 4096 {
		t.Fatalf("largest payload: %d bytes, %v", len(body), err)
	}
}
