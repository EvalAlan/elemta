package campaign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// One-click unsubscribe (RFC 8058).
//
// Gmail and Yahoo require bulk senders to offer it: a List-Unsubscribe header
// with an HTTPS link, and List-Unsubscribe-Post saying a POST to it is enough.
// The mail provider then shows its own "Unsubscribe" button and POSTs for the
// recipient. Without it, the recipient's other choice is "Report spam", and
// every one of those counts against the sender's domain.
//
// Each recipient's link names the campaign and their address, signed with a
// key only this server holds, so the link works without a database row per
// message, and nobody can unsubscribe anyone else by editing it.

// Unsubscriber makes and checks one-click unsubscribe links.
type Unsubscriber struct {
	key  []byte
	base string // https://host/unsubscribe/
}

// NewUnsubscriber returns links under base, signed with key. An empty base
// turns the links off.
func NewUnsubscriber(key []byte, base string) *Unsubscriber {
	if base != "" && !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &Unsubscriber{key: append([]byte(nil), key...), base: base}
}

// URL is the link for one recipient of a campaign, or "" when links are off.
func (u *Unsubscriber) URL(campaignID, address string) string {
	if u == nil || u.base == "" || len(u.key) == 0 {
		return ""
	}
	return u.base + u.Token(campaignID, address)
}

// Token is the signed part of the link.
func (u *Unsubscriber) Token(campaignID, address string) string {
	payload := campaignID + "\n" + strings.ToLower(strings.TrimSpace(address))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(u.sign(payload))
}

// Parse checks a token and returns what it names.
func (u *Unsubscriber) Parse(token string) (campaignID, address string, ok bool) {
	if u == nil || len(u.key) == 0 {
		return "", "", false
	}
	body, sig, found := strings.Cut(token, ".")
	if !found {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", false
	}
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(mac, u.sign(string(payload))) {
		return "", "", false
	}
	campaignID, address, found = strings.Cut(string(payload), "\n")
	if !found || address == "" {
		return "", "", false
	}
	return campaignID, address, true
}

// sign is a truncated HMAC: 128 bits is far past guessing, and keeps the
// link short enough for mail clients that wrap long headers badly.
func (u *Unsubscriber) sign(payload string) []byte {
	m := hmac.New(sha256.New, u.key)
	m.Write([]byte("elemta-unsubscribe\n" + payload))
	return m.Sum(nil)[:16]
}
