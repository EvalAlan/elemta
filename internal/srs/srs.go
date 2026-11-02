// Package srs implements the Sender Rewriting Scheme.
//
// Forwarding mail keeps the original envelope sender, so the next server
// checks that sender's SPF record against this server's address and it fails.
// SRS sends forwarded mail from an address at the forwarder's own domain, which
// passes, and encodes the original sender in it so a bounce can be sent back:
//
//	SRS0=hash=tt=example.org=alice@forwarder.example
//
// It is stateless: the MTA, which receives the bounces, shares only a secret
// with the mailbox service, which forwards. The hash stops strangers using an
// address like this as an open relay; the timestamp limits how long a captured
// one works.
package srs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// SecretsEnv holds the secrets, newest first and comma separated. The first
// signs; the rest still verify, so one can be replaced while bounces for
// addresses it signed are on their way.
const SecretsEnv = "ELEMTA_SRS_SECRETS"

const (
	// Lower case, because some servers change the case of an address and the
	// check has to survive that.
	alphabet   = "abcdefghijklmnopqrstuvwxyz234567"
	hashLength = 6
	day        = 24 * time.Hour
	// Ten bits of days, so the timestamp wraps after about 2.8 years.
	timestampRange = 1024
	// MaxAge is how long a rewritten address works. It only needs to outlast
	// a remote server's retries before it gives up and bounces.
	MaxAge = 21 * day
	// maxLocal is RFC 5321's limit, which this MTA enforces on its own
	// submission port too.
	maxLocal = 64
)

// Reasons an address can't be used.
var (
	ErrNotSRS   = errors.New("srs: not an SRS address")
	ErrInvalid  = errors.New("srs: invalid hash")
	ErrExpired  = errors.New("srs: expired")
	ErrTooLong  = errors.New("srs: rewritten address would be too long")
	ErrNoDomain = errors.New("srs: address has no domain")
)

var encoding = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)

// Rewriter rewrites and reverses addresses. A nil Rewriter is SRS turned off.
type Rewriter struct {
	secrets [][]byte
	now     func() time.Time
}

// New returns a Rewriter, or nil when there are no secrets.
func New(secrets []string) *Rewriter {
	r := &Rewriter{now: time.Now}
	for _, s := range secrets {
		if s = strings.TrimSpace(s); s != "" {
			r.secrets = append(r.secrets, []byte(s))
		}
	}
	if len(r.secrets) == 0 {
		return nil
	}
	return r
}

// FromEnv returns the Rewriter SecretsEnv describes, or nil when it isn't set.
func FromEnv() *Rewriter { return New(strings.Split(os.Getenv(SecretsEnv), ",")) }

// Is reports whether address has the form of an SRS address, whatever its
// domain. It doesn't check the hash.
func Is(address string) bool {
	local, _, ok := cut(address)
	if !ok || len(local) < 5 {
		return false
	}
	prefix := strings.ToUpper(local[:5])
	return prefix == "SRS0=" || prefix == "SRS1="
}

// Forward returns the address to send from when forwarding sender's mail from
// domain. Mail already from domain is returned as it is, because its SPF passes.
func (r *Rewriter) Forward(sender, domain string) (string, error) {
	local, senderDomain, ok := cut(sender)
	if !ok || domain == "" {
		return "", ErrNoDomain
	}
	if strings.EqualFold(senderDomain, domain) {
		return sender, nil
	}
	var rewritten string
	if prefix := strings.ToUpper(local[:min(5, len(local))]); prefix == "SRS0=" {
		// Forwarded twice. The next hop only has to reach the first forwarder,
		// which holds the rest, so this stays short.
		rest := local[4:]
		rewritten = "SRS1=" + r.hash(senderDomain, rest) + "=" + senderDomain + "=" + rest
	} else if prefix == "SRS1=" {
		// Forwarded again: keep the first forwarder, and sign for this domain.
		fields := strings.SplitN(local, "=", 4)
		if len(fields) < 4 {
			return "", ErrNotSRS
		}
		rewritten = "SRS1=" + r.hash(fields[2], fields[3]) + "=" + fields[2] + "=" + fields[3]
	} else {
		stamp := timestamp(r.now())
		rewritten = "SRS0=" + r.hash(stamp, senderDomain, local) + "=" + stamp + "=" + senderDomain + "=" + local
	}
	if len(rewritten) > maxLocal {
		return "", ErrTooLong
	}
	return rewritten + "@" + domain, nil
}

// Reverse returns the address a bounce to address should go to.
func (r *Rewriter) Reverse(address string) (string, error) {
	local, _, ok := cut(address)
	if !ok || !Is(address) {
		return "", ErrNotSRS
	}
	if strings.EqualFold(local[:5], "SRS1=") {
		fields := strings.SplitN(local, "=", 4)
		if len(fields) < 4 || !r.check(fields[1], fields[2], fields[3]) {
			return "", ErrInvalid
		}
		// The rest is what follows SRS0 at the first forwarder, separator
		// included, which is what the double = in these addresses is.
		return "SRS0" + fields[3] + "@" + fields[2], nil
	}
	fields := strings.SplitN(local, "=", 5)
	if len(fields) < 5 || fields[4] == "" || fields[3] == "" {
		return "", ErrNotSRS
	}
	if !r.check(fields[1], fields[2], fields[3], fields[4]) {
		return "", ErrInvalid
	}
	if !current(fields[2], r.now()) {
		return "", ErrExpired
	}
	return fields[4] + "@" + fields[3], nil
}

func (r *Rewriter) hash(parts ...string) string { return sign(r.secrets[0], parts) }

func (r *Rewriter) check(got string, parts ...string) bool {
	for _, secret := range r.secrets {
		if hmac.Equal([]byte(strings.ToLower(got)), []byte(sign(secret, parts))) {
			return true
		}
	}
	return false
}

func sign(secret []byte, parts []string) string {
	mac := hmac.New(sha256.New, secret)
	for _, part := range parts {
		// Lower case for the same reason as the alphabet, and a separator so
		// moving text between fields changes the hash.
		fmt.Fprintf(mac, "%s\x00", strings.ToLower(part))
	}
	return encoding.EncodeToString(mac.Sum(nil))[:hashLength]
}

func timestamp(now time.Time) string {
	days := now.Unix() / int64(day/time.Second) % timestampRange
	return string([]byte{alphabet[days>>5], alphabet[days&31]})
}

func current(stamp string, now time.Time) bool {
	if len(stamp) != 2 {
		return false
	}
	stamp = strings.ToLower(stamp)
	high, low := strings.IndexByte(alphabet, stamp[0]), strings.IndexByte(alphabet, stamp[1])
	if high < 0 || low < 0 {
		return false
	}
	today := now.Unix() / int64(day/time.Second) % timestampRange
	age := (today - int64(high<<5|low) + timestampRange) % timestampRange
	return age <= int64(MaxAge/day)
}

func cut(address string) (local, domain string, ok bool) {
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return "", "", false
	}
	return address[:at], address[at+1:], true
}
