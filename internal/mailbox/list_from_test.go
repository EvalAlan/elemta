package mailbox

import (
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// Copies to a list's outside members are signed for the list owner's domain,
// so they carry the list as From, never the poster's claimed address.
func TestExternalListCopyDoesNotKeepThePostersFrom(t *testing.T) {
	l := mailpolicy.List{Address: "sales@example.com", Name: "Sales", Owner: "boss@example.com"}
	for name, raw := range map[string]string{
		"plain":      "From: CEO <ceo@example.com>\r\nSubject: wire it\r\n\r\nbody\r\n",
		"two Froms":  "From: dana@example.org\r\nSubject: x\r\nFrom: ceo@example.com\r\n\r\nbody\r\n",
		"folded":     "From: CEO\r\n <ceo@example.com>\r\nSubject: x\r\n\r\nbody\r\n",
		"bare LF":    "From: ceo@example.com\nSubject: x\n\nbody\n",
		"lower case": "from: ceo@example.com\r\nSubject: x\r\n\r\nbody\r\n",
		"no body":    "From: ceo@example.com\r\nSubject: x",
	} {
		out := externalListMessage(l, listMessage(l, []byte(raw)))
		// One From, and its address is the list's. The poster may appear in
		// the display name ("ceo@example.com via Sales"), as list software
		// does; it's the address that DMARC and replies use.
		addrs, ok := mailpolicy.FromAddresses(out)
		if !ok || len(addrs) != 1 || addrs[0] != "sales@example.com" {
			t.Errorf("%s: From addresses %q\n%s", name, addrs, out)
		}
		if !strings.Contains(string(out), "body") && name != "no body" {
			t.Errorf("%s: body lost:\n%s", name, out)
		}
	}

	out := string(externalListMessage(l, []byte("From: Dana Lee <dana@example.org>\r\n\r\nhi\r\n")))
	if !strings.Contains(out, `From: "Dana Lee via Sales" <sales@example.com>`) || !strings.Contains(out, "Reply-To: Dana Lee <dana@example.org>") {
		t.Errorf("display name and Reply-To:\n%s", out)
	}
	out = string(externalListMessage(l, []byte("From: dana@example.org\r\nReply-To: desk@example.org\r\n\r\nhi\r\n")))
	if strings.Count(out, "Reply-To:") != 1 || !strings.Contains(out, "Reply-To: desk@example.org") {
		t.Errorf("an existing Reply-To must be kept:\n%s", out)
	}
}

// A forward is signed for its envelope's domain, so it keeps a From in that
// domain only when the MTA confirmed the sender on arrival.
func TestForwardNeedsNewFrom(t *testing.T) {
	v := func(verdict string) string {
		if verdict == "" {
			return ""
		}
		return mailpolicy.SenderVerifiedHeader + ": " + verdict + "\r\n"
	}
	env := "SRS0=ab=cd=example.org=dana@example.com"
	for _, tc := range []struct {
		name, verdict, from, envelope string
		want                          bool
	}{
		{"colleague, signed in", "auth ceo@example.com", "ceo@example.com", env, false},
		{"own domain, DMARC pass", "dmarc example.com", "ceo@example.com", env, false},
		{"own domain, unverified", "none", "ceo@example.com", env, true},
		{"own domain, no verdict", "", "ceo@example.com", env, true},
		{"own domain, someone else signed in", "auth lee@example.com", "ceo@example.com", env, true},
		{"subdomain of own domain, unverified", "none", "ceo@mail.example.com", env, true},
		{"outside domain", "none", "dana@example.org", env, false},
		{"null-sender forward", "none", "ceo@example.com", "", false},
		{"no SRS, outside sender's own envelope", "none", "dana@example.org", "dana@example.org", false},
		{"no SRS, envelope claims own domain", "none", "ceo@example.com", "ceo@example.com", true},
	} {
		raw := []byte(v(tc.verdict) + "From: " + tc.from + "\r\nSubject: x\r\n\r\nbody\r\n")
		if got := forwardNeedsNewFrom(raw, tc.envelope, "example.com"); got != tc.want {
			t.Errorf("%s: forwardNeedsNewFrom = %v, want %v", tc.name, got, tc.want)
		}
	}
}
