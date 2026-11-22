package campaign

import (
	"strings"
	"testing"
)

func TestUnsubscribeLinks(t *testing.T) {
	u := NewUnsubscriber([]byte("0123456789abcdef0123456789abcdef"), "https://mail.example.com/unsubscribe")
	link := u.URL("c42", "Pat@Example.com")
	if !strings.HasPrefix(link, "https://mail.example.com/unsubscribe/") {
		t.Fatalf("link %q", link)
	}
	token := strings.TrimPrefix(link, "https://mail.example.com/unsubscribe/")
	id, addr, ok := u.Parse(token)
	if !ok || id != "c42" || addr != "pat@example.com" {
		t.Fatalf("parsed %q %q %v", id, addr, ok)
	}

	// Editing the address, or using another server's key, must not work.
	body, sig, _ := strings.Cut(token, ".")
	other := u.Token("c42", "someone.else@example.com")
	otherBody, _, _ := strings.Cut(other, ".")
	for _, bad := range []string{otherBody + "." + sig, body + ".AAAA", body, "", "!!!." + sig} {
		if _, _, ok := u.Parse(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, _, ok := NewUnsubscriber([]byte("another key, another server....."), "https://x/").Parse(token); ok {
		t.Error("another key accepted the token")
	}

	// No base or no key: no links, and no header.
	if NewUnsubscriber(nil, "https://x/").URL("c", "a@b.c") != "" || NewUnsubscriber([]byte("k"), "").URL("c", "a@b.c") != "" {
		t.Error("made a link without a key or a base")
	}
	var none *Unsubscriber
	if none.URL("c", "a@b.c") != "" {
		t.Error("nil unsubscriber made a link")
	}
}

func TestBuildMessageOffersOneClickUnsubscribe(t *testing.T) {
	c := &Campaign{ID: "c1", From: "News <news@example.com>", Subject: "Hi", TextBody: "Hello"}
	r := Recipient{Email: "pat@example.com"}
	body, err := BuildMessage(c, r, "mail.example.com", "https://mail.example.com/unsubscribe/abc.def")
	if err != nil {
		t.Fatal(err)
	}
	msg := string(body)
	for _, want := range []string{"List-Unsubscribe: <https://mail.example.com/unsubscribe/abc.def>\r\n", "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in\n%s", want, msg)
		}
	}
	body, err = BuildMessage(c, r, "mail.example.com", "")
	if err != nil || strings.Contains(string(body), "List-Unsubscribe") {
		t.Errorf("header without a link: %v\n%s", err, body)
	}
	if _, err := BuildMessage(c, r, "mail.example.com", "https://x/a\r\nBcc: evil@example.com"); err == nil {
		t.Error("a link with a line break went into the header")
	}
}
