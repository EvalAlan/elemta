package mailcategory

import (
	"strings"
	"testing"
)

func msg(headers ...string) []byte {
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\nbody\r\n")
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want Category
	}{
		{"person", msg("From: Sam <sam@example.org>", "Subject: lunch?"), Primary},
		{"reply from a person", msg("From: sam@example.org", "Subject: Re: the plan", "In-Reply-To: <a@b>"), Primary},
		{"mailman list", msg("From: Sam <sam@example.org>", "Subject: [dev] release", "List-Id: <dev.lists.example.org>", "List-Post: <mailto:dev@lists.example.org>", "List-Unsubscribe: <mailto:x>"), Forums},
		{"google group", msg("From: sam@example.org", "Subject: hi", "X-Google-Group-Id: 123"), Forums},
		{"announce list without posting", msg("From: news@example.org", "Subject: digest", "List-Id: <n.example.org>", "List-Post: NO", "List-Unsubscribe: <mailto:x>"), Promotions},
		{"linkedin", msg("From: LinkedIn <messages-noreply@linkedin.com>", "Subject: You appeared in 5 searches", "List-Unsubscribe: <https://x>"), Social},
		{"facebook subdomain", msg("From: Facebook <notification@mail.facebookmail.com>", "Subject: New comment"), Social},
		{"mailchimp campaign", msg("From: Shop <hello@shop.example>", "Subject: 20% off this weekend", "List-Unsubscribe: <https://x>", "X-Mailchimp-Campaign: abc"), Promotions},
		{"marketing return path", msg("From: Shop <hello@shop.example>", "Subject: New arrivals", "List-Unsubscribe: <https://x>", "Return-Path: <bounce@mail.sendgrid.net>"), Promotions},
		{"shop receipt with unsubscribe", msg("From: Shop <orders@shop.example>", "Subject: Your order has shipped", "List-Unsubscribe: <https://x>", "X-Mailchimp-Campaign: abc"), Updates},
		{"newsletter from a person-like address", msg("From: Writer <writer@substack.example>", "Subject: Issue 42", "List-Unsubscribe: <https://x>"), Promotions},
		{"bulk from noreply", msg("From: Service <no-reply@service.example>", "Subject: Changes to our terms", "List-Unsubscribe: <https://x>"), Updates},
		{"password reset", msg("From: Service <security@service.example>", "Subject: Reset your password"), Updates},
		{"auto-submitted", msg("From: ci@example.org", "Subject: build failed", "Auto-Submitted: auto-generated"), Updates},
		{"auto-submitted no", msg("From: sam@example.org", "Subject: hi", "Auto-Submitted: no"), Primary},
		{"garbage", []byte("not a message"), Primary},
	}
	for _, c := range cases {
		if got := Classify(c.raw, nil); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got.Name(), c.want.Name())
		}
	}
}

func TestOverridesWin(t *testing.T) {
	promo := msg("From: Shop <hello@news.shop.example>", "Subject: Sale", "List-Unsubscribe: <https://x>", "X-Mailchimp-Campaign: abc")
	if got := Classify(promo, Overrides{"@shop.example": Primary}); got != Primary {
		t.Fatalf("parent domain override: got %q", got.Name())
	}
	if got := Classify(promo, Overrides{"@shop.example": Updates, "hello@news.shop.example": Social}); got != Social {
		t.Fatalf("address beats domain: got %q", got.Name())
	}
	person := msg("From: sam@example.org", "Subject: hi")
	if got := Classify(person, Overrides{"sam@example.org": Forums}); got != Forums {
		t.Fatalf("override on a person: got %q", got.Name())
	}
}

func TestKeywordsRoundTrip(t *testing.T) {
	for _, c := range All {
		var flags []string
		if k := c.Keyword(); k != "" {
			flags = []string{`\Seen`, k}
		}
		if got := FromKeywords(flags); got != c {
			t.Errorf("%s: got %q", c.Name(), got.Name())
		}
		if p, ok := Parse(c.Name()); !ok || p != c {
			t.Errorf("Parse(%q) = %q, %v", c.Name(), p.Name(), ok)
		}
	}
	if _, ok := Parse("bogus"); ok {
		t.Error("Parse accepted bogus")
	}
	if got := FromKeywords([]string{"$categoryforums", "$CategorySocial"}); got != Social {
		t.Errorf("two keywords: got %q, want the first in tab order", got.Name())
	}
}
