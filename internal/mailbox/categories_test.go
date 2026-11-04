package mailbox

import (
	"context"
	"errors"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailcategory"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func TestDeliveryTagsCategories(t *testing.T) {
	r := newAddressingRig(t)
	ctx := context.Background()
	ana := r.dir.accounts[r.addr("ana")]
	to := []string{r.addr("ana")}
	r.send("x@example.org", "", to, msgWith("hello")) // creates the account
	t.Cleanup(func() { _, _ = r.e.DB.Exec(`DELETE FROM mailbox_category_rules WHERE account=$1`, ana.ID) })

	r.send("sam@example.org", "", to, "From: sam@example.org\r\nSubject: lunch\r\n\r\nhi\r\n")
	r.send("bounce@mail.sendgrid.net", "", to, "From: Shop <hello@shop.example>\r\nSubject: Sale\r\nList-Unsubscribe: <https://x>\r\nX-Mailchimp-Campaign: a\r\n\r\nbuy\r\n")
	r.send("n@linkedin.com", "", to, "From: LinkedIn <n@linkedin.com>\r\nSubject: new connection\r\n\r\nx\r\n")
	// Spam gets no category: Junk has no tabs.
	r.send("s@else.example", "", to, "X-Spam-Status: Yes, score=9\r\nFrom: Shop <s@else.example>\r\nList-Unsubscribe: <https://x>\r\nX-Mailchimp-Campaign: a\r\n\r\nbuy\r\n")

	// The user said this shop belongs in Primary.
	if _, err := r.e.PutCategoryRule(ctx, ana.ID, CategoryRule{Sender: "@Shop.example", Category: "primary"}); err != nil {
		t.Fatal(err)
	}
	r.send("bounce@mail.sendgrid.net", "", to, "From: Shop <deals@news.shop.example>\r\nSubject: Sale 2\r\nList-Unsubscribe: <https://x>\r\nX-Mailchimp-Campaign: a\r\n\r\nbuy\r\n")

	_, msgs, err := r.e.Snapshot(ctx, ana.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	var got []mailcategory.Category
	for _, m := range msgs {
		got = append(got, mailcategory.FromKeywords(m.Flags))
	}
	want := []mailcategory.Category{mailcategory.Primary, mailcategory.Primary, mailcategory.Promotions, mailcategory.Social, mailcategory.Primary}
	if len(got) != len(want) {
		t.Fatalf("INBOX holds %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("message %d: %q, want %q", i, got[i].Name(), want[i].Name())
		}
	}
	_, junk, _ := r.e.Snapshot(ctx, ana.ID, "Junk")
	for _, m := range junk {
		if c := mailcategory.FromKeywords(m.Flags); c != mailcategory.Primary {
			t.Errorf("spam was given category %q", c.Name())
		}
	}
}

func TestCategoryRules(t *testing.T) {
	r := newAddressingRig(t)
	ctx := context.Background()
	ana := r.dir.accounts[r.addr("ana")]
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("hello"))
	t.Cleanup(func() { _, _ = r.e.DB.Exec(`DELETE FROM mailbox_category_rules WHERE account=$1`, ana.ID) })

	got, err := r.e.SetCategoryRules(ctx, ana.ID, []CategoryRule{
		{Sender: "A@x.example", Category: "social"},
		{Sender: "@y.example", Category: "Updates"},
		{Sender: "a@x.example", Category: "forums"}, // the later entry wins
		{Sender: " ", Category: "social"},           // blank lines are skipped
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (CategoryRule{"@y.example", "updates"}) || got[1] != (CategoryRule{"a@x.example", "forums"}) {
		t.Fatalf("rules: %+v", got)
	}
	for name, in := range map[string]CategoryRule{
		"bad sender":   {Sender: "nope", Category: "social"},
		"bad category": {Sender: "a@x.example", Category: "spam"},
	} {
		if _, err := r.e.PutCategoryRule(ctx, ana.ID, in); !errors.Is(err, mailpolicy.ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := r.e.PutCategoryRule(ctx, ana.ID, CategoryRule{Sender: "a@x.example", Category: "primary"}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.e.CategoryRules(ctx, ana.ID)
	if len(got) != 2 || got[1].Category != "primary" {
		t.Fatalf("after put: %+v", got)
	}
}
