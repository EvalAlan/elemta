package mailbox

import (
	"context"
	"errors"
	"testing"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

func (r *addressingRig) folderCount(local, folder string) int {
	r.t.Helper()
	_, msgs, err := r.e.Snapshot(context.Background(), r.dir.accounts[r.addr(local)].ID, folder)
	if err != nil {
		return 0
	}
	return len(msgs)
}

func TestSenderRulesAndJunk(t *testing.T) {
	r := newAddressingRig(t)
	ctx := context.Background()
	ana := r.dir.accounts[r.addr("ana")]
	// The account exists once something was delivered to it.
	r.send("x@example.org", "", []string{r.addr("ana")}, msgWith("hello"))
	if _, err := r.e.SetSenderRules(ctx, ana.ID, []string{"Friend@Good.example", "@partner.example"}, []string{"@spammy.example"}, 10); err != nil {
		t.Fatal(err)
	}
	flagged := func(from string) string {
		return "X-Spam-Status: Yes, score=9.0/5.0\r\nFrom: " + from + "\r\nSubject: s\r\n\r\nbuy\r\n"
	}
	clean := func(from string) string { return "From: " + from + "\r\nSubject: s\r\n\r\nhi\r\n" }

	r.send("friend@good.example", "", []string{r.addr("ana")}, flagged("friend@good.example"))   // allowed: INBOX
	r.send("x@partner.example", "", []string{r.addr("ana")}, flagged("x@partner.example"))       // allowed domain: INBOX
	r.send("someone@else.example", "", []string{r.addr("ana")}, flagged("someone@else.example")) // spam: Junk
	r.send("a@spammy.example", "", []string{r.addr("ana")}, clean("a@spammy.example"))           // blocked: Junk
	// A blocked envelope sender isn't lifted by an allowed From.
	r.send("b@spammy.example", "", []string{r.addr("ana")}, clean("friend@good.example"))
	// The sender's own header below the MTA's doesn't clear the flag.
	r.send("c@else.example", "", []string{r.addr("ana")}, "X-Spam-Status: Yes, score=9\r\nX-Spam-Status: No\r\nFrom: c@else.example\r\n\r\nx\r\n")
	if in, junk := r.folderCount("ana", "INBOX"), r.folderCount("ana", "Junk"); in != 3 || junk != 4 {
		t.Errorf("INBOX %d (want 3), Junk %d (want 4)", in, junk)
	}

	// Validation: a rule in both lists, a bad entry, the limit.
	for name, c := range map[string][2][]string{
		"both":     {{"a@x.example"}, {"A@x.example"}},
		"bad":      {{"not an address"}, nil},
		"too many": {{"a@x.example", "b@x.example"}, {"c@x.example"}},
	} {
		if _, err := r.e.SetSenderRules(ctx, ana.ID, c[0], c[1], 2); !errors.Is(err, mailpolicy.ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	got, _ := r.e.SenderRules(ctx, ana.ID)
	if len(got.Allow) != 2 || len(got.Block) != 1 {
		t.Errorf("a refused change altered the rules: %+v", got)
	}
}
