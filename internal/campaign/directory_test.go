package campaign

import (
	"strings"
	"testing"
)

// Importing a directory is the one recipient source an operator cannot eyeball
// first, so the tests are about what must never silently happen: mailing a
// disabled account, mailing someone twice, or quietly shrinking the list.

func TestRecipientsFromDirectory(t *testing.T) {
	users := []DirectoryUser{
		{Email: "amy@example.com", FullName: "Amy Pond", Username: "amy", IsActive: true},
		{Email: "rory@example.com", FullName: "Rory", Username: "rory", IsActive: true},
		{Email: "gone@example.com", FullName: "Former Person", Username: "gone", IsActive: false},
		{Email: "", Username: "noaddress", IsActive: true},
		{Email: "not an address", Username: "broken", IsActive: true},
		{Email: "AMY@example.com", Username: "amy-alias", IsActive: true},
	}

	recipients, skipped := RecipientsFromDirectory(users)

	if len(recipients) != 2 {
		t.Fatalf("got %d recipients, want 2: %+v", len(recipients), recipients)
	}
	if recipients[0].Email != "amy@example.com" || recipients[1].Email != "rory@example.com" {
		t.Errorf("recipients are not in address order: %+v", recipients)
	}

	// Merge variables, so a template can greet people without a hand-built CSV.
	if recipients[0].Vars["name"] != "Amy Pond" {
		t.Errorf("name var = %q", recipients[0].Vars["name"])
	}
	if recipients[0].Vars["first_name"] != "Amy" {
		t.Errorf("first_name var = %q", recipients[0].Vars["first_name"])
	}
	// A single-word full name still has a usable first_name rather than none.
	if recipients[1].Vars["first_name"] != "Rory" {
		t.Errorf("single-word name produced first_name = %q", recipients[1].Vars["first_name"])
	}

	// Everything left out is reported. An operator who imports six accounts and
	// gets two recipients has to be able to see why.
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{"not active", "no email address", "not a valid address"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped list does not mention %q:\n%s", want, joined)
		}
	}
	if len(skipped) != 3 {
		t.Errorf("got %d skip reasons, want 3: %v", len(skipped), skipped)
	}
}

// TestDisabledAccountsAreNeverMailed is the one that matters most: a disabled
// account is usually someone who has left, and mailing them is at best
// pointless and at worst a disclosure.
func TestDisabledAccountsAreNeverMailed(t *testing.T) {
	recipients, _ := RecipientsFromDirectory([]DirectoryUser{
		{Email: "left@example.com", Username: "left", IsActive: false},
	})
	if len(recipients) != 0 {
		t.Errorf("a disabled account produced a recipient: %+v", recipients)
	}
}

// TestAliasesDoNotProduceTwoCopies: several directory entries pointing at one
// mailbox is normal, and sending the same person the campaign twice is the most
// visible way to look incompetent.
func TestAliasesDoNotProduceTwoCopies(t *testing.T) {
	recipients, skipped := RecipientsFromDirectory([]DirectoryUser{
		{Email: "one@example.com", Username: "a", IsActive: true},
		{Email: "ONE@EXAMPLE.COM", Username: "b", IsActive: true},
		{Email: "one@example.com", Username: "c", IsActive: true},
	})
	if len(recipients) != 1 {
		t.Fatalf("got %d recipients, want 1: %+v", len(recipients), recipients)
	}
	// A duplicate is expected in a directory, so it is not a problem to report.
	if len(skipped) != 0 {
		t.Errorf("aliases were reported as problems: %v", skipped)
	}
}

// TestNoUsableAccountsIsEmptyNotError: an empty directory is a real answer, and
// the caller decides what to do about it.
func TestNoUsableAccountsIsEmptyNotError(t *testing.T) {
	recipients, skipped := RecipientsFromDirectory(nil)
	if len(recipients) != 0 || len(skipped) != 0 {
		t.Errorf("empty input produced %d recipients and %d problems", len(recipients), len(skipped))
	}
}

// TestSkippedAccountsAreIdentifiable: a reason with no name in it tells the
// operator nothing they can act on.
func TestSkippedAccountsAreIdentifiable(t *testing.T) {
	_, skipped := RecipientsFromDirectory([]DirectoryUser{
		{Email: "x@example.com", Username: "specific-user", IsActive: false},
		{Email: "", Username: "", FullName: "", IsActive: true},
	})
	if len(skipped) != 2 {
		t.Fatalf("skipped = %v", skipped)
	}
	joined := strings.Join(skipped, "\n")
	if !strings.Contains(joined, "specific-user") {
		t.Errorf("skip reason does not identify the account: %v", skipped)
	}
	// Even an account with nothing usable in it must still be countable.
	if !strings.Contains(joined, "no username") && !strings.Contains(joined, "no email") {
		t.Errorf("an account with no identifiers produced an unusable reason: %v", skipped)
	}
}

// TestDirectoryImportCSVRoundTrips pins the contract between the dashboard and
// this parser.
//
// The import writes the directory into the recipients box as CSV and the server
// parses it back. Those are different languages in different files, so nothing
// but a test keeps them agreeing, and the failure is quiet: a quoting mistake
// turns into "line 3 is not a valid address" for a directory the operator knows
// is fine.
//
// The block below is the dashboard's own output, generated by its CSV assembly
// against values chosen to break naive joining — a comma in a name, an embedded
// quote, and an account with no merge variables at all.
func TestDirectoryImportCSVRoundTrips(t *testing.T) {
	const fromTheDashboard = `email,name,first_name
a@example.com,"Pond, Amy",Amy
b@example.com,"He said ""hi""",
c@example.com,,`

	recipients, problems, err := ParseRecipients(fromTheDashboard)
	if err != nil {
		t.Fatalf("the dashboard's own CSV did not parse: %v", err)
	}
	if len(problems) != 0 {
		t.Errorf("the dashboard's own CSV produced problems: %v", problems)
	}
	if len(recipients) != 3 {
		t.Fatalf("got %d recipients, want 3: %+v", len(recipients), recipients)
	}

	byEmail := map[string]Recipient{}
	for _, r := range recipients {
		byEmail[r.Email] = r
	}

	// A comma inside a quoted value must not split the row.
	if got := byEmail["a@example.com"].Vars["name"]; got != "Pond, Amy" {
		t.Errorf("name with a comma round-tripped as %q", got)
	}
	// A doubled quote must come back as one.
	if got := byEmail["b@example.com"].Vars["name"]; got != `He said "hi"` {
		t.Errorf("name with a quote round-tripped as %q", got)
	}
	// An account the directory had no name for must still be mailable.
	if _, ok := byEmail["c@example.com"]; !ok {
		t.Error("the recipient with no merge variables was lost")
	}
}

// TestRecipientsFromDirectoryFeedTheCSVTheParserAccepts closes the loop the
// other way: whatever the conversion produces has to survive the trip through
// the dashboard and back.
func TestRecipientsFromDirectoryFeedTheCSVTheParserAccepts(t *testing.T) {
	recipients, _ := RecipientsFromDirectory([]DirectoryUser{
		{Email: "amy@example.com", FullName: "Pond, Amy", Username: "amy", IsActive: true},
		{Email: "rory@example.com", Username: "rory", IsActive: true},
	})

	// Rebuild the CSV the way the dashboard does.
	var b strings.Builder
	b.WriteString("email,name,first_name,username\n")
	for _, r := range recipients {
		cell := func(v string) string {
			if strings.ContainsAny(v, `",`) {
				return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
			}
			return v
		}
		b.WriteString(r.Email + "," + cell(r.Vars["name"]) + "," +
			cell(r.Vars["first_name"]) + "," + cell(r.Vars["username"]) + "\n")
	}

	parsed, problems, err := ParseRecipients(b.String())
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if len(problems) != 0 {
		t.Errorf("round trip reported problems: %v", problems)
	}
	if len(parsed) != len(recipients) {
		t.Errorf("round trip changed the recipient count: %d -> %d", len(recipients), len(parsed))
	}
}
